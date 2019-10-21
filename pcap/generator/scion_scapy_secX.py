from __future__ import absolute_import, print_function

import scapy.all as scapy
import struct
import time
import random
import string
import sys

assert sys.version_info >= (3,), "Due to incompatibilities around handling bytes, this only works under Python 3"

from scapy.all import Ether, IP, UDP
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

HF_MAC_KEY = b'\0'*15 + b'\x47'  # 128w0x47

SCION_ADDR_TYPE = {1: 'ipv4', 2: 'ipv6', 3: 'svc'}

ISDField = scapy.ShortField
ASField  = lambda name, default: scapy.XBitField(name, default, 6*8)

def raw(packet):
    return str(packet)  # would be bytes in python3

class UnixTimeField(scapy.IntField):
    def i2repr(self, pkt, x):
        if x is None: return None
        return time.strftime('%d %b %Y %H:%M:%S UTC', time.gmtime(x))

class ISD_AS(scapy.Packet):
    name = 'ISD-AS'
    fields_desc = [
        ISDField('ISD', None),
        ASField('AS', None),
    ]

    def extract_padding(self, p):
        return "", p

class SecurityExtension(scapy.Packet):
    name = "SCION Security Extension"
    fields_desc = [
        scapy.BitEnumField('next_hdr',  None,   8, scapy.IP_PROTOS),
        scapy.ByteField('hdr_len', None),
        scapy.XByteField('extType', 0x2),
        scapy.ByteEnumField("secMode", 0x0, {0x0: "AES-CMAC", 0x1: "HMAC_SHA256", 0x2: "Ed25519", 0x3: "GCM_AES128"}),
        scapy.XBitField('metadata',0xffffffff,4*8),
        scapy.MultipleTypeField(
            [
                (scapy.XBitField('authenticator', None, 16*8), lambda pkt: pkt.secMode == 0x0),
                (scapy.XBitField('authenticator', None, 32*8), lambda pkt: pkt.secMode == 0x1),
                (scapy.XBitField('authenticator', None, 64*8), lambda pkt: pkt.secMode == 0x2),
                (scapy.XBitField('authenticator', None, 16*8), lambda pkt: pkt.secMode == 0x3),
            ],
            scapy.StrField("authenticator", None)
        ),
    ]

    def extract_padding(self, p):
        # TODO fix when removing hard-coded v4
        return "", p

    def post_build(self, pkt, pay):
        if self.hdr_len == None:
            self.hdr_len = len(pkt)
            pkt = pkt[:1] + struct.pack('B', int(self.hdr_len / 8)) + pkt[2:]
        return pkt+pay
        

class SCIONAddr(scapy.Packet):
    name = 'SCION Address header'
    fields_desc = [
        scapy.PacketField('dst_isdas', None, ISD_AS),
        scapy.PacketField('src_isdas', None, ISD_AS),
        # hard-coded v4 for now
        scapy.IPField('dst_host', None),
        scapy.IPField('src_host', None),
    ]

    def extract_padding(self, p):
        # TODO fix when removing hard-coded v4
        return "", p

    # def post_build(self, pkt, pay):
    #     # pad to a multiple of 8
    #     # TODO fix when removing hard-coded v4
    #     pass

class HopField(scapy.Packet):
    IMMUTABLE_FLAGS = 0x0 # TODO
    FLAGS=0
    RANGE_SKIP_FLAGS=1
    RANGE_END=8
    RANGE_BEFORE_MAC=5
    name = 'SCION Hop field'
    fields_desc = [
        scapy.XBitField('flags', 0x0, 8),
        scapy.ByteField('expiry', 63),
        scapy.BitField('ingress_if', None, 12),
        scapy.BitField('egress_if', None, 12),
        scapy.XBitField('mac', None, 3*8), # TODO
    ]

    def extract_padding(self, p):
        return "", p

class PathSegment(scapy.Packet):
    name = 'SCION Path segment'
    fields_desc = [
        scapy.BitField('flags', 0x0, 8),
        UnixTimeField('timestamp', None),
        ISDField('isd', None),
        scapy.FieldLenField('nhops', None, count_of='hops', fmt='B'),
        scapy.PacketListField('hops', None, HopField, count_from=lambda p: p.nhops),
    ]

    def extract_padding(self, p):
        return "", p

    def post_build(self, pkt, pay):
        # compute MACs on HFs
        # this is not a thing that should be done by the client normally :D
        # => only useful for testing
        # TODO This is *not* verified against a "real" SCION packet yet!
        # Somebody should do something!
        def calculate_mac(current, prev):
            if prev != None:
                prev_data = prev[HopField.RANGE_SKIP_FLAGS:HopField.RANGE_END]
            else:
                prev_data = b'\0'*(HopField.RANGE_END - HopField.RANGE_SKIP_FLAGS)
            data = (struct.pack('!I', self.timestamp) +
                    struct.pack('B', current[HopField.FLAGS] & HopField.IMMUTABLE_FLAGS) +
                    current[HopField.RANGE_SKIP_FLAGS:HopField.RANGE_BEFORE_MAC] +
                    prev_data)
            # print('prev_data: ', len(prev_data), prev_data.encode('hex'))
            # print('data: ', len(data), data.encode('hex'))
            assert len(data) == 128//8

            c = cmac.CMAC(algorithms.AES(HF_MAC_KEY), backend=default_backend())
            c.update(data)
            return c.finalize()

        for i in range(len(self.hops)):
            if not self.hops[i].mac:
                curr_beg = 8 + 8*i
                curr_end = 8 + 8*(i+1)
                prev_beg = curr_beg - 8
                mac_beg  = curr_end - 3
                curr = pkt[curr_beg:curr_end]
                prev = pkt[prev_beg:curr_beg] if i > 0 else None
                mac = calculate_mac(curr, prev)

                # print('DEBUG: updating MAC: {} -> {}'.format(struct.pack('!I', self.hops[i].mac).encode('hex'), mac.encode('hex')))
                # print('DEBUG: updating MAC -> {}'.format(mac.encode('hex')))

                mac_bytes = mac[:3]  # take the most significant bits
                pkt = pkt[:mac_beg] + mac_bytes + pkt[curr_end:]

        return pkt+pay

# def count_segments(path_hdr):
#     count = 0
#     here = 0
#     while here < len(path_hdr):
#         if 

class SCION(scapy.Packet):
    name = 'SCION'
    fields_desc = [
        # Common header
        scapy.BitField(    'version',   0,      4),
        scapy.BitEnumField('dst_type',  "ipv4", 6, SCION_ADDR_TYPE),
        scapy.BitEnumField('src_type',  "ipv4", 6, SCION_ADDR_TYPE),
        scapy.BitField(    'total_len', None,   16),
        scapy.BitField(    'hdr_len',   None,   8),
        scapy.BitField(    'curr_inf',  None,   8),
        scapy.BitField(    'curr_hf',   None,   8),
        scapy.BitEnumField('next_hdr',  None,   8, scapy.IP_PROTOS),

        scapy.PacketField('addr', None, SCIONAddr),

        scapy.PacketListField('path', None, PathSegment, count_from=lambda _: 3),
        scapy.PacketField('ext', None, SecurityExtension)
    ]

    # this is terrible, but apparently that's how scapy works :-/
    def post_build(self, pkt, pay):
        # compute lengths
        if self.total_len == None:
            self.total_len = len(pkt) + len(pay)
            pkt = pkt[:2] + struct.pack('!H', self.total_len) + pkt[4:]
        if self.hdr_len == None:
            self.hdr_len = len(pkt) - self.ext.hdr_len
            if self.hdr_len % 8 != 0:
                raise ValueError("SCION packet header length not multiple of 8 bytes!")
            self.hdr_len = int(self.hdr_len / 8) #must divide by 8
            pkt = pkt[:4] + struct.pack('B', self.hdr_len) + pkt[5:]

        return pkt+pay

def randompayload(stringLength):
    """Generate a random string of fixed length """
    letters = string.ascii_letters
    random.seed(1)
    return ''.join(random.choice(letters) for i in range(stringLength))

def set_current_inf_hf(seg, hf, pkt):
    """Calculates offsets for hf-th HF in seg-th segment and saves them in the packet.
    """
    # TODO will break when ipv4 is not hard-coded
    total_before = sum((1 + len(pkt.path[prev].hops)) for prev in range(seg))
    pkt.curr_inf = 32//8 + total_before
    pkt.curr_hf  = 32//8 + total_before + 1 + hf

    """ set correct headers """
    pkt.ext.next_hdr = scapy.IP_PROTOS.udp
    pkt.next_hdr = 222
    #pkt.ext.hdr_len = 4 + 4 + 16

    scapy.bind_layers(UDP, SCION, sport=50000)
    scapy.bind_layers(UDP, SCION, dport=50000)
    scapy.bind_layers(SCION,UDP)

    return pkt

def some_scion_packet():

    spse_key = randompayload(16)
    print(spse_key)
    spse_key_hex = hex(int("".join(str(ord(c)) for c in spse_key)))
    print(spse_key_hex)
	
    return SCION(
        addr=SCIONAddr(
            dst_isdas=ISD_AS(ISD=47, AS=0x4747), src_isdas=ISD_AS(ISD=00, AS=0x4242),
            dst_host='10.0.0.47', src_host='10.0.0.42',
        ),
        path=[
            PathSegment(timestamp=0x147, isd=42, hops=[
                HopField(ingress_if=1, egress_if=2),
                HopField(ingress_if=0, egress_if=3),
            ]),
        ],
        ext=SecurityExtension(secMode=0x0, metadata=0x147, authenticator=0x61616161626262626363636364646464)
    )

def gen_packet(v, inf=0, hf=0):
    sender = '00:60:dd:44:c2:c4' # enp3s0
    recver = '00:60:dd:44:c2:c5' # enp5s0
    return (
        Ether(dst=recver, src=sender) /
        IP(src='1.1.1.1', dst='2.2.2.2') /
        UDP(dport=50000, sport=50000) /
        set_current_inf_hf(inf, hf, some_scion_packet()) /
        UDP(dport=10047, sport=10042) /
        randompayload(v)
    )
def write(str_s,pkt):
    scapy.wrpcap(str_s, pkt, append=True)

def main():
    values = [88, 188, 288, 388, 488, 588, 688, 788, 888, 988, 1088, 1188, 1288, 1388, 1434]
    for v in values:
      p = gen_packet(v- 88)
      p.show2()
      scapy.hexdump(p)
      str_v = v
      str_s = 'bench_' + str(str_v) + '.pcap'
      write(str_s, p)

if __name__ == '__main__':
    main()
