#include "lib/libcuckoofilter/include/cuckoo_filter.h"

#define ETH_HDR(m) (struct ether_hdr *)(rte_pktmbuf_mtod((m), uint8_t *))
#define IPV4_HDR(m) (struct ipv4_hdr *)(ETH_HDR(m) + 1)
#define UDP_HDR(m) (struct udp_hdr *)(IPV4_HDR(m) + 1)
#define CMN_HDR(m) (SCIONCommonHeader *)(UDP_HDR(m) + 1)
#define ADDRESSES_HDR(m) (*SCIONAddresses *)(CMN_HDR(m) + 1)


void print_ip(int ip);

typedef struct {
    // first 12 bits represent destination ISD and rest the destination AS
    uint32_t dst_isd_and_as;

    // first 12 bits represent the source ISD and rest the source AS
    uint32_t src_isd_and_as;

    // There's more fields here but we don't require it and also it can
    // be variable length (ipv4 vs ipv6), therefore the overhead is not
    // worth the consistency and we define it here insteda of the packet.c
    // file.
} SCIONAddresses;

typedef struct {
    uint8_t NextHdr;
    uint8_t ExtHdrLen;
    uint8_t ExtType;

    // Next comes the ExtPayload, whose size depends on the type of extension
} SCIONExtHeader;


void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}
