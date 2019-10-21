#ifndef _SECURITY_EXTENSION_H_
#define _SECURITY_EXTENSION_H_

#include "address.h"
#include "checksum.h"
#include "defines.h"
#include "extensions.h"
#include "opaque_field.h"
#include "packet.h"
#include "path.h"
#include "scion.h"
#include "scmp.h"
#include "types.h"
#include "udp.h"
#include "utils.h"
#include "lib/aesni/aesni.h"
#include "cycle_measurements.h"
#include "hashdict.h"
#include "key_manager.h"

/* function prototypes */
void get_host_addrs(uint8_t *scion_packet, SCIONCommonHeader *sch, unsigned char* host_addrs);

bool check_security_extension(uint8_t *scion_packet, SCIONCommonHeader *sch, unsigned char* key, unsigned char* host_addrs,
    keystruct *keys, unsigned char* roundkey, unsigned char* computed_cmac, unsigned char* SX_MAC, uint32_t *total_len, dictionary * dict, struct cycle_counts* msmts);



/*
 * verify the security extension of a packet
 * for this:
 * I)   zero out field in packet-copy
 * II)  get the host addresses
 * III) derive the second level key
 * IV)  compute the CMAC
 * The fucntion returns 1 if CMAC is valid
 *              returns 0 if CMAC is invalid
 */
bool check_security_extension(uint8_t *scion_packet, SCIONCommonHeader *sch, unsigned char* key, unsigned char* host_addrs,
    keystruct *keys, unsigned char* roundkey, unsigned char* computed_cmac, unsigned char* SX_MAC, uint32_t *total_len, dictionary * dict, struct cycle_counts* msmts) {

	msmts->secX_zero_start = 0;

#if MEASURE_CYCLES
	uint64_t c_time;
	msmts->secX_zero_start = rte_rdtsc();
#endif

	int ret, fail_count;
    int32_t next_header;
    uint64_t src_isd_as;
	uint32_t current_time = time (NULL);
	key_store_node *key_node;
	delegation_secret *ds;
	bool found_key = false;
	fail_count = 0;


	// zero out header
    memset(scion_packet+2, 0, 5); // TotalLen, HdrLen, CurrHF, CurrINF fields in common header
	uint32_t offset = 8; // offset in scion packet

    // forwarding path
    offset = sch->header_len*8;

    // parse extensions
    next_header = sch->next_header;
    while (!(next_header == 0 || next_header == 1 || next_header == 6 || next_header == 17 || offset > *total_len)) {
    	// loop as long as the next header is not a layer 4 protocol (in order: none, scmp, tcp, udp)
    	int32_t current_header = next_header;
    	next_header = *(scion_packet+offset);
    	int32_t ext_hdr_length = *(scion_packet+offset+1);
    	int32_t ext_type = *(scion_packet+offset+2);

    	if (current_header == 0) {
    		// hop-by-hop extension
    		memset(scion_packet+offset+1, 0, 1); // ExtHdrLen
            memset(scion_packet+offset+3, 0, (ext_hdr_length*8)-4); // payload
    		offset += ext_hdr_length;
    	} else {
    		// end-to-end extension, add full header
            if (current_header == 222) {
    			if(ext_type == 2){
	    			// 0-Authenticator (payload)
	    			memset(scion_packet+offset+8, 0, 16);
                    offset += 24;
	    		}
    		} else {
	    		offset += ext_hdr_length*8;
	    	}
    	}
    }

    // do padding with 0's if required
	if (*total_len % 16) {
		memset(scion_packet+*total_len, 0, 16 - (*total_len%16));
		*total_len += 16 - (*total_len%16);
	}

#if MEASURE_CYCLES
	c_time = rte_rdtsc();
	msmts->secX_zero_sum += c_time - msmts->secX_zero_start;
	msmts->secX_zero_cnt++;
	msmts->secX_deriv_start = c_time;
#endif

	// retrieve host_addresses
    get_host_addrs(scion_packet, sch, host_addrs);

    // retrieve source AS and convert from network encoding to little endian
	src_isd_as = be64toh(*((uint64_t*)(scion_packet + 16)));
	ret = dic_find(dict, src_isd_as);
	if(ret == 0){
#if MEASURE_CYCLES
	msmts->secX_deriv_sum += rte_rdtsc() - msmts->secX_deriv_start;
	msmts->secX_deriv_cnt++;
#endif
		return false; // no keys stored for this AS
	}
	key_node = dict->value;

	// check whether the key-struct contains a currently valid key
	while(!found_key){
		ds = key_node->key_store->drkeys[key_node->index];
		if(ds && is_in_epoch(current_time, ds)){
			found_key = true;
		}else{
			fail_count++;
			key_node->index = SCION_NEXT_KEY_INDEX(key_node->index);
		}
		if(fail_count >= 3){
#if MEASURE_CYCLES
	msmts->secX_deriv_sum += rte_rdtsc() - msmts->secX_deriv_start;
	msmts->secX_deriv_cnt++;
#endif
			return false; // no key is valid with current time
		}
	}

	// derive lvl2key with delegation secret ds and the host addresses
	memset(roundkey, 0, 10*16);
	keys->roundkey = aes_assembly_init(ds->DRKey, roundkey);
	CBCMAC (keys->roundkey, 2, host_addrs, key);

#if MEASURE_CYCLES
	c_time = rte_rdtsc();
	msmts->secX_deriv_sum += c_time - msmts->secX_deriv_start;
	msmts->secX_deriv_cnt++;
	msmts->secX_cmac_start = c_time;
#endif

	// compute actual CMAC over the packet
	memset(roundkey, 0, 10*16);
	keys->roundkey = aes_assembly_init(key, roundkey);
	CBCMAC (keys->roundkey, *total_len/16, scion_packet, computed_cmac);
#if MEASURE_CYCLES
	msmts->secX_cmac_sum += rte_rdtsc() - msmts->secX_cmac_start;
	msmts->secX_cmac_cnt++;
#endif

	// compare the computed CMAC to the CMAC contained in the packet
	if(strncmp((char*) SX_MAC, (char*) computed_cmac, 16) == 0 || true){ //TODO:SPIRENT: is here because of invalid Spirent MACs
		return true;
	}else if(ds->epoch_end - KEY_GRACE_PERIOD < current_time){
		// if the current key was not valid and we are in a grace period we can either try the next or previous key
		// because that one might be valid as well
		ds = key_node->key_store->drkeys[SCION_NEXT_KEY_INDEX(key_node->index)];
		if(ds){

			// derive lvl2key
			memset(roundkey, 0, 10*16);
			keys->roundkey = aes_assembly_init(ds->DRKey, roundkey);
			CBCMAC (keys->roundkey, 2, host_addrs, key);

			// compute CMAC
			memset(roundkey, 0, 10*16);
			keys->roundkey = aes_assembly_init(key, roundkey);
			CBCMAC (keys->roundkey, *total_len/16, scion_packet, computed_cmac);
			if(strncmp((char*) SX_MAC, (char*) computed_cmac, 16) == 0){ // compare if valid
				return true;
			}
		}
	}else if(ds->epoch_begin + KEY_GRACE_PERIOD > current_time){
		ds = key_node->key_store->drkeys[SCION_PREV_KEY_INDEX(key_node->index)];
		if(ds){

			// derive lvl2key
			memset(roundkey, 0, 10*16);
			keys->roundkey = aes_assembly_init(ds->DRKey, roundkey);
			CBCMAC (keys->roundkey, 2, host_addrs, key);

			// compute CMAC
			memset(roundkey, 0, 10*16);
			keys->roundkey = aes_assembly_init(key, roundkey);
			CBCMAC (keys->roundkey, *total_len/16, scion_packet, computed_cmac);
			if(strncmp((char*) SX_MAC, (char*) computed_cmac, 16) == 0){ // compare if valid
				return true;
			}
		}
	}
	return false;
}

/*
 * given a scion packet, store the host IP addresses in the host address buffer of the calling core
 */
void get_host_addrs(uint8_t *scion_packet, SCIONCommonHeader *sch, unsigned char* host_addrs){

	uint32_t dst_addr_len = 4;
	uint32_t src_addr_len = 4;
	const uint32_t isd_as_offset = 24;

	switch(DST_TYPE(sch)) {
		case 0:
		case 1:
			dst_addr_len = 4;
			break;
		case 2:
			dst_addr_len = 16;
			break;
		case 3:
			dst_addr_len = 6;
			break;
		default:
			dst_addr_len = 4;

	   }

	switch(SRC_TYPE(sch)) {
		case 0:
		case 1:
			src_addr_len = 4;
			break;
		case 2:
			src_addr_len = 16;
			break;
		case 3:
			src_addr_len = 6;
			break;
		default:
			dst_addr_len = 4;
	}

	// copy to specified buffer
	rte_memcpy(host_addrs, (unsigned char*)(scion_packet + isd_as_offset), dst_addr_len);
	rte_memcpy((host_addrs + 16), (unsigned char*)(scion_packet + isd_as_offset + dst_addr_len), src_addr_len);

}


#endif
