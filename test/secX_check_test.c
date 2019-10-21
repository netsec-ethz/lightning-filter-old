#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


#include "security_extension.h"

static void test_copy_host_addrs(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	unsigned char * packet = "\x00\x41\x00\x58\x07\x04\x05\xde\x00\x2f\x00\x00\x00\x00\x47\x47" \
			"\x00\x00\x00\x00\x00\x00\x42\x42\x0a\x00\x00\x2f\x0a\x00\x00\x2a" \
			"\x00\x00\x00\x01\x47\x00\x2a\x02\x00\x3f\x00\x10\x02\x1f\xc2\x2f" \
			"\x00\x3f\x00\x00\x03\x1b\xa3\x97\x11\x03\x02\x00\x00\x00\x01\x47" \
			"\x61\x61\x61\x61\x62\x62\x62\x62\x63\x63\x63\x63\x64\x64\x64\x64" \
			"\x27\x3a\x27\x3f\x00\x08\x00\x00";

	SCIONCommonHeader *sch = (SCIONCommonHeader *)packet;
	unsigned char *scion_packet = packet;
	unsigned char host_addr_buffer[32];

	//printf("dst_type %d\n",DST_TYPE(sch));
	//printf("src %d\n",SRC_TYPE(sch));
	assert_true(DST_TYPE(sch) == 1);
	assert_true(SRC_TYPE(sch) == 1);

	//printf("offs %x\n", *(unSRC_TYPE(sch)signed int*)(scion_packet+24));
	//printf("offs %x\n", *(unsigned int*)(scion_packet+24+4));

	get_host_addrs(scion_packet, sch,  host_addr_buffer);

	assert_memory_equal(scion_packet+24, host_addr_buffer, 4);
	assert_memory_equal(scion_packet+24+4, host_addr_buffer+16, 4);


}


static void test_derive_lvl2DRKey(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	unsigned char  packet[88] = "\x00\x41\x00\x58\x07\x04\x05\xde\x00\x2f\x00\x00\x00\x00\x47\x47" \
			"\x00\x00\x00\x00\x00\x00\x42\x42\x0a\x00\x00\x2f\x0a\x00\x00\x2a" \
			"\x00\x00\x00\x01\x47\x00\x2a\x02\x00\x3f\x00\x10\x02\x1f\xc2\x2f" \
			"\x00\x3f\x00\x00\x03\x1b\xa3\x97\x11\x03\x02\x00\x00\x00\x01\x47" \
			"\x61\x61\x61\x61\x62\x62\x62\x62\x63\x63\x63\x63\x64\x64\x64\x64" \
			"\x27\x3a\x27\x3f\x00\x08\x00\x00";

	SCIONCommonHeader *sch = (SCIONCommonHeader *)packet;
	unsigned char *scion_packet = packet;
	unsigned char host_addr_buffer[32] = "";
	unsigned char key_buffer[16] = "";
	keystruct *keys = malloc(sizeof(keystruct));
	unsigned char roundkey[196] = ""; // stack smashing
	unsigned char computed_cmac[16] = "";
	unsigned char SX_MAC[16] = "";
	uint32_t total_len = 88;

	uint64_t as = be64toh(*((uint64_t*)(scion_packet + 16)));
	uint32_t now = time(NULL);
	uint32_t next_time;

	key_storage *key_storage = malloc(sizeof(key_storage));
	key_store_node* key_store_node = malloc(sizeof(key_store_node));
	key_store_node->index = 0;
	key_store_node->key_store = key_storage;

	dictionary * dict = dic_new(32);

	dic_add(dict,as, key_store_node);


	dic_find(dict,as);
	key_storage = dict->value->key_store;

	delegation_secret *key = malloc(sizeof(key_storage));
	get_DRKey(now, as, key);
	next_time = key->epoch_end;
	key_storage->drkeys[0] = key;
	key = malloc(sizeof(key_storage));
	get_DRKey(next_time, as, key);
	key_storage->drkeys[1] = key;

	struct cycle_counts msmts;

	check_security_extension(scion_packet, sch, key_buffer, host_addr_buffer,
	    keys, roundkey, computed_cmac, SX_MAC, &total_len, dict, &msmts);

	assert_memory_equal("\xc3\x2b\x03\x6f\x47\x50\x4d\x18\x72\x00\x4b\xf6\xbf\x0f\x1f\x19", key_buffer, 16);
}


static void test_compute_cmac(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	unsigned char  packet[88] = "\x00\x41\x00\x58\x07\x04\x05\xde\x00\x2f\x00\x00\x00\x00\x47\x47" \
			"\x00\x00\x00\x00\x00\x00\x42\x42\x0a\x00\x00\x2f\x0a\x00\x00\x2a" \
			"\x00\x00\x00\x01\x47\x00\x2a\x02\x00\x3f\x00\x10\x02\x1f\xc2\x2f" \
			"\x00\x3f\x00\x00\x03\x1b\xa3\x97\x11\x03\x02\x00\x00\x00\x01\x47" \
			"\x61\x61\x61\x61\x62\x62\x62\x62\x63\x63\x63\x63\x64\x64\x64\x64" \
			"\x27\x3a\x27\x3f\x00\x08\x00\x00";

	SCIONCommonHeader *sch = (SCIONCommonHeader *)packet;
	unsigned char *scion_packet = packet;
	unsigned char host_addr_buffer[32] = "";
	unsigned char key_buffer[16] = "";
	keystruct *keys = malloc(sizeof(keystruct));
	unsigned char roundkey[196] = ""; // (unsigned char*)malloc_aligned(16, 10*16*sizeof(char));
	unsigned char computed_cmac[16] = "";
	unsigned char SX_MAC[16] = "\x68\xbf\x9b\x69\x9c\xb9\xac\x01\x8b\x08\xb8\x3d\xef\xfe\x7a\x94";
	uint32_t total_len = 88;

	uint64_t as = be64toh(*((uint64_t*)(scion_packet + 16)));
	uint32_t now = time(NULL);
	uint32_t next_time;

	key_storage *key_storage = malloc(sizeof(key_storage));
	key_store_node* key_store_node = malloc(sizeof(key_store_node));
	key_store_node->index = 0;
	key_store_node->key_store = key_storage;

	dictionary * dict = dic_new(32);

	dic_add(dict,as, key_store_node);


	dic_find(dict,as);
	key_storage = dict->value->key_store;

	delegation_secret *key = malloc(sizeof(key_storage));
	get_DRKey(now, as, key);
	next_time = key->epoch_end;
	key_storage->drkeys[0] = key;
	key = malloc(sizeof(key_storage));
	get_DRKey(next_time, as, key);
	key_storage->drkeys[1] = key;

	struct cycle_counts msmts;

	check_security_extension(scion_packet, sch, key_buffer, host_addr_buffer,
	    keys, roundkey, computed_cmac, SX_MAC, &total_len, dict, &msmts);

	assert_memory_equal(SX_MAC, computed_cmac, 6);
}
