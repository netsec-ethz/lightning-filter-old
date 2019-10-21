#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "security_extension.h"

static void test_packet(void **state)
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

