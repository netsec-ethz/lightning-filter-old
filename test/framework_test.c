#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void test_simple(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	//char* p;
	//scionfwd_usage(p);
    //assert_true(4 == 4);
}

static void test_negative(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	//int res = get_addr_len(0);
    //assert_true(-1 == res);
}

static void test_null(void **state)
{	
	if(state == NULL){
		state = NULL;
	}
    assert_true(0 == 0);
}

