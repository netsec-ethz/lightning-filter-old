#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


int unit_test_main(void);

static void test_simple(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	printf("test simple\n");
	//char* p;
	//scionfwd_usage(p);
    //assert_true(4 ==4);
}

static void test_negative(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	printf("test simple\n");
	//int res = get_addr_len(0);
    //assert_true(-1 == res);
}

static void test_null(void **state)
{	
	if(state == NULL){
		state = NULL;
	}
	printf("test simple\n");
    assert_true(0 == 0);
}

int unit_test_main(void)
{
	const struct CMUnitTest tests[] = {

        cmocka_unit_test(test_simple),
        cmocka_unit_test(test_negative),
        cmocka_unit_test(test_null),
    };
	int failed_tests = cmocka_run_group_tests(tests, NULL, NULL);
    return failed_tests;
}
