#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


static void cfg_end_hosts(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;

	res = load_rate_limits("../test/test_config/end_hosts.cfg");
	assert_true(res == 0);
}

static void cfg_end_hosts_too_many(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;

	res = load_rate_limits("../test/test_config/end_hosts_too_many.cfg");
	assert_true(res == -1);
}

static void cfg_end_hosts_mismatch(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;

	res = load_rate_limits("../test/test_config/end_hosts_mismatch.cfg");
	assert_true(res == -1);
}

static void cfg_end_hosts_not_found(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;

	res = load_rate_limits("../test/test_config/end_hosts_missing.cfg");
	assert_true(res == -1);
}

static void cfg_scion_filter(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;

	res = load_config("../test/test_config/scion_filter.cfg");
	assert_true(res == 0);
}

static void cfg_scion_filter_set_all(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;

	res = load_config("../test/test_config/scion_filter_all.cfg");
	assert_true(res == 0);
}


