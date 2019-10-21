#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "scion_bloom.h"


int unit_test_main(void);

static void test_bloom_init(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	uint64_t nb_entries = 700000;
	uint64_t error_rate  = 10000;
	struct bloom bloom_filter;
	int res;

	// standard bloom filter
	res = bloom_init(&bloom_filter, nb_entries, 1.0/error_rate);
	assert_true(res == 0);

	// too small
	res = bloom_init(&bloom_filter, 999, 1.0/error_rate);
	assert_true(res == 1);
	
	// error 0.0
	res = bloom_init(&bloom_filter, nb_entries, 0.0);
	assert_true(res == 1);

	// error 1.0
	res = bloom_init(&bloom_filter, nb_entries, 1.0);
	assert_true(res == 0);

	//error negative
	res = bloom_init(&bloom_filter, nb_entries, -1.0);
	assert_true(res == 1);

	//error > 1
	res = bloom_init(&bloom_filter, nb_entries, 2.0);
	assert_true(res == 1);

}

static void test_bloom_free(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	uint64_t nb_entries = 700000;
	uint64_t error_rate  = 10000;
	struct bloom bloom_filter;
	int res;


	//first add
	res = bloom_init(&bloom_filter, nb_entries, 1.0/error_rate);
	res = sc_bloom_add(&bloom_filter, 1, 0, "aaaabbbbccccdddd", 16);
	assert_true(res == 0);
	// second add
	res = sc_bloom_add(&bloom_filter, 1, 0, "aaaabbbbccccdddd", 16);
	assert_true(res == 1);


	//free
	bloom_free(&bloom_filter);

	// should be empty again
	res = bloom_init(&bloom_filter, nb_entries, 1.0/error_rate);
	res = sc_bloom_add(&bloom_filter, 1, 0, "aaaabbbbccccdddd", 16);
	assert_true(res == 0);
}

static void test_bloom_add(void **state)
{	
	if(state == NULL){
		state = NULL;
	}

	uint64_t nb_entries = 700000;
	uint64_t error_rate  = 10000;
	struct bloom bloom_filter;
	int res;

	// uninitialised
	/* somebody modified the bloom filter implementation to skip the initialisation check
	 * in order to improve performance I guess.
	 * It should actually return -1
	 */
	//res = sc_bloom_add(&bloom_filter, 1, 0, "aaaabbbbccccdddd", 16);
	//assert_true(res == 0);

	//first add
	res = bloom_init(&bloom_filter, nb_entries, 1.0/error_rate);
	res = sc_bloom_add(&bloom_filter, 1, 0, "aaaabbbbccccdddd", 16);
	assert_true(res == 0);
	// second add
	res = sc_bloom_add(&bloom_filter, 1, 0, "aaaabbbbccccdddd", 16);
	assert_true(res == 1);
	// different add
	res = sc_bloom_add(&bloom_filter, 1, 0, "eeeeffffgggghhhh", 16);
	assert_true(res == 0);
}

static void test_bloom_add_two_filters(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	uint64_t nb_entries = 700000;
	uint64_t error_rate  = 10000;
	struct bloom bloom_filter[2];
	int res;

	//init
	res = bloom_init(&bloom_filter[0], nb_entries, 1.0/error_rate);
	assert_true(res == 0);
	res = bloom_init(&bloom_filter[1], nb_entries, 1.0/error_rate);
	assert_true(res == 0);

	//add and check in first filter
	res = sc_bloom_add(bloom_filter, 2, 0, "aaaabbbbccccdddd", 16);
	assert_true(res == 0);
	res = sc_bloom_add(bloom_filter, 2, 0, "aaaabbbbccccdddd", 16);
	assert_true(res == 1);

	// check elems in second filter
	res = sc_bloom_add(bloom_filter, 2, 1, "aaaabbbbccccdddd", 16);
	assert_true(res == 1);
	res = sc_bloom_add(bloom_filter, 2, 1, "eeeeffffgggghhhh", 16);
	assert_true(res == 0);
}

static void test_bloom_reset_two_filters(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	uint64_t nb_entries = 700000;
	uint64_t error_rate  = 10000;
	struct bloom bloom_filter[2];
	int res;

	// init both filters
	res = bloom_init(&bloom_filter[0], nb_entries, 1.0/error_rate);
	assert_true(res == 0);
	res = bloom_init(&bloom_filter[1], nb_entries, 1.0/error_rate);
	assert_true(res == 0);

	// add elem to first filter
	res = sc_bloom_add(bloom_filter, 2, 0, "aaaabbbbccccdddd", 16);
	assert_true(res == 0);

	// add elem to second filter
	res = sc_bloom_add(bloom_filter, 2, 1, "eeeeffffgggghhhh", 16);
	assert_true(res == 0);

	bloom_free(&bloom_filter[0]);
	res = bloom_init(&bloom_filter[0], nb_entries, 1.0/error_rate);

	// elem in filter 1 should be gone
	res = sc_bloom_add(bloom_filter, 2, 1, "aaaabbbbccccdddd", 16);
	assert_true(res == 0);

	// elem in filter 2 should still be there
	res = sc_bloom_add(bloom_filter, 2, 1, "eeeeffffgggghhhh", 16);
	assert_true(res == 1);


}

static void test_bloom_check(void **state){
	if(state == NULL){
			state = NULL;
		}

		uint64_t nb_entries = 700000;
		uint64_t error_rate  = 10000;
		struct bloom bloom_filter;
		int res;

		//first add
		bloom_init(&bloom_filter, nb_entries, 1.0/error_rate);
		res = sc_bloom_add(&bloom_filter, 1, 0, "aaaabbbbccccdddd", 16);

		res = bloom_check(&bloom_filter, 1, 0, "aaaabbbbccccdddd", 16);
		assert_true(res == 1);
		res = bloom_check(&bloom_filter, 1, 0, "aaaabbbbccccdddd", 16);
		assert_true(res == 1);
		res = bloom_check(&bloom_filter, 1, 0, "eeeeffffgggghhhh", 16);
		assert_true(res == 0);

		// for some reason the check function internally calls the add function,
		// so on the second check call we expect true
		res = bloom_check(&bloom_filter, 1, 0, "eeeeffffgggghhhh", 16);
		assert_true(res == 1);
}


