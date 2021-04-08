#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <cmocka.h>


#include "key_manager.h"

static void test_in_epoch_in(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	uint32_t val_time;
	delegation_secret *key = malloc(sizeof *key);

	val_time = time(NULL);
	key->epoch_begin = val_time - 1;
	key->epoch_end = val_time + 1;

	res = is_in_epoch(val_time, key);
	assert_true(res == 1);
}

static void test_in_epoch_out_before(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	uint32_t val_time;
	delegation_secret *key = malloc(sizeof *key);

	val_time = time(NULL);
	key->epoch_begin = val_time + 1;
	key->epoch_end = val_time + 2;

	res = is_in_epoch(val_time, key);
	assert_true(res == 0);
}

static void test_in_epoch_out_after(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	uint32_t val_time;
	delegation_secret *key = malloc(sizeof *key);

	val_time = time(NULL);
	key->epoch_begin = val_time - 2;
	key->epoch_end = val_time - 1;

	res = is_in_epoch(val_time, key);
	assert_true(res == 0);
}

static void test_in_epoch_border_begin(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	uint32_t val_time;
	delegation_secret *key = malloc(sizeof *key);

	val_time = time(NULL);
	key->epoch_begin = val_time;
	key->epoch_end = val_time + 1;

	res = is_in_epoch(val_time, key);
	assert_true(res == 1);
}

static void test_in_epoch_border_end(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	uint32_t val_time;
	delegation_secret *key = malloc(sizeof *key);

	val_time = time(NULL);
	key->epoch_begin = val_time - 1;
	key->epoch_end = val_time;

	res = is_in_epoch(val_time, key);
	assert_true(res == 1);
}

static void test_get_DRKey(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	int res;
	uint32_t val_time;
	uint64_t srcIA;
	delegation_secret *key = malloc(sizeof *key);

	val_time = time(NULL);
	srcIA = 1;

	res = get_DRKey(val_time, srcIA, key);

	assert_true(res == 0);
	assert_non_null(key);

	assert_true(key->src_ia == srcIA);
	assert_true(key->epoch_begin == val_time);
	assert_true(key->epoch_begin < key->epoch_end);
}

static void test_get_DRKey_mock_AS(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	int res;
	uint32_t val_time;
	uint64_t srcIA;
	delegation_secret *key = malloc(sizeof *key);

	val_time = time(NULL);
	srcIA = 1;

	res = get_DRKey(val_time, srcIA, key);

	assert_true(res == 0);
	assert_non_null(key);

	assert_true(key->src_ia == srcIA);
	assert_true(key->dst_ia == 0);

}

static void test_get_DRKey_mock_epoch(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	int res;
	uint32_t val_time;
	uint64_t srcIA;
	delegation_secret *key = malloc(sizeof *key);

	val_time = time(NULL);
	srcIA = 1;

	res = get_DRKey(val_time, srcIA, key);

	assert_true(res == 0);
	assert_non_null(key);

	assert_true(key->src_ia == srcIA);
	assert_true(key->epoch_begin == val_time);
	assert_true(key->epoch_end == val_time + 90);
	assert_true(key->epoch_end == key->epoch_begin + 90);
}

static void test_get_DRKey_mock_key_state(void **state)
{	
	if(state == NULL){
		state = NULL;
	}

	int res;
	uint32_t val_time;
	uint64_t srcIA;
	delegation_secret *key = malloc(sizeof *key);

	const char *key_1 = "aaaabbbbccccdddd";
	//char *key_2 = "eeeeffffgggghhhh";

	val_time = time(NULL);
	srcIA = 1;

	res = get_DRKey(val_time, srcIA, key);

	assert_true(res == 0);
	assert_non_null(key);

	uint32_t currentSecond = val_time % 60;
	if (currentSecond < 30) {
		assert_memory_equal(key->DRKey, key_1, 16);
	} else {
		assert_memory_equal(key->DRKey, key_1, 16);
	}
}


static void test_check_and_fetch(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	int res;
	uint64_t srcIA;
	key_store_node *node = malloc(sizeof *node);
	node->key_store = malloc(sizeof *node->key_store);
	srcIA = 1;

	assert_null(node->key_store->drkeys[0]);
	assert_null(node->key_store->drkeys[1]);
	assert_null(node->key_store->drkeys[2]);

	res = check_and_fetch(node, srcIA);
	assert_true(res == 0);

	assert_non_null(node->key_store->drkeys[0]);
	assert_non_null(node->key_store->drkeys[1]);
	assert_null(node->key_store->drkeys[2]);

	assert_true(node->key_store->drkeys[0]->epoch_begin < node->key_store->drkeys[1]->epoch_begin);


}

static void test_check_and_fetch_grace_period(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	int res;
	uint64_t srcIA;
	key_store_node *node = malloc(sizeof *node);
	node->key_store = malloc(sizeof *node->key_store);
	srcIA = 1;

	assert_null(node->key_store->drkeys[0]);
	assert_null(node->key_store->drkeys[1]);
	assert_null(node->key_store->drkeys[2]);

	res = check_and_fetch(node, srcIA);
	assert_true(res == 0);

	sleep(KEY_GRACE_PERIOD + 1);

	res = check_and_fetch(node, srcIA);
	assert_true(res == 0);

	assert_non_null(node->key_store->drkeys[0]);
	assert_non_null(node->key_store->drkeys[1]);
	assert_non_null(node->key_store->drkeys[2]);

	assert_true(node->key_store->drkeys[0]->epoch_begin < node->key_store->drkeys[1]->epoch_begin);
	assert_true(node->key_store->drkeys[1]->epoch_begin < node->key_store->drkeys[2]->epoch_begin);

}

static void test_check_and_fetch_grace_suspicious_long(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	int res;
	uint64_t srcIA;
	key_store_node *node = malloc(sizeof *node);
	node->key_store = malloc(sizeof *node->key_store);
	srcIA = 1;

	assert_null(node->key_store->drkeys[0]);
	assert_null(node->key_store->drkeys[1]);
	assert_null(node->key_store->drkeys[2]);

	res = check_and_fetch(node, srcIA);
	assert_true(res == 0);

	node->key_store->drkeys[1]->epoch_end *= 2;

	sleep(KEY_GRACE_PERIOD + 1);

	res = check_and_fetch(node, srcIA);
	assert_true(res == -1);
}

static void test_check_and_fetch_grace_suspicious_short(void **state)
{
	if(state == NULL){
		state = NULL;
	}

	int res;
	uint64_t srcIA;
	key_store_node *node = malloc(sizeof *node);
	node->key_store = malloc(sizeof *node->key_store);
	srcIA = 1;

	assert_null(node->key_store->drkeys[0]);
	assert_null(node->key_store->drkeys[1]);
	assert_null(node->key_store->drkeys[2]);

	res = check_and_fetch(node, srcIA);
	assert_true(res == 0);

	node->key_store->drkeys[1]->epoch_end = node->key_store->drkeys[1]->epoch_begin;

	sleep(KEY_GRACE_PERIOD + 1);

	res = check_and_fetch(node, srcIA);
	assert_true(res == -1);
}
