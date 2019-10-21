#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "hashdict.h"

static void hashdict_create(void **state)
{
	if(state == NULL){
			state = NULL;
		}
	int initial_size = 64;
	struct dictionary * dict;
	dict = dic_new(initial_size);

	assert_true(dict->length == 64);
	assert_true(dict->count == 0);
	assert_null(dict->value);
}


static void hashdict_add_node(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	struct dictionary * dict;
	struct key_store_node node;
	uint64_t key;
	int initial_size = 64;
	int ret;

	//create new dict
	dict = dic_new(initial_size);
	node.index = 0;
	key = 100;

	//add element
	ret = dic_add(dict, key, &node);
	assert_true(ret == 0);

	//check if present
	ret = dic_find(dict, key);
	assert_true(ret == 1);
	assert_true(dict->count == 1);
}

static void hashdict_add_twice(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	struct dictionary * dict;
	struct key_store_node node;
	uint64_t key;
	int initial_size = 64;
	int ret;

	dict = dic_new(initial_size);
	node.index = 1;
	key = 100;

	// add first time
	ret = dic_add(dict, key, &node);
	assert_true(ret == 0);

	// check if first key found
	ret = dic_find(dict, key);
	assert_true(ret == 1);
	assert_true(dict->count == 1);

	// add second time
	ret = dic_add(dict, key, &node);
	assert_true(ret == 1);

	//check if old key untouched and still only one elem in dict
	ret = dic_find(dict, key);
	assert_true(ret == 1);
	assert_true(dict->count == 1);
	assert_true(dict->value->index == 1);
}

static void hashdict_find_node(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	struct dictionary *dict;
	struct key_store_node *node;
	uint64_t key;
	int initial_size = 64;
	int ret;

	dict = dic_new(initial_size);

	node = malloc(sizeof(struct key_store_node));
	node->index = 0;
	key = 0;
	ret = dic_add(dict, key, node);
	assert_true(ret == 0);
	assert_true(dict->count == 1);

	node = malloc(sizeof(struct key_store_node));
	node->index = 1;
	key = 1;
	ret = dic_add(dict, key, node);
	assert_true(ret == 0);
	assert_true(dict->count == 2);

	node = malloc(sizeof(struct key_store_node));
	node->index = 2;
	key = 2;
	ret = dic_add(dict, key, node);
	assert_true(ret == 0);
	assert_true(dict->count == 3);

	for (int i = 0; i < 10; i++){
		ret = dic_find(dict, i);
		if(i < 3){
			//true case
			assert_true(ret == 1);
			assert_true(dict->value->index == i);
		}else{
			//false case
			assert_true(ret == 0);
		}
	}

}

static void hashdict_delete_node(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	struct dictionary *dict;
	struct key_store_node *node;
	uint64_t key;
	int initial_size = 64;
	int ret;

	dict = dic_new(initial_size);

	// add node
	node = malloc(sizeof(struct key_store_node));
	node->index = 2;
	key = 2;
	ret = dic_add(dict, key, node);
	assert_true(ret == 0);

	// remove non-existent
	assert_true(dict->count = 1);
	ret = dic_remove(dict, 1);
	assert_true(ret == 0);
	assert_true(dict->count = 1);

	// remove existent
	assert_true(dict->count = 1);
	ret = dic_remove(dict, key);
	assert_true(ret == 1);
	assert_true(dict->count == 0);

	// remove removed
	ret = dic_remove(dict, key);
	assert_true(ret == 0);
	assert_true(dict->count == 0);
}


static void hashdict_resize(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	struct dictionary *dict;
	struct key_store_node *node;
	uint64_t key;
	int initial_size = 1;
	int ret;

	dict = dic_new(initial_size);

	assert_true(dict->count == 0);
	assert_true(dict->length == 1);

	//add object to map
	node = malloc(sizeof(struct key_store_node));
	node->index = 0;
	key = 0;
	ret = dic_add(dict, key, node);
	assert_true(ret == 0);
	assert_true(dict->count == 1);
	assert_true(dict->length == 1);

	node = malloc(sizeof(struct key_store_node));
	node->index = 1;
	key = 1;
	ret = dic_add(dict, key, node);
	assert_true(ret == 0);
	assert_true(dict->count == 2);
	assert_true(dict->length == 1);

	// add object to cause resize
	node = malloc(sizeof(struct key_store_node));
	node->index = 2;
	key = 2;
	ret = dic_add(dict, key, node);
	assert_true(ret == 0);
	assert_true(dict->count == 3);
	assert_true(dict->length == 1);

	// add object to cause resize
	node = malloc(sizeof(struct key_store_node));
	node->index = 0;
	key = 3;
	ret = dic_add(dict, key, node);

	assert_true(ret == 0);
	assert_true(dict->count == 4);
	assert_true(dict->length == 1 * dict->growth_factor);


	//check all keys are present
	for( int i = 0; i < 4; i++){
		ret = dic_find(dict, key);
		assert_true(ret == 1);
	}
}


static void hashdict_full(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	struct dictionary *dict;
	struct key_store_node *node;
	uint64_t key;
	int initial_size = 1;
	int ret;

	dict = dic_new(initial_size);

	node = malloc(sizeof(struct key_store_node));
	node->index = 0;
	key = 0;
	ret = dic_add(dict, key, node);

	node = malloc(sizeof(struct key_store_node));
	node->index = 1;
	key = 1;
	ret = dic_add(dict, key, node);

	node = malloc(sizeof(struct key_store_node));
	node->index = 2;
	key = 2;
	ret = dic_add(dict, key, node);

	node = malloc(sizeof(struct key_store_node));
	node->index = 0;
	key = 3;
	ret = dic_add(dict, key, node);

	//check all keys are present
	for( int i = 0; i < 4; i++){
		ret = dic_find(dict, i);
		assert_true(ret == 1);
	}


	//remove a key in the middle
	ret = dic_remove(dict, 0);
	assert_true(ret == 1);

	//check availability of all keys
	for( int i = 0; i < 4; i++){
		ret = dic_find(dict, i);
		if(i == 0){
			assert_true(ret == 0);
		}else{
			assert_true(ret == 1);
		}

	}

	//remove first key
	ret = dic_remove(dict, 3);
	assert_true(ret == 1);

	//check availability of all keys
	for( int i = 0; i < 4; i++){
		ret = dic_find(dict, i);
		if(i == 0 || i == 3){
			assert_true(ret == 0);
		}else{
			assert_true(ret == 1);
		}

	}
}

