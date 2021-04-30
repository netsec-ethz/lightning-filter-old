#ifndef _KEY_DICTIONARY_H_
#define _KEY_DICTIONARY_H_

#include <rte_memory.h>

#include "key_storage.h"

struct key_dictionary_node {
	uint64_t key;
	struct key_store_node *value;
	struct key_dictionary_node *next;
} __rte_cache_aligned;

struct key_dictionary {
	struct key_dictionary_node **table;
	size_t size;
	uint32_t count;
	struct key_store_node *value;
} __rte_cache_aligned;

struct key_dictionary *key_dictionary_new(size_t initial_size);
void key_dictionary_delete(struct key_dictionary *d);
void key_dictionary_find(struct key_dictionary *d, uint64_t key);
int key_dictionary_add(struct key_dictionary *d, uint64_t key, struct key_store_node *value);

#endif
