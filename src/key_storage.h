#ifndef _KEY_STORAGE_H_
#define _KEY_STORAGE_H_

#include <rte_memory.h>

#define NEXT_KEY_INDEX(x) (((x) + 1) % 3)
#define PREV_KEY_INDEX(x) (((x) + 2) % 3)

struct delegation_secret {
	int64_t validity_not_before;
	int64_t validity_not_after;
	unsigned char key[16];
} __rte_cache_aligned;

struct key_store {
	struct delegation_secret delegation_secrets[3];
} __rte_cache_aligned;

struct key_store_node {
	size_t key_index;
	struct key_store *key_store;
} __rte_cache_aligned;

#endif
