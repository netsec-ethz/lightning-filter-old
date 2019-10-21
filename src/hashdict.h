#ifndef _HASH_DICTC_H_
#define _HASH_DICTC_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <rte_memory.h>

#include "key_storage.h"

typedef int (*enumFunc)(void *key, int count, int *value, void *user);

typedef struct dictionary dictionary;
typedef struct keynode keynode;

struct keynode {
	struct keynode *next;
	uint64_t key;
	key_store_node *key_store;
}__rte_cache_aligned;
		
struct dictionary {
	struct keynode **table;
	int length, count;
	double growth_treshold;
	double growth_factor;
	key_store_node *value;
}__rte_cache_aligned;

/* See hashdict_README.md */
/* the code in this file is a modified version of the implementation by
 * https://github.com/exebook/hashdict.c
 * However, it is adapted to use uint64_t as a key, and correspondigly uses
 * the splitmix64 hash-function instead
 */
struct dictionary* dic_new(int initial_size);
void dic_delete(struct dictionary* dic);
int dic_add(struct dictionary* dic, uint64_t key, key_store_node *value);
int dic_find(struct dictionary* dic, uint64_t key);
int dic_remove(struct dictionary* dic, uint64_t key);
#endif
