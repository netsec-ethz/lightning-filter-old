#ifndef _HASH_DICTC_FLOW_H_
#define _HASH_DICTC_FLOW_H_

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <rte_memory.h>
#include <rte_atomic.h>

typedef struct dictionary_flow dictionary_flow;
typedef struct keynode_flow keynode_flow;
typedef struct dos_counter dos_counter;

/* dos counter struct */
struct dos_counter {
	int64_t secX_counter;
	int64_t sc_counter;
	int64_t refill_rate;
	rte_atomic64_t * reserve;
};

struct keynode_flow {
	struct keynode_flow *next;
	uint64_t key;
	dos_counter *counters;
}__rte_cache_aligned;
		
struct dictionary_flow {
	struct keynode_flow **table;
	int length, count;
	double growth_treshold;
	double growth_factor;
	dos_counter  *value;
}__rte_cache_aligned;

/* See hashdict_README.md */

/* This is essentially the same code as in hashdict.h and hashdict.c
 * However, since they contain differnt nodes, it is split in two files
 * This causes a lot of boilerplate, and a better way would be to have a generic
 * value type I assume
 */

struct dictionary_flow* dic_new_flow(int initial_size);
void dic_delete_flow(struct dictionary_flow* dic);
int dic_add_flow(struct dictionary_flow* dic, uint64_t key, dos_counter *value);
int dic_find_flow(struct dictionary_flow* dic, uint64_t key);
int dic_remove_flow(struct dictionary_flow* dic, uint64_t key);
#endif
