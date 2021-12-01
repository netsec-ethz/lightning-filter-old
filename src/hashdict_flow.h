/*
 * Based on the project exebook/hashdict.c
 * See https://github.com/exebook/hashdict.c
 */

#ifndef _HASH_DICTC_FLOW_H_
#define _HASH_DICTC_FLOW_H_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <rte_atomic.h>
#include <rte_memory.h>

typedef struct dictionary_flow dictionary_flow;
typedef struct keynode_flow keynode_flow;
typedef struct dos_counter dos_counter;
typedef struct dictionary_flow_key dictionary_flow_key;

struct dictionary_flow_key {
	char data[10];
};

/* dos counter struct */
struct dos_counter {
	int64_t secX_counter;
	int64_t sc_counter;
	int64_t refill_rate;
	rte_atomic64_t *reserve;
};

struct keynode_flow {
	struct keynode_flow *next;
	dictionary_flow_key *key;
	dos_counter *counters;
} __rte_cache_aligned;

struct dictionary_flow {
	struct keynode_flow **table;
	int length, count;
	double growth_treshold;
	double growth_factor;
	dos_counter *value;
} __rte_cache_aligned;

struct dictionary_flow *dic_new_flow(int initial_size);
void dic_delete_flow(struct dictionary_flow *dic);
int dic_add_flow(struct dictionary_flow *dic, dictionary_flow_key *key, dos_counter *value);
int dic_find_flow(struct dictionary_flow *dic, dictionary_flow_key *key);
int dic_remove_flow(struct dictionary_flow *dic, dictionary_flow_key *key);
#endif
