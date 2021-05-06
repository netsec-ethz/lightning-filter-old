/*
 * Based on the project exebook/hashdict.c
 * See https://github.com/exebook/hashdict.c
 */

#include <inttypes.h>

#include "hashdict_flow.h"

#define hash_func_flow splitmix_flow

uint64_t splitmix_flow(uint64_t x);
struct keynode_flow *keynode_new_flow(uint64_t key, dos_counter *value);
void keynode_delete_flow(struct keynode_flow *node);
void keynode_remove_flow(struct keynode_flow *node);
void dic_reinsert_when_resizing_flow(struct dictionary_flow *dic, struct keynode_flow *k2);
void dic_resize_flow(struct dictionary_flow *dic, int newsize);

uint64_t splitmix_flow(uint64_t x) {
	x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x;
}

struct keynode_flow *keynode_new_flow(uint64_t key, dos_counter *value) {
	struct keynode_flow *node = malloc(sizeof *node);
	node->next = NULL;
	node->key = key;
	node->counters = value;
	return node;
}

void keynode_remove_flow(struct keynode_flow *node) {
	free(node);
}

void keynode_delete_flow(struct keynode_flow *node) {
	if (node->next)
		keynode_delete_flow(node->next);
	free(node);
}

struct dictionary_flow *dic_new_flow(int initial_size) {
	struct dictionary_flow *dic = malloc(sizeof *dic);
	if (initial_size == 0)
		initial_size = 1024;
	dic->length = initial_size;
	dic->count = 0;
	dic->value = NULL;
	dic->table = calloc(sizeof *dic->table, dic->length);
	dic->growth_treshold = 2.0;
	dic->growth_factor = 2;
	return dic;
}

void dic_delete_flow(struct dictionary_flow *dic) {
	for (int i = 0; i < dic->length; i++) {
		if (dic->table[i])
			keynode_delete_flow(dic->table[i]);
	}
	free(dic->table);
	dic->table = 0;
	free(dic);
}

void dic_reinsert_when_resizing_flow(struct dictionary_flow *dic, struct keynode_flow *k2) {
	int n = hash_func_flow(k2->key) % dic->length;
	if (dic->table[n] == 0) {
		dic->table[n] = k2;
		dic->value = dic->table[n]->counters;
		return;
	}
	struct keynode_flow *k = dic->table[n];
	k2->next = k;
	dic->table[n] = k2;
	dic->value = k2->counters;
}

void dic_resize_flow(struct dictionary_flow *dic, int newsize) {
	int o = dic->count;
	struct keynode_flow **old = dic->table;
	dic->length = newsize;
	dic->table = calloc(sizeof *dic->table, dic->length);
	for (int i = 0; i < o; i++) {
		struct keynode_flow *k = old[i];
		while (k) {
			struct keynode_flow *next = k->next;
			k->next = 0;
			dic_reinsert_when_resizing_flow(dic, k);
			k = next;
		}
	}
	free(old);
}

int dic_add_flow(struct dictionary_flow *dic, uint64_t key, dos_counter *value) {
	int n = hash_func_flow(key) % dic->length;
	double f = (double)dic->count / (double)dic->length;
	if (f > dic->growth_treshold) {
		dic_resize_flow(dic, dic->length * dic->growth_factor);
		return dic_add_flow(dic, key, value);
	}
	if (dic->table[n] == NULL) {
		dic->table[n] = keynode_new_flow(key, value);
		dic->value = dic->table[n]->counters;
		dic->count++;
		return 0;
	}
	struct keynode_flow *k = dic->table[n];
	while (k) {
		if ((k->key == key)) {
			dic->value = k->counters;
			return 1;
		}
		k = k->next;
	}
	dic->count++;
	struct keynode_flow *k2 = keynode_new_flow(key, value);
	k2->next = dic->table[n];
	dic->table[n] = k2;
	dic->value = k2->counters;
	return 0;
}

int dic_find_flow(struct dictionary_flow *dic, uint64_t key) {
	int n = hash_func_flow(key) % dic->length;
	__builtin_prefetch(dic->table[n]);
	struct keynode_flow *k = dic->table[n];
	if (!k)
		return 0;
	while (k) {
		if (k->key == key) {
			dic->value = k->counters;
			return 1;
		}
		k = k->next;
	}
	return 0;
}

int dic_remove_flow(struct dictionary_flow *dic, uint64_t key) {
	int n = hash_func_flow(key) % dic->length;
	__builtin_prefetch(dic->table[n]);
	struct keynode_flow *k = dic->table[n];
	struct keynode_flow *previous = NULL;
	if (!k)
		return 0;
	while (k) {
		if (k->key == key) {
			if (k->next) {
				if (!previous) {
					dic->table[n] = k->next;
				} else {
					previous->next = k->next;
				}
			} else {
				if (!previous) {
					dic->table[n] = NULL;
				} else {
					previous->next = NULL;
				}
			}
			keynode_remove_flow(k);
			dic->count--;

			return 1;
		}
		previous = k;
		k = k->next;
	}
	return 0;
}

#undef hash_func_flow
