#include <inttypes.h>

#include "hashdict.h"

#define hash_func splitmix

/* internal prototypes */
uint64_t splitmix(uint64_t x);
struct keynode *keynode_new(uint64_t key, key_store_node *value);
void keynode_delete(struct keynode *node);
void keynode_remove(struct keynode *node);
void dic_reinsert_when_resizing(struct dictionary* dic, struct keynode *k2);
void dic_resize(struct dictionary* dic, int newsize);


/* https://github.com/svaarala/duktape/blob/master/misc/splitmix64.c */
uint64_t splitmix(uint64_t x) {
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    x = x ^ (x >> 31);
    return x;
}


struct keynode *keynode_new(uint64_t key, key_store_node *value) {
	struct keynode *node = malloc(sizeof *node);
	node->next = NULL;
	node->key = key;
	node->key_store = value;
	return node;
}

void keynode_remove(struct keynode *node) {
	free(node);
}


void keynode_delete(struct keynode *node) {
	if (node->next) keynode_delete(node->next);
	free(node);
}


struct dictionary* dic_new(int initial_size) {
	struct dictionary *dic = malloc(sizeof *dic);
	if (initial_size == 0) initial_size = 1024;
	dic->length = initial_size;
	dic->count = 0;
	dic->value = NULL;
	dic->table = calloc(sizeof *dic->table, dic->length);
	dic->growth_treshold = 2.0;
	dic->growth_factor = 2;
	return dic;
}


void dic_delete(struct dictionary* dic) {
	for (int i = 0; i < dic->length; i++) {
		if (dic->table[i])
			keynode_delete(dic->table[i]);
	}
	free(dic->table);
	dic->table = 0;
	free(dic);
}


void dic_reinsert_when_resizing(struct dictionary* dic, struct keynode *k2) {
	int n = hash_func(k2->key) % dic->length;
	if (dic->table[n] == 0) {
		dic->table[n] = k2;
		dic->value = dic->table[n]->key_store;
		return;
	}
	struct keynode *k = dic->table[n];
	k2->next = k;
	dic->table[n] = k2;
	dic->value = k2->key_store;
}


void dic_resize(struct dictionary* dic, int newsize) {
	int o = dic->count;
	struct keynode **old = dic->table;
	dic->length = newsize;
	dic->table = calloc(sizeof *dic->table, dic->length);
	for (int i = 0; i < o; i++) {
		struct keynode *k = old[i];
		while (k) {
			struct keynode *next = k->next;
			k->next = 0;
			dic_reinsert_when_resizing(dic, k);
			k = next;
		}
	}
	free(old);
}


int dic_add(struct dictionary* dic, uint64_t key, key_store_node *value) {
	int n = hash_func(key) % dic->length;
	double f = (double)dic->count / (double)dic->length;
	if (f > dic->growth_treshold) {
		dic_resize(dic, dic->length * dic->growth_factor);
		return dic_add(dic, key, value);
	}
	if (dic->table[n] == NULL) {
		dic->table[n] = keynode_new(key, value);
		dic->value = dic->table[n]->key_store;
		dic->count++;
		return 0;
	}
	struct keynode *k = dic->table[n];
	while (k) {
		if ((k->key == key)) {
			dic->value = k->key_store;
			return 1;
		}
		k = k->next;
	}
	dic->count++;
	struct keynode *k2 = keynode_new(key, value);
	k2->next = dic->table[n];
	dic->table[n] = k2;
	dic->value = k2->key_store;
	return 0;
}


int dic_find(struct dictionary* dic, uint64_t key) {
	int n = hash_func(key) % dic->length;
	__builtin_prefetch(dic->table[n]);
	struct keynode *k = dic->table[n];
	if (!k) return 0;
	while (k) {
		if (k->key == key) {
			dic->value = k->key_store;
			return 1;
		}
		k = k->next;
	}
	return 0;
}


int dic_remove(struct dictionary* dic, uint64_t key) {
	int n = hash_func(key) % dic->length;
	__builtin_prefetch(dic->table[n]);
	struct keynode *k = dic->table[n];
	struct keynode *previous = NULL;
	if (!k) return 0;
	while (k) {
		if (k->key == key) {
			if(k->next){
				if(!previous){
					dic->table[n] = k->next;
				}else{
					previous->next = k->next;
				}
			}else{
				if(!previous){
					dic->table[n] = NULL;
				}else{
					previous->next = NULL;
				}
			}
			keynode_remove(k);
			dic->count--;

			return 1;
		}
		previous = k;
		k = k->next;
	}
	return 0;
}


#undef hash_func
