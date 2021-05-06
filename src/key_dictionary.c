/*
 * Based on the project exebook/hashdict.c
 * See https://github.com/exebook/hashdict.c
 */

#include <assert.h>
#include <stdbool.h>

#include "key_dictionary.h"

/* See https://github.com/svaarala/duktape/blob/master/misc/splitmix64.c */
static uint64_t hash(uint64_t x) {
	x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
	x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
	x = x ^ (x >> 31);
	return x;
}

struct key_dictionary *key_dictionary_new(size_t initial_size) {
	struct key_dictionary *d = malloc(sizeof *d);
	if (d == NULL) {
		return NULL;
	}
	d->size = initial_size == 0 ? 1024 : initial_size;
	d->table = calloc(sizeof *d->table, d->size);
	if (d->table == NULL) {
		free(d);
		return NULL;
	}
	d->count = 0;
	d->value = NULL;
	return d;
}

void key_dictionary_delete(struct key_dictionary *d) {
	for (size_t i = 0; i < d->size; i++) {
		struct key_dictionary_node *n = d->table[i];
		while (n != NULL) {
			struct key_dictionary_node *x = n;
			n = n->next;
			free(x);
		}
	}
	free(d->table);
	free(d);
}

void key_dictionary_find(struct key_dictionary *d, uint64_t key) {
	size_t h = hash(key) % d->size;
	__builtin_prefetch(d->table[h]);
	struct key_dictionary_node *n = d->table[h];
	while ((n != NULL) && (n->key != key)) {
		n = n->next;
	}
	d->value = n != NULL ? n->value : NULL;
}

static void resize(struct key_dictionary *d, size_t size) {
	struct key_dictionary_node **table = calloc(sizeof *table, size);
	if (table == NULL) {
		return;
	}
	for (size_t i = 0; i < d->size; i++) {
		struct key_dictionary_node *n = d->table[i];
		while (n != NULL) {
			struct key_dictionary_node *x = n;
			n = n->next;
			size_t h = hash(x->key) % size;
			x->next = table[h];
			table[h] = x;
		}
	}
	free(d->table);
	d->table = table;
	d->size = size;
}

int key_dictionary_add(struct key_dictionary *d, uint64_t key, struct key_store_node *value) {
	if (d->count == UINT32_MAX) {
		return -1;
	}
	size_t h = hash(key) % d->size;
	double f = (double)d->count / (double)d->size;
	if ((f > 2.0) && (d->size <= SIZE_MAX / 2)) {
		resize(d, d->size * 2);
		h = hash(key) % d->size;
	}
	struct key_dictionary_node *n = d->table[h];
	while ((n != NULL) && (n->key != key)) {
		n = n->next;
	}
	if (n != NULL) {
		d->value = n->value;
		return 1;
	}
	n = malloc(sizeof *n);
	if (n == NULL) {
		d->value = NULL;
		return -1;
	}
	n->key = key;
	n->value = value;
	n->next = d->table[h];
	d->table[h] = n;
	d->count++;
	d->value = n->value;
	return 0;
}
