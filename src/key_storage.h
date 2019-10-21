#ifndef _KEY_STORAGE_H_
#define _KEY_STORAGE_H_

#include <rte_memory.h>

#define SCION_NEXT_KEY_INDEX(x) ((x+1)%3) /* macro to get the next index on a size 3 ring-buffer */
#define SCION_PREV_KEY_INDEX(x) ((x+2)%3) /* macro to get the prvious index on a size 3 ring-buffer */
#define MIN(a,b) (a<b?a:b)

/* flags for debug and cycle analysis
 * it is a bit stupid that they are defined here
 * but scionfwd doesn't have a header file */
#define MEASURE_CYCLES 0
#define DEBUG_ENABLED 0

typedef struct delegation_secret delegation_secret;
typedef struct key_storage key_storage;
typedef struct key_store_node key_store_node;

uint32_t KEY_GRACE_PERIOD; /* key manager grace period */
uint32_t MINIMUM_KEY_VALIDITY; /* key manager minimum key validty period */
uint32_t KEY_CHECK_INTERVAL; /* interval in which to check for new keys  (1/10th of the MINIMUM_KEY_VALIDITY) */
double SUSPICIOUS_KEY_CHANGE_RATIO; /* threshold for validty period changes that flag a key as suspicious */

struct delegation_secret {
	uint32_t epoch_begin;
	uint32_t epoch_end;
	uint64_t src_ia;
	uint64_t dst_ia;
	unsigned char DRKey[16];
}__rte_cache_aligned;

struct key_storage {
	delegation_secret *(drkeys[3]);
}__rte_cache_aligned ;


struct key_store_node {
	uint8_t index;
	uint64_t nb_key_rollover;
	key_storage *key_store;
}__rte_cache_aligned;

#endif
