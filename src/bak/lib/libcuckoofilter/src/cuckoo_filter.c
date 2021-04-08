#include <inttypes.h>
#include "cuckoo_filter.h"

/* evaluation parameters */
#define SLOW_TABLE_SIZE_EVALUATION 0
///////////////////////////


#define CUCKOO_NESTS_PER_BUCKET     4
#define FP_MAX UINT32_MAX
#define KEY_SIZE 4

static inline uint32_t murmur3_32 (volatile uint8_t*, size_t, uint32_t);
static inline uint32_t predict(uint32_t*, uint8_t);

typedef struct {
	uint32_t              key;
	uint32_t              number_packets;
} __attribute__((packed)) cuckoo_nest_t;

typedef struct {
	uint32_t key;
	uint32_t h1;
	uint32_t h2;
	uint32_t number_packets;
} __attribute__((packed)) cuckoo_item_t;

typedef struct {
	bool                  was_found;
	cuckoo_item_t         item;
} cuckoo_result_t;

struct cuckoo_filter_t {
#if SLOW_TABLE_SIZE_EVALUATION	
	uint32_t			           kick_counter; // for evaluation purposes
	uint32_t			           rehash_counter; // for evaluation purposes
	uint32_t                       current_kick_chain_length; // for evaluation purposes
	uint32_t                       longest_kick_chain; // for evaluation purposes
#endif
	uint32_t                       bucket_count;
	uint32_t                       nests_per_bucket;
	uint32_t                       max_kick_attempts;
	uint32_t                       seed1;
	uint32_t                       seed2;
	uint32_t                       padding;
	cuckoo_item_t                  victim;
	cuckoo_item_t                 *last_victim;
	volatile cuckoo_nest_t         bucket[1];
}; 

/* ------------------------------------------------------------------------- */

static inline uint64_t
next_power_of_two (uint64_t x) {
	--x;
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;
	x |= x >> 32;
	return ++x;
}

/* ------------------------------------------------------------------------- */

static inline CUCKOO_FILTER_RETURN
add_fingerprint_to_bucket (
	volatile cuckoo_filter_t      *filter,
	uint32_t                       k,
	uint32_t			           number_packets,
	uint32_t                       h
) {
	for (size_t ii = 0; ii < filter->nests_per_bucket; ++ii) {
		volatile cuckoo_nest_t *nest =
			&filter->bucket[(h * filter->nests_per_bucket) + ii];
		if (0 == nest->key) {
			nest->key = k;
			nest->number_packets = number_packets;
#if SLOW_TABLE_SIZE_EVALUATION			
			if (filter->current_kick_chain_length > filter->longest_kick_chain)
				filter->longest_kick_chain = filter->current_kick_chain_length;

			filter->current_kick_chain_length = 0;
#endif
			return CUCKOO_FILTER_OK;
		}
	}

	return CUCKOO_FILTER_FULL;

} /* add_fingerprint_to_bucket() */

/* ------------------------------------------------------------------------- */

// returns the number of packets in the cuckoo hash
uint64_t cuckoo_filter_total_packet_count (
	volatile cuckoo_filter_t 	  *filter
) {
	uint64_t nest_count = filter->bucket_count * CUCKOO_NESTS_PER_BUCKET;
	uint64_t count = 0;
	
	for (uint64_t i = 0; i < nest_count; ++i) {
		if(filter->bucket[i].key) {
			count += filter->bucket[i].number_packets;
		}
	}
	return count;
} /* cuckoo_filter_total_packet_count */

/* ------------------------------------------------------------------------- */

void print_elements (
	cuckoo_filter_t 	*filter
) {
	printf("--------------------------------------\n");
	printf("Printing Elements in Slow Cuckoo Hash.\n");
	uint64_t counter = 0;
	uint64_t packet_count = 0;
	uint64_t nest_count = filter->bucket_count * CUCKOO_NESTS_PER_BUCKET;
	for (uint64_t i = 0; i < nest_count; ++i) {
		if(filter->bucket[i].key && filter->bucket[i].number_packets) {
			printf("Fingerprint: %"PRIu32" #Packets: %"PRIu32"\n", 
				filter->bucket[i].key, filter->bucket[i].number_packets);
			counter++;
			packet_count += filter->bucket[i].number_packets;
		}
	}
	printf("Total keys with nonzero value in table: %"PRIu64"\n", counter);
	printf("Total packets in table: %"PRIu64"\n", packet_count);
	printf("--------------------------------------\n");
} /* print_elements() */


/* ------------------------------------------------------------------------- */

static inline CUCKOO_FILTER_RETURN
cuckoo_filter_move (
	volatile cuckoo_filter_t      *filter,
	cuckoo_item_t	              *item,
	int                            depth
) {

	if (CUCKOO_FILTER_OK == add_fingerprint_to_bucket(filter,
	item->key, item->number_packets, item->h1)) {
		return CUCKOO_FILTER_OK;
	}

	if (CUCKOO_FILTER_OK == add_fingerprint_to_bucket(filter,
		item->key, item->number_packets, item->h2)) {
		return CUCKOO_FILTER_OK;
	}

	if (filter->max_kick_attempts == depth) {
		printf("kicking failed.. rehashing\n");
		cuckoo_rehash(filter);
		cuckoo_filter_add(filter, &(item->key), 4);
		cuckoo_filter_add_packets(filter, &(item->number_packets), &(item->key), 4);
		return CUCKOO_FILTER_OK;
	}

	cuckoo_item_t kicked_item;
  
	uint32_t row = (0 == (rand() % 2) ? item->h1 : item->h2);
	uint32_t col = (rand() % filter->nests_per_bucket);
	
	// get copy of kicked item
	kicked_item.key = filter->bucket[((row) * filter->nests_per_bucket) + col].key;
	kicked_item.h1 = murmur3_32((uint8_t *) &(kicked_item.key), 4, filter->seed1) % filter->bucket_count;
	kicked_item.h2 = murmur3_32((uint8_t *) &(kicked_item.key), 4, filter->seed2) % filter->bucket_count;
	kicked_item.number_packets = filter->bucket[((row) * filter->nests_per_bucket) + col].number_packets;

	// replace the entry
	filter->bucket[((row) * filter->nests_per_bucket) + col].key = item->key;
	filter->bucket[((row) * filter->nests_per_bucket) + col].number_packets = item->number_packets;

#if SLOW_TABLE_SIZE_EVALUATION	
	filter->current_kick_chain_length++;
	filter->kick_counter++;
#endif
	return cuckoo_filter_move(filter, &kicked_item, (depth + 1));
} /* cuckoo_filter_move() */

/* ------------------------------------------------------------------------- */

CUCKOO_FILTER_RETURN
cuckoo_filter_new (
	volatile cuckoo_filter_t     **filter,
	size_t  		               max_key_count, // actually now the table size (not max key size)
	size_t          		       max_kick_attempts
) {
	cuckoo_filter_t *new_filter;

	uint64_t bucket_count = max_key_count / CUCKOO_NESTS_PER_BUCKET;

	size_t allocation_in_bytes = (sizeof(cuckoo_filter_t)
		+ (bucket_count * CUCKOO_NESTS_PER_BUCKET * sizeof(cuckoo_nest_t)));

	if (0 != posix_memalign((void **) &new_filter, sizeof(uint64_t),
		allocation_in_bytes)) {
		return CUCKOO_FILTER_ALLOCATION_FAILED;
	}

	memset(new_filter, 0, allocation_in_bytes);

	new_filter->last_victim = NULL;
	memset(&new_filter->victim, 0, sizeof(new_filter)->victim);
	new_filter->bucket_count = bucket_count;
	new_filter->nests_per_bucket = CUCKOO_NESTS_PER_BUCKET;
	new_filter->max_kick_attempts = max_kick_attempts;

	new_filter->seed1 = rand();
	new_filter->seed2 = rand();

#if SLOW_TABLE_SIZE_EVALUATION
	new_filter->current_kick_chain_length = 0;
	new_filter->longest_kick_chain = 0;
	new_filter->kick_counter = 0;
	new_filter->rehash_counter = 0;
#endif

	*filter = new_filter;
	
	return CUCKOO_FILTER_OK;

} /* cuckoo_filter_new() */

/* ------------------------------------------------------------------------- */

CUCKOO_FILTER_RETURN
cuckoo_filter_free (
	volatile cuckoo_filter_t     **filter
) {
	free((void*) *filter);
	*filter = NULL;

	return CUCKOO_FILTER_OK;
}

/* ------------------------------------------------------------------------- */

static inline CUCKOO_FILTER_RETURN
cuckoo_filter_lookup (
	volatile cuckoo_filter_t      *filter,
	volatile cuckoo_result_t      *result,
	volatile void                 *key,
	size_t                         key_length_in_bytes
) {
	uint32_t h1 = murmur3_32(key, 4, filter->seed1) % filter->bucket_count;
	uint32_t h2 = murmur3_32(key, 4, filter->seed2) % filter->bucket_count;
	
	result->was_found = false;
	result->item.key = 0;
	result->item.number_packets = 0;
	result->item.h1 = 0;
	result->item.h2 = 0;

	for (size_t ii = 0; ii < filter->nests_per_bucket; ++ii) {
		volatile cuckoo_nest_t *n1 =
					&filter->bucket[(h1 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n1->key) {
			result->was_found = true;
			result->item.number_packets = n1->number_packets;
			break;
		}

		volatile cuckoo_nest_t *n2 =
					&filter->bucket[(h2 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n2->key) {
			result->was_found = true;
			result->item.number_packets = n2->number_packets;
			break;
		}
	}

	result->item.key = *((uint32_t *)key);
	result->item.h1 = h1;
	result->item.h2 = h2;
	return ((true == result->was_found)
		? CUCKOO_FILTER_OK : CUCKOO_FILTER_NOT_FOUND);

} /* cuckoo_filter_lookup() */

/* ------------------------------------------------------------------------- */

// if it returns true, number_packets countains the number of packets for this entry
// otherwise it does not exist in the table
bool cuckoo_filter_get_number_packets (
	volatile cuckoo_filter_t      *filter,
	uint32_t      		          *number_packets,
	void                          *key,
	size_t                         key_length_in_bytes
) {
	uint32_t h1 = murmur3_32(key, 4, filter->seed1) % filter->bucket_count;
	uint32_t h2 = murmur3_32(key, 4, filter->seed2) % filter->bucket_count;
	
	for (size_t ii = 0; ii < filter->nests_per_bucket; ++ii) {
		volatile cuckoo_nest_t *n1 =
			&filter->bucket[(h1 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n1->key) {
			*number_packets = n1->number_packets;
			return true;
		}

		volatile cuckoo_nest_t *n2 =
					&filter->bucket[(h2 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n2->key) {
			*number_packets = n2->number_packets;
			return true;
		}
	}
	return false;
} /* cuckoo_filter_get_number_packets() */

/* ------------------------------------------------------------------------- */

bool cuckoo_filter_add_packets (
	volatile cuckoo_filter_t      *filter,
	volatile uint32_t      		  *number_packets,
	volatile void                 *key,
	size_t                         key_length_in_bytes
) {
	
	uint32_t h1 = murmur3_32(key, 4, filter->seed1) % filter->bucket_count;
	uint32_t h2 = murmur3_32(key, 4, filter->seed2) % filter->bucket_count;
	
	for (size_t ii = 0; ii < filter->nests_per_bucket; ++ii) {
		volatile cuckoo_nest_t *n1 =
			&filter->bucket[(h1 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n1->key) {
			n1->number_packets += *number_packets;
			return true;
		}

		volatile cuckoo_nest_t *n2 =
					&filter->bucket[(h2 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n2->key) {
			n2->number_packets += *number_packets;
			return true;
		}
	}
	return false;
} /* cuckoo_filter_add_packets() */

/* ------------------------------------------------------------------------- */

// if it returns true, number_packets_pointer points to the location of the 
// of the number of packets
volatile uint32_t* cuckoo_filter_get_location (
	volatile cuckoo_filter_t      *filter,
	volatile void                 *key,
	size_t                		   key_length_in_bytes
) {
	
	uint32_t h1 = murmur3_32((uint8_t *) key, 4, filter->seed1) % filter->bucket_count;
	uint32_t h2 = murmur3_32((uint8_t *) key, 4, filter->seed2) % filter->bucket_count;
	
	for (size_t ii = 0; ii < filter->nests_per_bucket; ++ii) {
		volatile cuckoo_nest_t *n1 =
			&filter->bucket[(h1 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n1->key) {
			return &(n1->number_packets);
		}

		volatile cuckoo_nest_t *n2 =
			&filter->bucket[(h2 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n2->key) {
			return &(n2->number_packets);
		}
	}
	return 0;
} /* cuckoo_filter_add_packets() */

/* ------------------------------------------------------------------------- */

bool cuckoo_filter_decrement (
	volatile cuckoo_filter_t      *filter,
	void                          *key,
	size_t                         key_length_in_bytes
) {
	uint32_t h1 = murmur3_32(key, 4, filter->seed1) % filter->bucket_count;
	uint32_t h2 = murmur3_32(key, 4, filter->seed2) % filter->bucket_count;

	for (size_t ii = 0; ii < filter->nests_per_bucket; ++ii) {
		volatile cuckoo_nest_t *n1 =
			&filter->bucket[(h1 * filter->nests_per_bucket) + ii];
		if (*((uint32_t*)key) == n1->key) {
			if (n1->number_packets == 0) {			
				return false;
			}
			n1->number_packets = n1->number_packets - 1;
			return true;
		}

		volatile cuckoo_nest_t *n2 =
			&filter->bucket[(h2 * filter->nests_per_bucket) + ii];

		if (*((uint32_t*)key) == n2->key) {
			if (n2->number_packets == 0) {
				return false;
			}
			n2->number_packets = n2->number_packets - 1;

			return true;
		}
	}
	uint32_t k = *((uint32_t *)key);
	return false;
} /* cuckoo_filter_decrement() */

/* ------------------------------------------------------------------------- */

CUCKOO_FILTER_RETURN
cuckoo_filter_add (
	volatile cuckoo_filter_t      *filter,
	volatile void                 *key,
	size_t                         key_length_in_bytes
) {
	cuckoo_result_t   result;
	cuckoo_filter_lookup(filter, &result, key, key_length_in_bytes);
	if (true == result.was_found) {
		return CUCKOO_FILTER_OK;
	}

	if (NULL != filter->last_victim) {
		return CUCKOO_FILTER_FULL;
	}
	
	return cuckoo_filter_move(filter, &(result.item), 0);

} /* cuckoo_filter_add() */

/* ------------------------------------------------------------------------- */

CUCKOO_FILTER_RETURN
cuckoo_filter_contains (
	volatile cuckoo_filter_t      *filter,
	void                          *key,
	size_t                         key_length_in_bytes
) {
	cuckoo_result_t   result;

	uint32_t h1 = murmur3_32(key, 4, filter->seed1) % filter->bucket_count;
	uint32_t h2 = murmur3_32(key, 4, filter->seed2) % filter->bucket_count;
	
	for (size_t ii = 0; ii < filter->nests_per_bucket; ++ii) {
		volatile cuckoo_nest_t *n1 =
			&filter->bucket[(h1 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n1->key) {
			return true;
		}

		volatile cuckoo_nest_t *n2 =
			&filter->bucket[(h2 * filter->nests_per_bucket) + ii];
		if (*((uint32_t *)key) == n2->key) {
			return true;
		}
	}

	return false;
} /* cuckoo_filter_contains() */

/* ------------------------------------------------------------------------- */

void cuckoo_filter_scaled_copy(
	volatile cuckoo_filter_t 		*filter,
	volatile cuckoo_filter_t 		*scaled_copy,
	double				             scale
) {
	scaled_copy->seed1 = filter->seed1;
	scaled_copy->seed2 = filter->seed2;
	scaled_copy->bucket_count = filter->bucket_count;
	uint64_t nest_count = filter->bucket_count * CUCKOO_NESTS_PER_BUCKET;
	
	for (uint64_t i = 0; i < nest_count; ++i) {
		if(filter->bucket[i].key && filter->bucket[i].number_packets) {
			scaled_copy->bucket[i].key = filter->bucket[i].key;
			scaled_copy->bucket[i].number_packets = ((double)filter->bucket[i].number_packets * scale);
		}
	}
} /* cuckoo_filter_scaled_copy() */


/* ------------------------------------------------------------------------- */

// copies a filter and zeroes all entries that would be below 1 with the given
// scale
void cuckoo_filter_copy_and_zero_small_ASes(
	cuckoo_filter_t 		*filter,
	cuckoo_filter_t 		*zeroed_copy,
	double				     scale
) {
	zeroed_copy->seed1 = filter->seed1;
	zeroed_copy->seed2 = filter->seed2;
	zeroed_copy->bucket_count = filter->bucket_count;
	uint64_t nest_count = filter->bucket_count * CUCKOO_NESTS_PER_BUCKET;
	
	for (uint64_t i = 0; i < nest_count; ++i) {
		if(filter->bucket[i].key && filter->bucket[i].number_packets) {
			zeroed_copy->bucket[i].key = filter->bucket[i].key;
			if((double)filter->bucket[i].number_packets * scale < 1) {
				zeroed_copy->bucket[i].number_packets = 0;
			} else {
				zeroed_copy->bucket[i].number_packets = filter->bucket[i].number_packets;
			}
		} else {
			zeroed_copy->bucket[i].key = 0;
			zeroed_copy->bucket[i].number_packets = 0;
		}
	}
	
} /*cuckoo_filter_copy_and_zero_small_ASes */


/* ------------------------------------------------------------------------- */

void cuckoo_filter_get_stats(
	volatile cuckoo_filter_t 		*filter,
	uint32_t				        *kicks,
	uint32_t				        *rehashes,
	uint32_t				        *longest_kick_chain
) {
#if SLOW_TABLE_SIZE_EVALUATION	
	*kicks = filter->kick_counter;
	*rehashes = filter->rehash_counter;
	*longest_kick_chain = filter->longest_kick_chain;
#else
	printf("Turn on SLOW_TABLE_SIZE_EVALUATION in lib/libcuckoofilter/src/cuckoo_filter.c"
		"in order to use cuckoo_filter_get_stats.");
#endif
} /*cuckoo_filter_get_stats */

/* ------------------------------------------------------------------------- */

void cuckoo_rehash(
	volatile cuckoo_filter_t 		*filter
) {
	volatile cuckoo_filter_t *copy;
	cuckoo_filter_new((volatile cuckoo_filter_t **) &copy, filter->bucket_count * filter->nests_per_bucket,
		filter->max_kick_attempts);
	uint64_t nest_count = filter->bucket_count * CUCKOO_NESTS_PER_BUCKET;
	for (uint64_t i = 0; i < nest_count; ++i) {
		if(filter->bucket[i].key) {
			cuckoo_filter_add(copy, &(filter->bucket[i].key), 4);
			cuckoo_filter_add_packets(copy, &(filter->bucket[i].number_packets),
				&(filter->bucket[i].key), 4);
		}
	}

#if SLOW_TABLE_SIZE_EVALUATION
	copy->current_kick_chain_length = filter->current_kick_chain_length;
	copy->longest_kick_chain = filter->longest_kick_chain;
	copy->kick_counter = filter->kick_counter;
	copy->rehash_counter++;
#endif

	cuckoo_filter_free(&filter);
	filter = copy;
} /* cuckoo_rehash */

/* ------------------------------------------------------------------------- */

void cuckoo_predict_slice(
	volatile cuckoo_filter_t        **prediction_data,
	uint32_t                          no_prediction_filters,
	volatile cuckoo_filter_t         *target_slice,
	uint64_t                          max_no_packets
) {
	volatile cuckoo_filter_t *first_slice;
	volatile cuckoo_filter_t *current_slice;
	cuckoo_result_t result;
	uint32_t *ys = malloc(KEY_SIZE * no_prediction_filters);
	uint8_t nb_ys;
	uint32_t prediction;
	uint64_t total_packets = cuckoo_filter_total_packet_count(prediction_data[0]);
	
	// loop over all prediction slices
	for (uint32_t i = 0; i < no_prediction_filters; i++) {
		
		first_slice = prediction_data[i];
		
		uint64_t nest_count = first_slice->bucket_count * CUCKOO_NESTS_PER_BUCKET;
		
		// loop over keys in this prediction slice
		for (uint32_t j = 0; j < nest_count; ++j) {
			if(first_slice->bucket[j].key && first_slice->bucket[j].number_packets) {
				cuckoo_filter_lookup(target_slice, &result, &(first_slice->bucket[j].key), KEY_SIZE);
				if(result.was_found) {
					// already predicted this key
					continue;
				}

				// number packets in this slice
				ys[0] = first_slice->bucket[j].number_packets;
				nb_ys = 1;
				// lookup keys in the following prediction slices and add them to total
				for(uint32_t k = i+1; k < no_prediction_filters; k++) {
					cuckoo_filter_lookup(prediction_data[k], &result, &(first_slice->bucket[j].key), KEY_SIZE);
					if(result.was_found) {
						ys[nb_ys] = result.item.number_packets;
						nb_ys++;
					}
				}
				
				// predict and add to target
				prediction = predict(ys, nb_ys);
				cuckoo_filter_add(target_slice, &(first_slice->bucket[j].key), 4);
				cuckoo_filter_add_packets(target_slice, &prediction, &(first_slice->bucket[j].key), 4);
			
			}
		}
	}
	
	total_packets = cuckoo_filter_total_packet_count(target_slice);
	
	// zero ASes that are too small
	uint64_t nest_count = target_slice->bucket_count * CUCKOO_NESTS_PER_BUCKET;
	double scale = (double) max_no_packets / (double)total_packets;		
	for (uint64_t i = 0; i < nest_count; ++i) {
		if(target_slice->bucket[i].key && target_slice->bucket[i].number_packets) {
			target_slice->bucket[i].number_packets = ((double)target_slice->bucket[i].number_packets * scale);
		}
	}
}

// murmur hash, source: https://en.wikipedia.org/wiki/MurmurHash
static inline uint32_t
murmur3_32(volatile uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  if (len > 3) {
    uint32_t* key_x4 = (uint32_t*) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h = (h * 5) + 0xe6546b64;
    } while (--i);
    key = (uint8_t*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
} /* murmurhash() */

static inline uint32_t predict(uint32_t *ys, uint8_t no_values) {
	// simple prediction function, that predicts the next value based on
	// the ys-array of length no_values. The prediction function used
	// is linear regresssion

	double y_avg = 0;
	double x_avg = 0;
	for (uint8_t i = 1; i <= no_values; ++i) {
		y_avg += ys[i-1];
		x_avg += i;
	}
	y_avg /= no_values;
	x_avg /= no_values;

	// calculate beta
	double beta = 0;
	double div = 0;

	for (uint8_t i = 1; i <= no_values; ++i) {
		beta += (i - x_avg) * (ys[i-1] - y_avg);
		div += (i - x_avg) * (i - x_avg);
	}
	beta /= div;
	
	// calculate alpha
	double alpha = y_avg - (beta * x_avg);
	
	return (uint32_t) (alpha + (beta * (no_values + 1)));
}