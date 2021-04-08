#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>

#include "lib/go/go_key_manager.h"
#include "key_manager.h"

uint8_t key_type = 0;
uint64_t dstIA = 0; /* TODO: should be changed to AS id where the LightningFilter is deployed */
const char* protocol = "scion_filter";

/* prototypes */
int is_in_epoch(uint32_t val_time, delegation_secret *key);
int can_be_fetched(uint32_t current_time, uint32_t epoch_end);
int get_DRKey(uint32_t val_time, uint64_t srcIA, struct delegation_secret* key);
int fetch_key(key_storage *key_store, uint8_t index, uint32_t val_time, uint64_t as );
int check_remaining_keys(key_storage *key_store, uint32_t current_time, uint8_t index_of_first_key, uint64_t as);


/*
 * checks whether the current system time lies in the validity period of a key
 * returns 1 on success
 * returns 0 on failure
 */
int is_in_epoch(uint32_t val_time, delegation_secret *key){
#if DEBUG_ENABLED
	printf("timestamp %u, epoch start %u, epoch end %u ->", val_time, key->epoch_begin, key->epoch_end);
#endif
	if(key->epoch_begin <= val_time && key->epoch_end >= val_time){
		return 1;
	}
	return 0;
}

/*
 * checks whether a key can be replaced by a new key
 * for that the current time must be larger than the last key epoch begin
 * plus the grace period
 * returns 1 on success
 * returns 0 on fialure
 */
int can_be_fetched(uint32_t current_time, uint32_t epoch_begin){
	if(current_time > epoch_begin + KEY_GRACE_PERIOD){
		return 1;
	}
	return 0;
}




/*
 * Fetches a new delegation secret for a specified AS and time from the certificate server
 * The call is made via a shared library that contains a Go wrapper in c.
 * The actual request to the certificate server is done in Go and then copied back
 * to the C memory.
 * returns  0 on success
 * returns -1 on failure
 */
int get_DRKey(uint32_t val_time, uint64_t srcIA, struct delegation_secret* key){

	// allocate memory on c heap, so that Go can copy data to that memory location
	char *ptr = malloc(40 * sizeof (char));
	int res;

	// call go Function trhough cgo wrapper. We need to pass the pointer to our allocated memory
	res = GetLvl1DRKey(key_type, val_time, srcIA, dstIA, ptr);
	if(res > 0){
		key = NULL;
		return -1;
	}

	// copy data to the fields of the key struct
	memcpy(&(key->epoch_begin), ptr, 4);
	memcpy(&(key->epoch_end), ptr+4, 4);
	memcpy(&(key->src_ia), ptr+8, 8);
	memcpy(&(key->dst_ia), ptr+16, 8);
	memcpy(key->DRKey, ptr+24, 16);

	return 0;
}


/* fetch a new key for an AS and a defined starting time
 * (The starting time is usually the endtime of the prevous key)
 * returns 0 on success
 * return -1 on failure
 */
int fetch_key(key_storage *key_store, uint8_t index, uint32_t val_time, uint64_t as){
	int ret;
	delegation_secret *key;
	delegation_secret *previous_key;
	uint32_t current_key_validity;
	uint32_t previous_key_validity;
	uint32_t previous_epoch_end;

	SUSPICIOUS_KEY_CHANGE_RATIO = 30;

	// allocate key struct and fetch the actual key
	key = malloc(sizeof *key);
	ret = get_DRKey(val_time, as, key);
	if(ret < 0){
		printf(" failed\n");
		return -1;
	}

	// On Success
	key_store->drkeys[index] = key;

	if(key_store->drkeys[SCION_PREV_KEY_INDEX(index)]){ // if there is a previous key (not true on start-up)

		// calculate current and previous key validity
		current_key_validity = key->epoch_end - key->epoch_begin;
		previous_key = key_store->drkeys[SCION_PREV_KEY_INDEX(index)];
		previous_key_validity = previous_key->epoch_end - previous_key->epoch_begin;
		previous_epoch_end = previous_key->epoch_end;

		// check if there is a suspicious change in key validity length
		if(previous_key_validity > SUSPICIOUS_KEY_CHANGE_RATIO * current_key_validity ||
				current_key_validity > SUSPICIOUS_KEY_CHANGE_RATIO * previous_key_validity){
			// SUSPICIOUS KEY
			//printf("FOUND SUSPICIOUS KEY\n");
			//printf("PREVIOUS VALIDITY: %u, NEW VALIDITY: %u , %f , %f\n", previous_key_validity, current_key_validity,
			//		SUSPICIOUS_KEY_CHANGE_RATIO * current_key_validity, SUSPICIOUS_KEY_CHANGE_RATIO * previous_key_validity);
			return -1;
		}
		// check whether there is a gap in the key validity period
		if (previous_epoch_end != key->epoch_begin){
			// ILLEGAL KEY
			//printf("FOUND POSSIBLY ILLEGAL KEY\n");
			return -1;
		}
	}

	// recalculate the minimum key validity
	MINIMUM_KEY_VALIDITY = MIN(MINIMUM_KEY_VALIDITY, (key->epoch_end - key->epoch_begin));

	return 0;
}

/*
 * if there is at least on valid key in the ring-buffer,
 * check whether any other key needs to be fetched
 * that means that potentially k+1 and k+2 are fetched
 * returns 0 on success
 * returns -1 on failure
 */
int check_remaining_keys(key_storage *key_store, uint32_t current_time, uint8_t index_of_first_key, uint64_t as){

	int ret;
	uint8_t index_to_check;
	uint32_t last_epoch_end;

	// epoch end of the current key
	// inex for the next key that is potentially replaced
	last_epoch_end = key_store->drkeys[index_of_first_key]->epoch_end;
	index_to_check = SCION_NEXT_KEY_INDEX(index_of_first_key);

	// if the key is missing -> immediately fetch new key
	if(key_store->drkeys[index_to_check] == false){
		ret = fetch_key(key_store, index_to_check, last_epoch_end, as);
		if(ret < 0){
			return -1;
		}
	// else only fetch the key is old (this should actuall never happen)
	}else if ((key_store->drkeys[index_to_check]->epoch_begin >= last_epoch_end) == false){
		ret = fetch_key(key_store, index_to_check, last_epoch_end, as);
		if(ret < 0){
			return -1;
		}
	}

	last_epoch_end = key_store->drkeys[index_to_check]->epoch_end;
	index_to_check = SCION_NEXT_KEY_INDEX(index_to_check);


	/* potentially fetch k + 2 */

	// if key is not present
	if(key_store->drkeys[index_to_check]  == false){
		// this is just to avoid immediately fetch k+2 on start-up
		if((key_store->drkeys[index_of_first_key]->epoch_begin + KEY_GRACE_PERIOD < current_time) == false){
			return 0;
		}
		ret = fetch_key(key_store, index_to_check, last_epoch_end, as);
		if(ret < 0){
			return -1;
		}
		return 0;
	// else check whether the key is old
	}else if ((key_store->drkeys[index_to_check]->epoch_begin >= last_epoch_end) == false){
		// check whether that old key can actually be replaced already (grace period)
		if (can_be_fetched(current_time, key_store->drkeys[index_of_first_key]->epoch_begin)){
			// fetch the new key
			ret = fetch_key(key_store, index_to_check, last_epoch_end, as);
			if(ret < 0){
				return -1;
			}
			return 0;
		}
		return 0;
	}
	return 0;
}

/*
 * this function checks for a given AS which keys need to be replaces
 */
int check_and_fetch(key_store_node *node, uint64_t as){

	int ret, fail_count;
	uint8_t index_to_check;
	uint32_t current_time;
	key_storage *key_store;

	fail_count = 0;
	current_time = time(NULL); //get curretn systime
	index_to_check= node->index;

	// find a valid key starting from the current key
	// if none of the three keys are valid then we need to fetch completely new keys
	// (should happend only at start-up)
	while(fail_count < 3){
		key_store = node->key_store;
		if(key_store->drkeys[index_to_check]){ // is there a key at that ring-buffer position?
			if(is_in_epoch(current_time, node->key_store->drkeys[index_to_check])){ // is it valid?
				ret = check_remaining_keys(key_store, current_time, index_to_check, as); // yes -> fetch all other keys
				if(ret < 0){
					return -1;
				}
				return 0;
			}
		}
		fail_count++;
		index_to_check = SCION_NEXT_KEY_INDEX(index_to_check);
		node->index = index_to_check;
		node->nb_key_rollover++;
	}

	//apparently we have no keys stored for this AS fetch any key first now
	ret = fetch_key(key_store, index_to_check, current_time, as);
	if(ret < 0){
		return -1;
	}

	// fetch the remaining keys
	check_remaining_keys(key_store, current_time, index_to_check, as);

	return 0;
}

