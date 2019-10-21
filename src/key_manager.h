#ifndef _KEY_MANAGER_H_
#define _KEY_MANAGER_H_

#include <stdint.h>
#include "key_storage.h"

/* Prototypes */

/*
 * for a given AS and the key_store node of that AS
 * we check whether any keys can be replaced, depending on the current time
 * and the key validty periods
 * returns 0 on success
 * return -1 on failure
 */
int check_and_fetch(key_store_node* node, uint64_t as);

/*
 * checks whether the current system time lies in the validity period of a key
 * returns 1 on success
 * returns 0 on failure
 */
int is_in_epoch(uint32_t val_time, delegation_secret *key);

/*
 * Fetches a new delegation secret for a specified AS and time from the certificate server
 * The call is made via a shared library that contains a Go wrapper in c.
 * The actual request to the certificate server is done in Go and then copied back
 * to the C memory.
 * returns  0 on success
 * returns -1 on failure
 */
int get_DRKey(uint32_t val_time, uint64_t srcIA, struct delegation_secret* key);
#endif
