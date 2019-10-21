/*
 *  Copyright (c) 2012-2017, Jyri J. Virkki
 *  All rights reserved.
 *
 *  This file is under BSD license. See LICENSE file.
 */

/*
 * Refer to bloom.h for documentation on the public interfaces.
 */

#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bloom.h"
#include "murmurhash2.h"

#define MAKESTRING(n) STRING(n)
#define STRING(n) #n


inline static int test_bit_set_bit(unsigned char * buf,
                                   unsigned int x, int set_bit)
{
  unsigned int byte = x >> 3;
  unsigned char c = buf[byte];        // expensive memory access
  unsigned int mask = 1 << (x % 8);

  if (c & mask) {
    return 1;
  } else {
    if (set_bit) {
      buf[byte] = c | mask;
    }
    return 0;
  }
}


static int bloom_check_add(struct bloom * bloomlist, int bloom_size, int active_id,
                           const void * buffer, int len)
{
  // Do not check if we are sure that this is true
  //for ( int k = 0; k < bloom_size; k++ ) {
  //  if (bloomlist[k]->ready == 0) {
  //    printf("bloom at %p not initialized!\n", (void *)bloomlist[k]);
  //    return -1;
  //  }
  //}
  //if (active_bloom->ready == 0) {
  //  printf("bloom at %p not initialized!\n", (void *)active_bloom);
  //  return -1;
  //}

  int hits = 0;
  register unsigned int a = murmurhash2(buffer, len, 0x9747b28c);
  register unsigned int b = murmurhash2(buffer, len, a);
  register unsigned int x;
  register          int i;

  struct bloom * active_bloom = &bloomlist[active_id];
  // check and add to active hash
  for (i = 0; i < active_bloom->hashes; i++) {
    x = (a + i*b) % active_bloom->bits;
    if (test_bit_set_bit(active_bloom->bf, x, 1)) {
      hits++;
    }
  }

  if (hits == active_bloom->hashes) {
    return 1;                // 1 == element already in (or collision)
  }

  register int k;
  register struct bloom * cur_bloom;
  // For every remaining bloom filter check if packet was seen
  for ( k = 0; k < bloom_size; k++ ) {
    if ( k == active_id ) {
        continue;
    }

    hits = 0;
    cur_bloom = &bloomlist[k];
    for (i = 0; i < cur_bloom->hashes; i++) {
      x = (a + i*b) % cur_bloom->bits;
      if (test_bit_set_bit(cur_bloom->bf, x, 0)) {
        hits++;
      }
      else {
        break;
      }
    }

    if (hits == cur_bloom->hashes) {
      return 1;                // 1 == element already in (or collision)
    }
  }

  return 0;
}


int bloom_init(struct bloom * bloom, int entries, double error)
{
  bloom->ready = 0;

  if (entries < 1000 || error == 0) {
    return 1;
  }

  bloom->entries = entries;
  bloom->error = error;

  double num = log(bloom->error);
  double denom = 0.480453013918201; // ln(2)^2
  bloom->bpe = -(num / denom);

  double dentries = (double)entries;
  bloom->bits = (int)(dentries * bloom->bpe);

  if (bloom->bits % 8) {
    bloom->bytes = (bloom->bits / 8) + 1;
  } else {
    bloom->bytes = bloom->bits / 8;
  }

  bloom->hashes = (int)ceil(0.693147180559945 * bloom->bpe);  // ln(2)

  bloom->bf = (unsigned char *)calloc(bloom->bytes, sizeof(unsigned char));
  if (bloom->bf == NULL) {
    return 1;
  }

  bloom->ready = 1;
  return 0;
}


int bloom_check(struct bloom * bloom, int bloom_size, int active_id, const void * buffer, int len)
{
  return bloom_check_add(bloom, bloom_size, active_id, buffer, len);
}


int bloom_add(struct bloom * bloom, int bloom_size, int active_id, const void * buffer, int len)
{
  return bloom_check_add(bloom, bloom_size, active_id, buffer, len);
}


void bloom_print(struct bloom * bloom)
{
  printf("bloom at %p\n", (void *)bloom);
  printf(" ->entries = %d\n", bloom->entries);
  printf(" ->error = %f\n", bloom->error);
  printf(" ->bits = %d\n", bloom->bits);
  printf(" ->bits per elem = %f\n", bloom->bpe);
  printf(" ->bytes = %d\n", bloom->bytes);
  printf(" ->hash functions = %d\n", bloom->hashes);
}


void bloom_free(struct bloom * bloom)
{
  if (bloom->ready) {
    free(bloom->bf);
  }
  bloom->ready = 0;
}

