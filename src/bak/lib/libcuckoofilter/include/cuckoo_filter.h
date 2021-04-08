#ifndef CUCKOO_FILTER_H
#define CUCKOO_FILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

typedef enum {
  CUCKOO_FILTER_OK = 0,
  CUCKOO_FILTER_NOT_FOUND,
  CUCKOO_FILTER_FULL,
  CUCKOO_FILTER_ALLOCATION_FAILED,
} CUCKOO_FILTER_RETURN;

typedef struct cuckoo_filter_t cuckoo_filter_t;

struct cuckoo_number_packets_t {
  uint32_t number_packets;
  bool was_found;
};

uint64_t cuckoo_filter_total_packet_count (
  volatile cuckoo_filter_t     *filter
);

CUCKOO_FILTER_RETURN
cuckoo_filter_new (
  volatile cuckoo_filter_t     **filter,
  size_t                         max_key_count,
  size_t                         max_kick_attempts
);

CUCKOO_FILTER_RETURN
cuckoo_filter_free (
  volatile cuckoo_filter_t     **filter
);

bool cuckoo_filter_decrement (
  volatile cuckoo_filter_t      *filter,
  void                          *key,
  size_t                         key_length_in_bytes
);

CUCKOO_FILTER_RETURN
cuckoo_filter_add (
  volatile cuckoo_filter_t      *filter,
  volatile void                 *key,
  size_t                         key_length_in_bytes
);

bool cuckoo_filter_get_number_packets (
  volatile cuckoo_filter_t      *filter,
  uint32_t                      *number_packets,
  void                          *key,
  size_t                        key_length_in_bytes
);

void print_elements(
  cuckoo_filter_t      *filter
);

bool cuckoo_filter_add_packets (
  volatile cuckoo_filter_t      *filter,
  volatile uint32_t             *number_packets,
  volatile void                 *key,
  size_t                         key_length_in_bytes
);

volatile uint32_t* cuckoo_filter_get_location (
  volatile cuckoo_filter_t      *filter,
  volatile void                          *key,
  size_t                         key_length_in_bytes
);

void cuckoo_filter_get_stats(
  volatile cuckoo_filter_t      *filter,
  uint32_t                      *kicks,
  uint32_t                      *rehashes,
  uint32_t                      *longest_kick_chain
);

void cuckoo_rehash(
  volatile cuckoo_filter_t      *filter
);

void cuckoo_filter_scaled_copy(
  volatile cuckoo_filter_t     *filter,
  volatile cuckoo_filter_t     *scaled_copy,
  double                        scale
);

CUCKOO_FILTER_RETURN
cuckoo_filter_contains (
  volatile cuckoo_filter_t      *filter,
  void                          *key,
  size_t                         key_length_in_bytes
);

void cuckoo_predict_slice (
  volatile cuckoo_filter_t     **prediction_data,
  uint32_t                       no_prediction_filters,
  volatile cuckoo_filter_t      *target_slice,
  uint64_t                       ax_no_packets
);

#endif /* CUCKOO_FILTER_H */
