#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <inttypes.h>

#include "ds.h"
#include "murmur.h"
#include "libcuckoofilter/include/cuckoo_filter.h"

scionfwd_fast_table* cuckoo_table_init(uint32_t size) {
  // allocate table
  scionfwd_fast_table *table;
  table = calloc(1, sizeof *table);
  table->size = size;
  table->records = calloc(table->size, sizeof *table->records);

  // set two pseudorandom seeds
  srand(time(NULL));
  table->seed1 = rand();
  table->seed2 = rand();
  return table;
}

void scionfwd_fast_table_insert(scionfwd_fast_table *table, void* value) {
  uint32_t address = *((uint32_t *) value);

  uint32_t hv1 = murmur3_32((uint8_t *)&address, VAL_SIZE, table->seed1);
  uint32_t hv2; // compute later for efficiency
  
  record *entry1;
  entry1 = &table->records[hv1%(table->size)];
  record *entry2; // compute later for efficiency

  // entries are always added in this order, so since we'll do many more counter updates than
  // real inserts we do updates first to avoid unnecessary lookups for real inserts
  if (entry1->address == address) {
    entry1->number_packets++;
    return;
  } else {
    hv2 = murmur3_32((uint8_t *)&address, VAL_SIZE, table->seed2);
    entry2 = &table->records[hv2%(table->size)];
    if (entry2->address == address) {
      entry2->number_packets++;
      return;
    }
  }

  // if we reach here, both locations are either occupied with different keys or empty
  if (entry1->address == 0) {
    entry1->address = address;
    entry1->number_packets = 1;
    return;
  } else {
    if (entry2->address == 0) {
      entry2->address = address;
      entry2->number_packets = 1;
      return;
    }
  }

  // if we reach here, insert failed, both slots are occupied, so ignore.
  return;
}

void scionfwd_fast_table_reset(scionfwd_fast_table *table) {
  record * temp_records = table->records; 
  table->records = calloc(table->size, sizeof *table->records);
  free(temp_records);

  // set new pseudorandom seeds
  table->seed1 = rand();
  table->seed2 = rand();
}

void scionfwd_fast_table_free(scionfwd_fast_table *table) {
  free(table->records);
  free(table);
}

bool consolidate_tables(scionfwd_fast_table *fast_table, uint32_t fast_table_size, volatile cuckoo_filter_t *slow_table) {
  // loop through fast table
  uint32_t counter = 0;
  uint64_t packets = 0;
  for(int i = 0; i < fast_table_size; i++) {
    if(fast_table->records[i].address) {
      packets += (uint64_t)fast_table->records[i].number_packets;
      if(cuckoo_filter_contains(slow_table, &(fast_table->records[i].address), VAL_SIZE)) {
        cuckoo_filter_add_packets(slow_table, &(fast_table->records[i].number_packets),
          &(fast_table->records[i].address), VAL_SIZE);
      } else {

        cuckoo_filter_add(slow_table, &(fast_table->records[i].address), VAL_SIZE);

        cuckoo_filter_add_packets(slow_table, &(fast_table->records[i].number_packets),
          &(fast_table->records[i].address), VAL_SIZE);
      }
    }
  }
}



#define fast_table_size_evaluation_nb_sizes 10
#define nb_nb_AS 7
void fast_table_size_evaluation(void){
  const int nb_sizes = fast_table_size_evaluation_nb_sizes;
  const int nb_ASes[nb_nb_AS] = {60000, 80000, 100000, 120000, 140000, 160000, 180000};
 
  const int nb_runs = 100;
  int table_sizes[fast_table_size_evaluation_nb_sizes] = {20000, 40000, 60000, 80000, 100000, 120000, 140000, 160000, 180000, 200000};
  
  char buf[100];
  for (int as = 0; as < nb_nb_AS; as++) {
    snprintf(buf, sizeof(buf), "fast_table_size_evaluation_%dASes.csv", nb_ASes[as]);
    int nb_AS = nb_ASes[as];

    // csv structure: table_size,nb_AS,run_id,distinct_keys_in_table
    FILE *fp_csv = fopen(buf, "w+");
    printf("Evaluation.. generating %d  random AS addresses\n\n", nb_AS);
    fprintf(fp_csv, "table_size,nb_AS,run_id,distinct_keys_in_table\n");

    
    srand(time(NULL));
    char randomness[nb_AS * VAL_SIZE];
    for (int i = 0; i < nb_AS * VAL_SIZE; i++) {
      randomness[i] = (char)rand();
    }

    for (int i = 0; i < nb_sizes; i++) {
      int table_size = table_sizes[i];
      printf("Evaluating table size %d..\n", table_size);
      scionfwd_fast_table *fast_table = cuckoo_table_init(table_size);
      for (int r = 0; r < nb_runs; r++) {
        for (int k = 0; k < nb_AS; k++) {
          scionfwd_fast_table_insert(fast_table, &randomness[k*VAL_SIZE]);
        }

        int counter = 0;
        for (int l = 0; l < table_size; l++) {
          if (fast_table->records[l].address) {
            counter++;
          }
        }
        printf("Run %d, distinct keys in table: %d\n", r, counter);
        fprintf(fp_csv,"%d,%d,%d,%d\n", table_size, nb_AS,r,counter);
        scionfwd_fast_table_reset(fast_table);
      }
    }
    fclose(fp_csv);
  }
}

// note, nb_nb_AS defined at fast table size evaluation
void slow_table_size_evaluation(void) {
  const int nb_ASes[nb_nb_AS] = {60000, 80000, 100000, 120000, 140000, 160000, 180000};
  const int nb_runs = 100;
  int table_sizes[] = {80000, 100000, 120000, 140000, 160000, 180000, 200000, 220000, 240000, 260000, 280000, 300000, 320000, 340000};
  
  char buf[100];
  for (int as = 0; as < nb_nb_AS; as++) {
    snprintf(buf, sizeof(buf), "slow_table_size_evaluation_%dASes.csv", nb_ASes[as]);
    int nb_AS = nb_ASes[as];

    // csv structure: table_size,nb_AS,run_id,distinct_keys_in_table
    FILE *fp_csv = fopen(buf, "w+");
    printf("Evaluation.. generating %d  random AS addresses\n\n", nb_AS);
    fprintf(fp_csv, "table_size,nb_AS,run_id,rehashes,total_kicks,longest_kick_chain\n");

    volatile cuckoo_filter_t *slow_table;

    srand(time(NULL));
    char randomness[nb_AS * VAL_SIZE];
    for (int i = 0; i < nb_AS * VAL_SIZE; i++) {
      randomness[i] = (char)rand();
    }

    for (int i = as; i < as + 7; i++) {
      int table_size = table_sizes[i];
      printf("Evaluating table size %d..\n", table_size);

      // very high kick threshold so that if rehashing has to occur it is likely to be
      // necessary. this is only to evaluate the total kicks and maximum kick chain
      
      for (int r = 0; r < nb_runs; r++) {
        cuckoo_filter_new((volatile cuckoo_filter_t **)&slow_table, table_size, 1000);
        for (int k = 0; k < nb_AS; k++) {
          //printf("adding %"PRIu32"..\n", *((uint32_t *) &(randomness[k*VAL_SIZE])));
          cuckoo_filter_add(slow_table, &(randomness[k*VAL_SIZE]), VAL_SIZE);
        }

        uint32_t kicks, rehashes, longest_kick_chain;
        cuckoo_filter_get_stats(slow_table, &kicks, &rehashes, &longest_kick_chain);


        printf("Run %d, kicks: %"PRIu32", rehashes: %"PRIu32", longest kick chain: %"PRIu32"\n", r, kicks, rehashes, longest_kick_chain);
        fprintf(fp_csv,"%d,%d,%d,%"PRIu32",%"PRIu32",%"PRIu32"\n", table_size, nb_AS,r,rehashes,kicks,longest_kick_chain);
        

        cuckoo_filter_free(&slow_table);
      }
    }
    fclose(fp_csv);
  }
}
