#include "libcuckoofilter/include/cuckoo_filter.h"

#define VAL_SIZE 4

#define COUNTER_OFFSET 16
// counter size in bytes
#define COUNTER_SIZE 4

#define FAST_TABLE_INIT_SIZE 10


typedef struct {
	uint32_t address; // we have to store it since we need to be able to recover it to sum into the 'slow' cuckoo hash table
	uint32_t number_packets;
} record;

typedef struct {
	record* records;
	uint32_t size;
	uint32_t seed1;
	uint32_t seed2;
} scionfwd_fast_table;

scionfwd_fast_table* cuckoo_table_init(uint32_t size);

void scionfwd_fast_table_insert(scionfwd_fast_table *table, void* value);

void scionfwd_fast_table_reset(scionfwd_fast_table *table);

bool consolidate_tables(scionfwd_fast_table *fast_table, uint32_t fast_table_size, volatile cuckoo_filter_t *slow_table);

void fast_table_size_evaluation(void);

void slow_table_size_evaluation(void);