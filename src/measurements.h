#ifndef _MEASUREMENTS_H_
#define _MEASUREMENTS_H_

struct measurements {
	uint64_t dup_start;
	uint64_t dup_sum;
	uint64_t dup_cnt;
	uint64_t header_start;
	uint64_t header_sum;
	uint64_t header_cnt;
	uint64_t secX_start;
	uint64_t secX_sum;
	uint64_t secX_cnt;
	uint64_t bloom_add_start;
	uint64_t bloom_add_sum;
	uint64_t bloom_add_cnt;
	uint64_t pktcopy_start;
	uint64_t pktcopy_sum;
	uint64_t pktcopy_cnt;
	uint64_t tx_enqueue_start;
	uint64_t tx_enqueue_sum;
	uint64_t tx_enqueue_cnt;
	uint64_t dropped;
	uint64_t forwarded;
	uint64_t bloom_hits;
	uint64_t bloom_misses;
	uint64_t invalid_secX;
	uint64_t tx_drain_start;
	uint64_t tx_drain_sum;
	uint64_t tx_drain_cnt;
	uint64_t rx_drain_start;
	uint64_t rx_drain_sum;
	uint64_t rx_drain_cnt;

	uint64_t bloom_free_start;
	uint64_t bloom_free_sum;
	uint64_t bloom_free_cnt;

	uint64_t rate_limit_start;
	uint64_t rate_limit_sum;
	uint64_t rate_limit_cnt;

	uint64_t secX_zero_start;
	uint64_t secX_zero_sum;
	uint64_t secX_zero_cnt;
	uint64_t secX_deriv_start;
	uint64_t secX_deriv_sum;
	uint64_t secX_deriv_cnt;
	uint64_t secX_cmac_start;
	uint64_t secX_cmac_sum;
	uint64_t secX_cmac_cnt;
};

#endif
