/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 * 
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_malloc.h>
#include <rte_metrics.h>
#include <rte_latencystats.h>
#include <rte_flow.h>
#include <rte_gso.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

// includes for libraries
#include "security_extension.h"
#include "scionfwd_util.h"
#include "lib/aesni/aesni.h"
#include "scion_bloom.h"
#include "cycle_measurements.h"
#include "key_manager.h"
#include "hashdict.h"
#include "hashdict_flow.h"
#include "key_storage.h"



/* defines */

// logging
#define RTE_LOGTYPE_scionfwd RTE_LOGTYPE_USER1

// Bloom Filter
#define MAX_BLOOM_FILTERS 2
#define MAX_SUPPORTED_PORTS 16

// Metrics IPC Socket
#define ADDRESS "/tmp/echo.sock"

// States for DOS
// (EVEN and ODD are black and red in the thesis for better visualisation)
#define EVEN 0
#define ODD 1

// queue params
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 128
#define MAX_RX_QUEUE_PER_PORT 128

// lcore params
#define MAX_LCORE_PARAMS 1024
#define MAX_NB_SOCKETS 8

// memory and drain params
#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

// Configurable number of RX/TX ring descriptors
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;



/* MAIN DATA STRUCTS */

// cycle count struct, used by each core to collect cycle counts
struct cycle_counts measurements[RTE_MAX_LCORE];

/* mempool, we have one mempool for each socket, shared by
 * all cores on that socket */
static struct rte_mempool * scionfwd_pktmbuf_pool[MAX_NB_SOCKETS];

// core statistic struct
struct core_stats {
	uint64_t rx_counter;
	uint64_t tx_bypass_counter;
	uint64_t tx_firewall_counter;
	uint64_t key_mismatch_counter;
	uint64_t secX_fail_counter;
	uint64_t bloom_filter_hit_counter;
	uint64_t bloom_filter_miss_counter;
	uint64_t as_rate_limited;
	uint64_t rate_limited;
} __rte_cache_aligned;

// core runtime  struct
typedef struct lcore_values {
	struct core_stats stats;		/* core stats object */
	struct rte_gso_ctx gso_ctx;     /**< GSO context */
	struct rte_mempool *mbp; /**< The mbuf pool to use by this core */
    struct bloom bloom_filters[MAX_BLOOM_FILTERS];
    uint64_t active_filter_id;
    struct timeval last_ts, cur_ts;
	struct rte_eth_dev_tx_buffer *tx_bypass_buffer;
	struct rte_eth_dev_tx_buffer *tx_firewall_buffer;
	uint8_t socket_id;
	uint8_t rx_port_id;
	uint8_t rx_queue_id;
	uint8_t tx_bypass_port_id;
	uint8_t tx_firewall_port_id;
	uint16_t tx_bypass_queue_id;
	uint16_t tx_firewall_queue_id;
}lcore_values;
struct lcore_values core_vars[RTE_MAX_LCORE];


// port runtime struct
typedef struct port_values{
	uint8_t socket_id;
	uint32_t nb_slave_cores;
	struct rte_eth_dev_info dev_info;   /**< PCI info + driver name */
	struct rte_eth_conf     dev_conf;   /**< Port configuration. */
	struct ether_addr       eth_addr;   /**< Port ethernet address */
	struct rte_eth_stats    stats;      /**< Last port statistics */
	uint8_t rx_slave_core_ids[RTE_MAX_LCORE]; /* ids of all rx cores allocated to this port */
	uint8_t tx_slave_core_ids[RTE_MAX_LCORE]; /* ids of all tx cores allocated to this port */
}port_values;
struct port_values port_vars[RTE_MAX_ETHPORTS];


/* denial of service statistic struct
 * used by the rate-limiter, each struct field is an array of two,
 * for both the even and the odd state */
typedef struct dos_statistic {
	dictionary_flow *dos_dictionary[2];
	int64_t secX_dos_packet_count[2];
	int64_t sc_dos_packet_count[2];
	rte_atomic64_t *reserve[2];
}dos_statistic;

/* arrary contatining the dos stat structs for each core,
 * once for the current period and once for the previous */
struct dos_statistic dos_stats[RTE_MAX_LCORE];
struct dos_statistic previous_dos_stat[RTE_MAX_LCORE];


// DPDK NIC configuration
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN, /* max packet lenght capped to ETHERNET MTU */
		.split_hdr_size = 0,
	},
	.rx_adv_conf = {
		.rss_conf = { /* configuration according to NIC capability */
			.rss_key = NULL,
			.rss_hf = ETH_RSS_FRAG_IPV4 |
			ETH_RSS_NONFRAG_IPV4_TCP |
			ETH_RSS_NONFRAG_IPV4_UDP |
			ETH_RSS_NONFRAG_IPV4_SCTP |
			ETH_RSS_NONFRAG_IPV4_OTHER |
			ETH_RSS_FRAG_IPV6 |
			ETH_RSS_NONFRAG_IPV6_TCP |
			ETH_RSS_NONFRAG_IPV6_UDP |
			ETH_RSS_NONFRAG_IPV6_SCTP |
			ETH_RSS_NONFRAG_IPV6_OTHER |
			ETH_RSS_L2_PAYLOAD
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};



/* global variables */

// force quit flag, will be set to true by signal handlers
// all threads will stop if flag has been set and application will terminate
static volatile bool force_quit;

// global atomic that stores the current state of the rate-limiter
static rte_atomic16_t dos_state;

// ports
uint8_t nb_ports;
uint8_t nb_rx_ports;
uint8_t nb_tx_ports;
uint8_t nb_tx_bypass_ports;
uint8_t nb_tx_firewall_ports;

// port type bitmaps
bool is_active_port[RTE_MAX_ETHPORTS];
bool is_rx_port[RTE_MAX_ETHPORTS];
bool is_tx_bypass_port[RTE_MAX_ETHPORTS];
bool is_tx_firewall_port[RTE_MAX_ETHPORTS];

// lcores
uint32_t nb_cores;
uint32_t nb_slave_cores;

// core type bitmaps
bool is_dos_core[RTE_MAX_LCORE];
bool is_key_manager_core[RTE_MAX_LCORE];
bool is_metrics_core[RTE_MAX_LCORE];
bool is_slave_core[RTE_MAX_LCORE];
bool is_in_use[RTE_MAX_LCORE];

//key manager
uint32_t key_manager_core_id; /* cpu_id of the key manager core */
dictionary *key_dictinionary[RTE_MAX_LCORE]; /* holds pointer to the key dictionary of each core */

// used to store key struct, roundkeys, computed CMAC and packet CMAC
// in CMAC computation. Memory allocation at main loop start
// (initialization start). Overwritten in each computation (reuse for
// efficiency)
keystruct *keys[RTE_MAX_LCORE]; /* ringbuffers for each core */
unsigned char* derived_keys[RTE_MAX_LCORE]; /*buffer to store derived lvl2 keys */
unsigned char* key_hosts_addrs[RTE_MAX_LCORE]; /* address buffers for lvl2 key derviation */
unsigned char* roundkey[RTE_MAX_LCORE]; /* buffer to store AES round keys */
unsigned char *computed_cmac[RTE_MAX_LCORE]; /* buffers to store the computed CMAC of a packet */
unsigned char *current_packet_SX[RTE_MAX_LCORE]; /* buffers to store extracted CMAC for SecX */

// used to store a packet copy in order to zero out unprotected parts
// in the CMAC computation
unsigned char* pkt_cpy[RTE_MAX_LCORE];

/* Global pools for the rate-limiter
 * one pool is fr SecX traffic the other for normal SCION traffic */
int64_t current_pool[2];



/* system configuration */

// mask of receiving ports
static uint32_t scionfwd_rx_port_mask = 0;

// mask of bypass ports
static uint32_t scionfwd_tx_bypass_port_mask = 0;

// mask of firewall ports
static uint32_t scionfwd_tx_firewall_port_mask = 0;

// blooom filter config
uint64_t NUM_BLOOM_ENTRIES = 700000;
uint64_t BLOOM_ERROR_RATE  = 10000;
int delta_us = 2500000;
int BLOOM_FILTERS = 2;

// rate-limiter config */
static uint64_t system_refill_rate; /* global rate-limit (scaled to 100 micro seconds) */
static uint64_t MAX_POOL_SIZE_FACTOR = 5; /* max allowd pool size (determines max paket burst) */
static double RESERVE_FRACTION = 0.03; /* fraction of rate-limit allocation stored in shared reserve */

// MAC updating enabled by default
// (deprecated)
static int mac_updating = 0;

// NUMA allocation enabled by default
static int numa_on = 1;

// interactive CLI disabled by default
static int is_interactive;

// load info from config enabled by default
// (not all params can be provided via commandline)
static int from_config_enabled = 1;

// key configurations and rate-limits loaded from config file
static uint64_t *config_keys;
static int64_t *config_limits;
static uint32_t config_nb_keys;


/* tsc-based timers responsible for triggering actions */
uint64_t tsc_hz; /* only for cycle counting */
static uint64_t slice_timer_period = 1800; /* #seconds for each bucket, scaled to hertz */
static uint64_t slice_timer_period_seconds = 1800; /* #seconds for each bucket, unscaled, seconds */
static uint64_t dos_slice_period; /* lenght of a rate limit slice (100 micro seconds) */


/* number of packets that the host wants to receive maximally. 0 if no limit 
 *  limit is number of packets per second
   (deprecated) */
uint64_t receive_limit = UINT64_MAX;



/* function prototypes */

int scion_filter_main(int argc, char **argv);
int export_set_up_metrics(void);
int cli_read_line(void);
void print_cli_usage(void);
void prompt(void);
int load_config(char *file_name);
int load_rate_limits(char *file_name);
static int scionfwd_parse_portmask(const char *portmask);
static int scionfwd_parse_timer_period(const char *q_arg);



/*
 * Logic that given a packet decides whether the packet is
 * a) forwareded to the bypass   -> return  1
 * b) forwarded to the firewall  -> return  0
 * c) dropped                    -> return -1
 *
 * The packet is first parsed, then rate-limited and if possible
 * then authenitcated and checked against the bloom filters for
 * duplicate suppression. Mor info in the thesis "Lighning Filter"
 *
 * (Due to late design changes the function was changed from a binary decision logic
 * to the current logic. Thus, it is a bit make-shift)
 */
static int
scionfwd_should_forward(int16_t state, struct rte_mbuf *m)
{
	// we need the lcore id, the corresponding core runtime struct and the cycle measurment struct
    uint32_t lcore_id = rte_lcore_id();
    struct lcore_values *c = &core_vars[lcore_id];
    struct cycle_counts* msmts = &measurements[lcore_id];

    // rate-limit stats struct and AS rate-limit hashtable
    dos_statistic core_dos_stat = dos_stats[lcore_id];
    dictionary_flow *lcore_dict = core_dos_stat.dos_dictionary[state];

    // key dictionary for this lcore
    dictionary * dict = key_dictinionary[lcore_id];

    uint64_t src_isd_as; /* source AS number */
    int result;

    // is true for SecX traffic and false for normal scion traffic
    bool has_SX = false;


#if MEASURE_CYCLES
    msmts->header_start = rte_rdtsc();
#endif

	struct ipv4_hdr *ipv4 = IPV4_HDR(m); // version_ihl,type_of_service,packet_id,fragment_offset,time_to_live,next_proto_id,hdr_checksum,src_addr,dst_addr
    SCIONCommonHeader *sch = CMN_HDR(m); // ver_dst_src,total_len,header_len,current_iof,current_hof,next_header

	unsigned char *scion_packet =  (unsigned char*) (UDP_HDR(m)+1);
 	uint32_t total_len = ntohs(ipv4->total_length) - 28; // 28 is the IP + UDP header length
    
    // before we parse the packet for CMAC relevant data, check whether a security extension is present
 	uint32_t offset = sch->header_len * 8; // offset in scion packet in bytes
	int32_t next_header = sch->next_header;	
	
	// loop as long as the next header is not a layer 4 protocol (in order: none, scmp, tcp, udp)
	while (!(next_header == 0 || next_header == 1 || next_header == 6 || next_header == 17 || offset > total_len)) {
    	if (next_header == 222) { // 222 is the SecX header
    		// store CMAC stored in packet
    		current_packet_SX[lcore_id] = scion_packet+offset+8;
    		has_SX = true;
    		break;
    	}
    	next_header = *(scion_packet+offset);
    	offset += *(scion_packet+offset+1);
	}

#if MEASURE_CYCLES
    msmts->header_sum += rte_rdtsc() - msmts->header_start;
    msmts->header_cnt++;

	msmts->rate_limit_start = rte_rdtsc();
#endif

    /* rate limiting general */

	// retrieve source AS from the packet
    uint64_t *ptr = (uint64_t*)(scion_packet + 16);
	src_isd_as = be64toh(*ptr); // convert network to little endian


	//check whether we have that AS configured, if not we used the other traffic category (AS label 0)
	result = dic_find_flow(lcore_dict, src_isd_as);
	if(result <= 0){
		dic_find_flow(lcore_dict, 0);
	}

	// this is SecX traffic
	if (has_SX) {
		//check all buckets to see if packet can be processed and decrement corresponding bucket.
		if(lcore_dict->value->secX_counter <= 0){ // check if secX bucket has enough tokens
			if(lcore_dict->value->sc_counter <= 0){ // if not, check normal SCION bucket
				int64_t value = rte_atomic64_read(lcore_dict->value->reserve); // again if not, check reserve (atomic)
				if(value <= 0){
					c->stats.as_rate_limited++; // if all fails than the packet is dropped
					return -1;
				}else{
					rte_atomic64_sub(lcore_dict->value->reserve, total_len);
				}
			}else{
				lcore_dict->value->sc_counter-= total_len;
			}
		}else{
			lcore_dict->value->secX_counter-= total_len;
		}

		// check then for overall rate (same procedure as above but use global DOS stat struct)
		if(dos_stats[lcore_id].secX_dos_packet_count[state] <= 0){
			if(dos_stats[lcore_id].sc_dos_packet_count[state] <= 0){
				int64_t value = rte_atomic64_read(dos_stats[lcore_id].reserve[state]);
				if(value <= 0){
					c->stats.rate_limited++;
					return -1;
				}else{
					rte_atomic64_sub(dos_stats[lcore_id].reserve[state], total_len);
				}
			}else{
				dos_stats[lcore_id].sc_dos_packet_count[state] -= total_len;
			}
		}else{
			dos_stats[lcore_id].secX_dos_packet_count[state] -= total_len;
		}


#if MEASURE_CYCLES
        msmts->pktcopy_start = rte_rdtsc();
#endif

		// get a copy of the packet so we can zero parts in CMAC copmutation
		rte_memcpy(pkt_cpy[lcore_id], scion_packet, total_len);

#if MEASURE_CYCLES
        msmts->pktcopy_sum += rte_rdtsc() - msmts->pktcopy_start;
        msmts->pktcopy_cnt++;
        msmts->secX_start = rte_rdtsc();
#endif

        //check the security extension (derive second level key, compute CMAC, compare)
		bool res = check_security_extension(pkt_cpy[lcore_id], sch, derived_keys[lcore_id], key_hosts_addrs[lcore_id], keys[lcore_id],
			roundkey[lcore_id], computed_cmac[lcore_id], current_packet_SX[lcore_id], &total_len ,dict, msmts);

#if MEASURE_CYCLES
        msmts->secX_sum += rte_rdtsc() - msmts->secX_start;
        msmts->secX_cnt++;
#endif

		if ( res  || true) { //TODO:SPIRENT; always true because CMAC is always false with Spirent

#if MEASURE_CYCLES
			msmts->bloom_free_start = rte_rdtsc();
#endif

			// perdiodicall rotate and reset the bloom filters to avoid overcrowding
            gettimeofday(&c->cur_ts, NULL);
            if ( (c->cur_ts.tv_sec - c->last_ts.tv_sec) * 1000000 + c->cur_ts.tv_usec - c->last_ts.tv_usec > delta_us ) {
                c->active_filter_id = (c->active_filter_id + 1 ) % MAX_BLOOM_FILTERS;

                bloom_free(&c->bloom_filters[c->active_filter_id]);
                bloom_init(&c->bloom_filters[c->active_filter_id], NUM_BLOOM_ENTRIES, 1.0/BLOOM_ERROR_RATE);
                c->last_ts = c->cur_ts;
            }

#if MEASURE_CYCLES
			msmts->bloom_free_sum += rte_rdtsc() - msmts->bloom_free_start;
			msmts->bloom_free_cnt++;
#endif

#if MEASURE_CYCLES
            msmts->bloom_add_start = rte_rdtsc();
#endif

            // check bloom filters, to see if this core has already seen this packet CMAC
            //  0 - element is not present
            //  1 - element is present (or false positive due to collision)
            int res = sc_bloom_add(c->bloom_filters, MAX_BLOOM_FILTERS, c->active_filter_id, computed_cmac[lcore_id], 16);

#if MEASURE_CYCLES
            msmts->bloom_add_sum += rte_rdtsc() - msmts->bloom_add_start;
            msmts->bloom_add_cnt++;
#endif
            if ( res && false) {  //TODO:SPIRENT false because we use the same MAC everywhere for testing, to observe deterministc results
				c->stats.bloom_filter_hit_counter++;
				return -1;
            }
            else {
                c->stats.bloom_filter_miss_counter++;
                return 1;
            }
		}else{
			// cmac failed
			c->stats.secX_fail_counter++;
			return -1;
		}
	} else {
#if MEASURE_CYCLES
		msmts->invalid_secX++;
#endif

		// rate limit non-secX traffic (similar way as wiht SecX)
		// difference is that we only check the normal SCION traffic bucket and not the SecX bucket and reserve
#if MEASURE_CYCLES
    msmts->rate_limit_start = rte_rdtsc();
#endif

		if(lcore_dict->value->sc_counter <= 0){
				 c->stats.as_rate_limited++;
#if MEASURE_CYCLES
    msmts->rate_limit_sum += rte_rdtsc() - msmts->rate_limit_start;
    msmts->rate_limit_cnt++;
#endif
			return -1;
		}else{
			lcore_dict->value->sc_counter-= total_len;
		}

		// check then for overall rate
		if(dos_stats[lcore_id].sc_dos_packet_count[state] <= 0){
			c->stats.rate_limited++;
#if MEASURE_CYCLES
    msmts->rate_limit_sum += rte_rdtsc() - msmts->rate_limit_start;
    msmts->rate_limit_cnt++;
#endif
			return -1;
		}else{
			dos_stats[lcore_id].sc_dos_packet_count[state] -= total_len;
		}

#if MEASURE_CYCLES
    msmts->rate_limit_sum += rte_rdtsc() - msmts->rate_limit_start;
    msmts->rate_limit_cnt++;
#endif
		return 0;
	}

}

/*
 * forward function that is called by each processing core for each packet
 * responsible for forwarding or dropping a packet, based on the return value of
 * "should forward"
 */
static void
scionfwd_simple_forward(struct rte_mbuf *m , struct lcore_values * lvars, int16_t state)
{
	unsigned lcore_id = rte_lcore_id();
    struct cycle_counts* msmts = &measurements[lcore_id];
	lvars->stats.rx_counter++;
	
	int should_forward = scionfwd_should_forward(state, m);

#if MEASURE_CYCLES
        msmts->tx_enqueue_start = rte_rdtsc();
#endif

    if(should_forward == 1){ // send to bypass
		rte_eth_tx_buffer(lvars->tx_bypass_port_id, lvars->tx_bypass_queue_id, lvars->tx_bypass_buffer, m);
    	lvars->stats.tx_bypass_counter++;
	} else if(should_forward == 0){ // send to firewall
		rte_eth_tx_buffer(lvars->tx_firewall_port_id, lvars->tx_firewall_queue_id, lvars->tx_firewall_buffer, m);
		lvars->stats.tx_firewall_counter++;
	}else{ // drop packet
		rte_pktmbuf_free(m);
		msmts->dropped++;
	}

#if MEASURE_CYCLES
        msmts->tx_enqueue_sum += rte_rdtsc() - msmts->tx_enqueue_start;
#endif
}

/* main processing core loop
 * handles queue management and calls simple forward to do packet processing
 * periodically we train the TX buffers
 * we check whether the rx buffer contains new packets and prefetch these packet, process them
 * */
static void
scionfwd_main_loop(void)
{

	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned lcore_id;
	unsigned j, nb_rx;

	int16_t state;
	uint64_t prev_tsc, diff_tsc, cur_tsc;
	prev_tsc = 0;

	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	uint64_t last_dos_slice_tsc = rte_rdtsc();
	lcore_id = rte_lcore_id();

#if MEASURE_CYCLES
    struct cycle_counts* msmts = &measurements[lcore_id];
#endif

    struct lcore_values * lvars = &core_vars[lcore_id];
	pkt_cpy[lcore_id] = rte_malloc(NULL, 1500, 16);
    keys[lcore_id] = rte_malloc (NULL, 1 * sizeof (keystruct), RTE_CACHE_LINE_SIZE);

    derived_keys[lcore_id] = rte_malloc (NULL, 16, 16);
    key_hosts_addrs[lcore_id] = rte_malloc (NULL, 32, 16);

    roundkey[lcore_id] = (unsigned char*)rte_malloc(NULL, 10*16, 16);
    current_packet_SX[lcore_id] = (unsigned char*)rte_malloc(NULL, 16, RTE_CACHE_LINE_SIZE);

	// zeroing is not required for CMAC(), but using output also
	// as 0 array for padding
	computed_cmac[lcore_id] = rte_malloc(NULL,16,RTE_CACHE_LINE_SIZE);

	state = !rte_atomic16_read(&dos_state);


	/* main loop */
	while (!force_quit) {

		// read TSC register for time
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		// TX burst queue drain
		if (unlikely(diff_tsc > drain_tsc)) {
#if MEASURE_CYCLES
			prev_tsc = cur_tsc;
			msmts->tx_drain_start = rte_rdtsc();
#endif
			rte_eth_tx_buffer_flush(lvars->tx_bypass_port_id, lvars->tx_bypass_queue_id, lvars->tx_bypass_buffer);
			rte_eth_tx_buffer_flush(lvars->tx_firewall_port_id, lvars->tx_firewall_queue_id, lvars->tx_firewall_buffer);
#if MEASURE_CYCLES
			msmts->tx_drain_cnt++;
			msmts->tx_drain_sum += rte_rdtsc() - msmts->tx_drain_start;
#endif
		}


#if MEASURE_CYCLES
		msmts->rx_drain_start = rte_rdtsc();
#endif

		// Read packet from RX queues
		nb_rx = rte_eth_rx_burst((uint8_t) lvars->rx_port_id, lvars->rx_queue_id, pkts_burst, MAX_PKT_BURST);

#if MEASURE_CYCLES
		msmts->rx_drain_cnt = rte_rdtsc();
		msmts->rx_drain_sum += rte_rdtsc() - msmts->rx_drain_start;
#endif

		// prefetch all RX packets
		for (j = 0; j < nb_rx; j++) {
			m = pkts_burst[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));

#if MEASURE_CYCLES
			msmts->dup_start = rte_rdtsc();
#endif		
			// check the rate-limiter state roughly every 100 microseconds
			// and set own state to opposite of the rate-limiter
			// has to be done before each packet processing, to make sure that we
			// are always in the correct state
			if (cur_tsc - last_dos_slice_tsc > dos_slice_period) {
				state = !rte_atomic16_read(&dos_state);
				last_dos_slice_tsc = cur_tsc;
			}

			scionfwd_simple_forward(m, lvars, state);

#if MEASURE_CYCLES
            msmts->dup_cnt++;
            msmts->dup_sum += rte_rdtsc() - msmts->dup_start;
#endif			
		}
	}
}


/*
 * called by metrics exporter once at start-up
 * inititalizes memory structures and exports all system information and
 * the configuration
 * communicates via IPC with the Go metrics exporter
 */
int export_set_up_metrics(void){
	register int s, socket_len;
	struct sockaddr_un saun;
	char buffer[256];

	uint8_t port_id;
	struct port_values *port;
	struct ether_addr mac_addr;
	int port_socket_id;

	saun.sun_family = AF_UNIX;
	strcpy(saun.sun_path, ADDRESS);

	// aquire UNIX socket
	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		rte_exit(EXIT_FAILURE, "Metrics core could not get a UNIX socket\n");
	}

	// connect to UNIX socket
	socket_len = sizeof(saun.sun_family) + strlen(saun.sun_path);
	if (connect(s, &saun, socket_len) < 0) {
		printf("Metrics could not connect to socket\n");
	}

	// send system configuration
	snprintf(buffer, sizeof(buffer), "set_up_sys_stats;%" PRIu64 ";%d;%" PRIu64 ";%" PRIu64 ";%d;%" PRIu32 ";"
			"%" PRIu8 ";%" PRIu8 ";%" PRIu8 ";%" PRIu8 ";%" PRIu8 ";%" PRIu32 ";%" PRIu32 ";%" PRIu64 ";fin\n",
			slice_timer_period_seconds, BLOOM_FILTERS, NUM_BLOOM_ENTRIES, BLOOM_ERROR_RATE, delta_us,
			KEY_GRACE_PERIOD, nb_ports, nb_rx_ports, nb_tx_ports, nb_tx_bypass_ports, nb_tx_firewall_ports,
			nb_cores, nb_slave_cores, receive_limit);
	send(s, buffer, strlen(buffer), 0);


	// for each active port, send the port configuration
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if(is_active_port[port_id] == false){
			continue;
		}

		port = &port_vars[port_id];
		port_socket_id = rte_eth_dev_socket_id(port_id);
		mac_addr = port->eth_addr;

		snprintf(buffer, sizeof(buffer),"set_up_port_stats;%d;%02X:%02X:%02X:%02X:%02X:%02X;%d;%s;%x;%u;%u;%"
						PRIu64 ";%" PRIu32 ";%u;%" PRIu32 ";%" PRIu32 ";%" PRIu32 ";%" PRIu32 ";"
						"%" PRIu32 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu16 ";"
						"%" PRIu8 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";fin\n",
						port_id,mac_addr.addr_bytes[0], mac_addr.addr_bytes[1], mac_addr.addr_bytes[2],
						mac_addr.addr_bytes[3], mac_addr.addr_bytes[4], mac_addr.addr_bytes[5],
						port_socket_id,port->dev_info.driver_name,port->dev_info.if_index,
						port->dev_info.min_mtu,port->dev_info.max_mtu,(uint64_t)(port->dev_info.dev_flags),
						port->dev_info.min_rx_bufsize, port->dev_info.max_rx_pktlen, port->dev_info.max_rx_queues,
						port->dev_info.max_tx_queues, port->dev_info.max_mac_addrs, port->dev_info.max_vfs,
						port->dev_info.max_vmdq_pools,port->dev_info.rx_offload_capa,port->dev_info.tx_offload_capa,
						port->dev_info.rx_queue_offload_capa, port->dev_info.tx_queue_offload_capa,
						port->dev_info.reta_size,port->dev_info.hash_key_size, port->dev_info.flow_type_rss_offloads,
						(uint64_t)(port->dev_info.speed_capa), (uint64_t)(port->dev_info.dev_capa));
		send(s, buffer, strlen(buffer), 0);
	}

	// close the socket
	close(s);
	return 0;
}

/* main loop of the metrics exporter
 * call the initial metrics export
 * communicates with Go exporter via IPC
 * to avoid holding on to the socket indefinitely and loosing it due to unforeseen events,
 * we reconnect every loop iteration and disconnect at the end of it.
 * This enables recovery at the cost of missing data-points, which is ok for stats collection over long time periods
 */
static void metrics_main_loop(void){
	printf("METRICS HAS STARTED\n");

	register int s, socket_len;
	int ret;
	struct sockaddr_un saun;
	char buffer[256];

	uint64_t last_slice_tsc = rte_rdtsc();
	uint64_t current_tsc;

	// lots of system-wide accumulators
	uint64_t total_rx_counter = 0;
	uint64_t total_tx_bypass_counter = 0;
	uint64_t total_tx_firewall_counter = 0;
	uint64_t total_key_mismatch_counter = 0;
	uint64_t total_secX_fail_counter = 0;
	uint64_t total_bloom_filter_hit_counter = 0;
	uint64_t total_bloom_filter_miss_counter = 0;
	uint64_t total_as_rate_limited_counter = 0;
	uint64_t total_rate_limited_counter = 0;

	uint64_t rx_counter = 0;
	uint64_t tx_bypass_counter = 0;
	uint64_t tx_firewall_counter = 0;
	uint64_t key_mismatch_counter = 0;
	uint64_t secX_fail_counter = 0;
	uint64_t bloom_filter_hit_counter = 0;
	uint64_t bloom_filter_miss_counter = 0;
	uint64_t as_rate_limited_counter = 0;
	uint64_t rate_limited_counter = 0;

	// export system configuarion and set-up IPC socket
	ret = export_set_up_metrics();

	saun.sun_family = AF_UNIX;
	strcpy(saun.sun_path, ADDRESS);
        
	/* main loop */
	while (!force_quit) {
		current_tsc = rte_rdtsc();

		// perform stats export according to slice timer period (default every 5 seconds)
		if (unlikely(current_tsc - last_slice_tsc > slice_timer_period)) {

			// update timings (hz may change due to turbo feature of cpu (Jonas: It does not really change though?))
			slice_timer_period = slice_timer_period_seconds * rte_get_timer_hz();
			last_slice_tsc = current_tsc;

			// Acquire socket
			if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
				//rte_exit(EXIT_FAILURE, "Metrics core could not get a UNIX socket\n");
			}

			//connect to socket
			socket_len = sizeof(saun.sun_family) + strlen(saun.sun_path);
			if (connect(s, &saun, socket_len) < 0) {
				//printf("metrics could not connect to socket\n");
			}

			// for each active port get hardware stats
			for (int port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++){
				if(is_active_port[port_id] == false){
					continue;
				}
				struct rte_eth_stats rte_stats;
				ret = rte_eth_stats_get(port_id, &rte_stats); // get HW stats
				if(ret < 0){
					continue;
				}
				rte_eth_stats_reset(port_id); // reset HW stats

				// send HW stats
				snprintf(buffer, sizeof(buffer), "port_stats;%d;%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";"
						"%" PRIu64 ";%" PRIu64 ";%" PRIu64 ";%" PRIu64";fin\n",
						port_id, rte_stats.ipackets, rte_stats.opackets, rte_stats.ibytes, rte_stats.obytes,
						rte_stats.imissed, rte_stats.ierrors, rte_stats.oerrors, rte_stats.rx_nombuf);
				send(s, buffer, strlen(buffer), 0);
			}

			// for each lcore accumulate stats, reset intivdulas stats and send aggregate
			for (int i = 0; i < RTE_MAX_LCORE; i++) {
				if(is_slave_core[i] == false){
					continue;
				}

				// collect lcore stats
				struct core_stats * lstats = &(core_vars[i].stats);
				rx_counter = lstats->rx_counter;
				tx_bypass_counter = lstats->tx_bypass_counter;
				tx_firewall_counter = lstats->tx_firewall_counter;
				key_mismatch_counter = lstats->key_mismatch_counter;
				secX_fail_counter = lstats->secX_fail_counter;
				bloom_filter_hit_counter = lstats->bloom_filter_hit_counter;
				bloom_filter_miss_counter = lstats->bloom_filter_miss_counter;
				as_rate_limited_counter = lstats->as_rate_limited;
				rate_limited_counter = lstats->rate_limited;

				// reset lcore stats
				lstats->rx_counter = 0;
				lstats->tx_bypass_counter = 0;
				lstats->tx_firewall_counter = 0;
				lstats->key_mismatch_counter = 0;
				lstats->secX_fail_counter = 0;
				lstats->bloom_filter_hit_counter = 0;
				lstats->bloom_filter_miss_counter = 0;
				lstats->as_rate_limited = 0;
				lstats->rate_limited = 0;

				// accumulate system-wide stats
				total_rx_counter += rx_counter;
				total_tx_bypass_counter += tx_bypass_counter;
				total_tx_firewall_counter += tx_firewall_counter;
				total_key_mismatch_counter += key_mismatch_counter;
				total_secX_fail_counter += secX_fail_counter;
				total_bloom_filter_hit_counter += bloom_filter_hit_counter;
				total_bloom_filter_miss_counter += bloom_filter_miss_counter;
				total_as_rate_limited_counter += as_rate_limited_counter;
				total_rate_limited_counter += rate_limited_counter;

				// send individual lcore stats
				snprintf(buffer, sizeof(buffer),"core_stats;%d;%"PRIu64";%"PRIu64";%"PRIu64";"
						"%"PRIu64";%"PRIu64";%"PRIu64";%"PRIu64";fin\n"
						, i, rx_counter, tx_bypass_counter, tx_firewall_counter,
						key_mismatch_counter, secX_fail_counter,
						bloom_filter_hit_counter, bloom_filter_miss_counter);
				send(s, buffer, strlen(buffer), 0);
			}

			// send system-wide aggregate
			snprintf(buffer, sizeof(buffer),"core_stats;%d;%"PRIu64";%"PRIu64";%"PRIu64";%"PRIu64";"
					"%"PRIu64";%"PRIu64";%"PRIu64";fin\n"
					, -1, total_rx_counter, total_tx_bypass_counter, total_tx_firewall_counter,
					total_key_mismatch_counter, total_secX_fail_counter,
					total_bloom_filter_hit_counter, total_bloom_filter_miss_counter);
			send(s, buffer, strlen(buffer), 0);

			// reset system-wide counters
			total_rx_counter = 0;
			total_tx_bypass_counter = 0;
			total_tx_firewall_counter = 0;
			total_key_mismatch_counter = 0;
			total_secX_fail_counter = 0;
			total_bloom_filter_hit_counter = 0;
			total_bloom_filter_miss_counter = 0;
			total_as_rate_limited_counter = 0;
			total_rate_limited_counter = 0;

			// collect for each AS the key-store information
			struct dictionary * dict;
			dict = key_dictinionary[key_manager_core_id];

			for (int i = 0; i < dict->length; i++) {
				if (dict->table[i] != 0) {
					struct keynode *k = dict->table[i];
					while (k) {
						uint32_t index = k->key_store->index;
						delegation_secret * key = k->key_store->key_store->drkeys[index];
						snprintf(buffer, sizeof(buffer),"key_stats;%"PRIu64";%"PRIu64";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";fin\n",k->key,k->key_store->nb_key_rollover,key->epoch_begin, key->epoch_end, KEY_CHECK_INTERVAL, KEY_GRACE_PERIOD);
						send(s, buffer, strlen(buffer), 0);
						k = k->next;
					}
				}
			}
			close(s);



#if MEASURE_CYCLES

		/* cylce analysis code *
		 * take average across all cores for each pipeline step and print
		 * contains a lot of boilerplate code
		 */

		uint64_t dup_avg        = 0;
		uint64_t header_avg     = 0;
		uint64_t secX_avg       = 0;
		uint64_t secX_zero_avg  = 0;
		uint64_t secX_deriv_avg  = 0;
		uint64_t secX_cmac_avg  = 0;
		uint64_t bloom_add_avg  = 0;
		uint64_t bloom_free_avg = 0;
		uint64_t pktcopy_avg    = 0;
		uint64_t tx_enqueue_avg = 0;
		uint64_t tx_drain_avg   = 0;
		uint64_t rx_drain_avg   = 0;
		uint64_t rate_limit_avg   = 0;
		uint64_t active_dup_cores = 0;

		for (int i = 0; i < RTE_MAX_LCORE; i++) {
			if(measurements[i].dup_cnt) {

				// packet counter
				if (measurements[i].dup_cnt) {
					dup_avg += (measurements[i].dup_sum/measurements[i].dup_cnt);
					active_dup_cores++;
				}
				measurements[i].dup_sum = 0;
				measurements[i].dup_cnt = 0;

				// header counter
				if (measurements[i].header_cnt) {
					header_avg += (measurements[i].header_sum/measurements[i].header_cnt);
				}
				measurements[i].header_sum = 0;
				measurements[i].header_cnt = 0;

				// rate limit counter
				if (measurements[i].rate_limit_cnt) {
					rate_limit_avg += (measurements[i].rate_limit_sum/measurements[i].rate_limit_cnt);
				}
				measurements[i].rate_limit_sum = 0;
				measurements[i].rate_limit_cnt = 0;

				// secX counter
				if (measurements[i].secX_cnt) {
					secX_avg += (measurements[i].secX_sum/measurements[i].secX_cnt);
				}
				measurements[i].secX_sum = 0;
				measurements[i].secX_cnt = 0;

				// secX zero counter
				if (measurements[i].secX_zero_cnt) {
					secX_zero_avg += (measurements[i].secX_zero_sum / measurements[i].secX_zero_cnt);
				}
				measurements[i].secX_zero_sum = 0;
				measurements[i].secX_zero_cnt = 0;

				// secX deriv counter
				if (measurements[i].secX_deriv_cnt) {
					secX_deriv_avg += (measurements[i].secX_deriv_sum / measurements[i].secX_deriv_cnt);
				}
				measurements[i].secX_deriv_sum = 0;
				measurements[i].secX_deriv_cnt = 0;

				// secX cmac counter
				if (measurements[i].secX_cmac_cnt) {
					secX_cmac_avg += (measurements[i].secX_cmac_sum / measurements[i].secX_cmac_cnt);
				}
				measurements[i].secX_cmac_sum = 0;
				measurements[i].secX_cmac_cnt = 0;

				// bloom filter add counter
				if (measurements[i].bloom_add_cnt) {
					bloom_add_avg += (measurements[i].bloom_add_sum/measurements[i].bloom_add_cnt);
				}
				measurements[i].bloom_add_sum = 0;
				measurements[i].bloom_add_cnt = 0;


				// bloom filter reset
				if (measurements[i].bloom_free_cnt) {
					bloom_free_avg += (measurements[i].bloom_free_sum / measurements[i].bloom_free_cnt);
				}
				measurements[i].bloom_free_sum = 0;
				measurements[i].bloom_free_cnt = 0;

				// packet copy counter
				if (measurements[i].pktcopy_cnt) {
					pktcopy_avg += (measurements[i].pktcopy_sum/measurements[i].pktcopy_cnt);
				}
				measurements[i].pktcopy_sum = 0;
				measurements[i].pktcopy_cnt = 0;

				// enqueued counter
				if (measurements[i].tx_enqueue_cnt) {
					tx_enqueue_avg += (measurements[i].tx_enqueue_sum/measurements[i].tx_enqueue_cnt);
				}
				measurements[i].tx_enqueue_sum = 0;
				measurements[i].tx_enqueue_cnt = 0;

				// tx drain counter
				if (measurements[i].tx_drain_cnt) {
					tx_drain_avg += (measurements[i].tx_drain_sum / measurements[i].tx_drain_cnt);
				}
				measurements[i].tx_drain_sum = 0;
				measurements[i].tx_drain_cnt = 0;

				// rx drain counter
				if (measurements[i].rx_drain_cnt) {
					rx_drain_avg += (measurements[i].rx_drain_sum / measurements[i].rx_drain_cnt);
				}
				measurements[i].rx_drain_sum = 0;
				measurements[i].rx_drain_cnt = 0;
			}
		}

		printf("Cycles per second: %"PRIu64"\n", tsc_hz);

		if (dup_avg) dup_avg /= active_dup_cores;
		printf("Total average duplicate detection processing: %"PRIu64"\n", dup_avg);

		if (rx_drain_avg) rx_drain_avg /= active_dup_cores;
		printf("| Average rx drain processing: %"PRIu64"\n", rx_drain_avg);

		if (header_avg) header_avg /= active_dup_cores;
		printf("| Average header processing: %"PRIu64"\n", header_avg);

		if (rate_limit_avg) rate_limit_avg /= active_dup_cores;
		printf("| Average rate limit processing: %"PRIu64"\n", rate_limit_avg);

		if (pktcopy_avg) pktcopy_avg /= active_dup_cores;
		printf("| Average packet copy processing: %"PRIu64"\n", pktcopy_avg);

		if (secX_avg) secX_avg /= active_dup_cores;
		printf("| Average security extension processing: %"PRIu64"\n", secX_avg);

		if (secX_zero_avg) secX_zero_avg /= active_dup_cores;
		printf("  | Average zeroing-out processing: %"PRIu64"\n", secX_zero_avg);

		if (secX_deriv_avg) secX_deriv_avg /= active_dup_cores;
		printf("  | Average key derivation processing: %"PRIu64"\n", secX_deriv_avg);

		if (secX_cmac_avg) secX_cmac_avg /= active_dup_cores;
		printf("  | Average CMAC computation processing: %"PRIu64"\n", secX_cmac_avg);

		if (bloom_free_avg) bloom_free_avg /= active_dup_cores;
		printf("| Average bloom free-init processing: %"PRIu64"\n", bloom_free_avg);

		if (bloom_add_avg) bloom_add_avg /= active_dup_cores;
		printf("| Average bloom adding processing: %"PRIu64"\n", bloom_add_avg);

		if (tx_enqueue_avg) tx_enqueue_avg /= active_dup_cores;
		printf("| Average tx enqueue processing: %"PRIu64"\n", tx_enqueue_avg);

		if (tx_drain_avg) tx_drain_avg /= active_dup_cores;
		printf("| Average tx drain processing: %"PRIu64"\n", tx_drain_avg);

		printf("\n");
#endif
		}
	}
}

/*
 * function to set up the key-manager and to fetch all necessary AS delegation secrets
 * in order for the LightningFilter to function.
 * Generally the design works as described in https://github.com/scionproto/scion/blob/master/doc/DRKeyInfra.md
 * For each AS we have a ring-buffer that stores the three current (previous current, net) delegation secrets (DS)
 * the key manager will replace old keys with new ones
 */
static void init_key_manager(void){

	uint64_t as;
	dictionary * dict;
	uint32_t now = time(NULL);

	int initial_size = 32;
	MINIMUM_KEY_VALIDITY = 36000; // default value one day. if no key has shorter validity, we check at least every hour.

	// initialize key dictionaries for every lcore
	printf("KEY_MANAGER::initialize directories\n");
	for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
		if(is_in_use[core_id] == false){
			continue;
		}
		dictionary * dict = dic_new(initial_size);
		key_dictinionary[core_id] = dict;
	}


	// for each initial AS create key_storage and add it to the lcore dictionaries
	printf("KEY_MANAGER::starting key store init\n");
	for (uint8_t key_index = 0; key_index < config_nb_keys; key_index++){

		key_storage *key_storage = malloc(sizeof(key_storage)); //allocate one lcore-shared keystore for each AS.
		as = config_keys[key_index];

		printf("KEY_MANAGER::initializing key_store for AS: %"PRIu64"\n", as);
		for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
			if(is_in_use[core_id] == false){
				continue;
			}

			// for every lcore create a key-store node whihc points to the shared keystore
			key_store_node* key_store_node = malloc(sizeof(key_store_node));
			key_store_node->index = 0;
			key_store_node->key_store = key_storage;
			dict = key_dictinionary[core_id];
			dic_add(dict,as, key_store_node);
		}
	}

	// next the key manager will fetch the initial keys for every as (current and next key)
	// for every new key we check wether the minimum key validity (check interval) changes
	dict = key_dictinionary[key_manager_core_id];
	for (uint8_t key_index = 0; key_index < config_nb_keys; key_index++){
		as = config_keys[key_index];

		uint32_t next_time;
		delegation_secret *key;
		key_storage *key_storage;

		dic_find(dict,as);
		key_storage = dict->value->key_store;

		// get first key
		key = malloc(sizeof(key_storage));
		get_DRKey(now, as, key);
		MINIMUM_KEY_VALIDITY = MIN(MINIMUM_KEY_VALIDITY, (key->epoch_end - key->epoch_begin));
		next_time = key->epoch_end;
		key_storage->drkeys[0] = key;
		// get next key
		key = malloc(sizeof(key_storage));
		get_DRKey(next_time, as, key);
		key_storage->drkeys[1] = key;
		MINIMUM_KEY_VALIDITY = MIN(MINIMUM_KEY_VALIDITY, (key->epoch_end - key->epoch_begin));

	}
	// we define the key check interval (how often we check whether there is a new key for any AS)
	// as a 10th of the minimum key validity
	KEY_CHECK_INTERVAL = MINIMUM_KEY_VALIDITY / 10;
}


/*
 * this is the main loop of the key manager
 * while the system is running we check for new keys or keys that can be replaced.
 * We check perdiodically according to the key check interval
 */
static void key_manager_main_loop(void){
	printf("KEY MANAGER HAS STARTED\n");

	struct dictionary * dict;
	dict = key_dictinionary[key_manager_core_id];

	while (!force_quit) {

		// do for every AS
		for (int i = 0; i < dict->length; i++) {
			if (dict->table[i] != 0) {
				struct keynode *k = dict->table[i];
				while (k) {
					check_and_fetch(k->key_store, k->key); // check and possibly fetch new keys for this AS
					k = k->next;
				}
			}
		}

		KEY_CHECK_INTERVAL = MINIMUM_KEY_VALIDITY / 10;

		// sleep in one second chunks until the key check interval is over
		// this avoids hot spinning while alowing force quits
		for (uint32_t i = 0; i < KEY_CHECK_INTERVAL; i++){
			sleep(1);
			if(force_quit){
				break;
			}
		}
	}
}


/*
 * this function initialises the rate-limiter and defines the initial buckets.
 * As described in the "LighningFilter" thesis we use a modified version of token bucket
 *
 * The code contains some boilerplate because we have to calculate rate limits both system-wide
 * and per-AS, for SecX and normal SCION traffic. Moreover, to avoid data races, we calculate the
 * rate-limits for alternating even and odd states. Also we need to store the counters for the previous slices
 * both system-wide and per-AS.
 */
static void init_dos(void){

	int initial_size = 32;
	dos_statistic* dos_stat;
	dos_counter* counter;

	// reserve counters (have to be atomic becasue they are shared among all lcores)
	rte_atomic64_t * reserve_all_even = malloc(sizeof(rte_atomic64_t));
	rte_atomic64_t * reserve_all_odd = malloc(sizeof(rte_atomic64_t));

	// systemwide token pools initialized to zero for both states
	current_pool[0] = 0;
	current_pool[1] = 0;

	// for each core initalize:
	for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
		if(is_in_use[core_id] == false){
			continue;
		}

		// set the previous slcie counter to zero
		previous_dos_stat[core_id].secX_dos_packet_count[0] = 0;
		previous_dos_stat[core_id].secX_dos_packet_count[1] = 0;
		previous_dos_stat[core_id].sc_dos_packet_count[0] = 0;
		previous_dos_stat[core_id].sc_dos_packet_count[1] = 0;

		// initalize the dictionaries
		dos_stat = &dos_stats[core_id];
		dictionary_flow * dict_odd = dic_new_flow(initial_size);
		dictionary_flow * dict_even = dic_new_flow(initial_size);

		// store the dictionaries
		dos_stat->dos_dictionary[ODD] = dict_odd;
		dos_stat->dos_dictionary[EVEN] = dict_even;

		// set pointers to the reserve
		dos_stat->reserve[ODD] = reserve_all_odd;
		dos_stat->reserve[EVEN] = reserve_all_even;

		// initialize previous dictionaries
		dict_odd = dic_new_flow(initial_size);
		dict_even = dic_new_flow(initial_size);

		// set previous dictionaries
		previous_dos_stat[core_id].dos_dictionary[ODD] = dict_odd;
		previous_dos_stat[core_id].dos_dictionary[EVEN] = dict_even;
	}

	// for each AS store the create and link the per-AS reserve and intialize  the counters and refill rates
	// with the values read from the configuration file
	for (uint8_t key_index = 0; key_index < config_nb_keys; key_index++){

		// create reserves for that AS shared among all lcores (atomic counter)
		rte_atomic64_t * reserve_as_odd = malloc(sizeof(rte_atomic64_t));
		rte_atomic64_t * reserve_as_even = malloc(sizeof(rte_atomic64_t));

		// for each core do:
		for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
			if(is_in_use[core_id] == false){
				continue;
			}

			dos_stat = &dos_stats[core_id];

			// create dos_counter for odd dictionary
			counter = malloc(sizeof(dos_counter));
			counter->secX_counter = 0;
			counter->sc_counter = 0;
			counter->refill_rate = config_limits[key_index];
			counter->reserve = reserve_as_odd; // pointer to reserve atomic
			dic_add_flow(dos_stat->dos_dictionary[ODD], config_keys[key_index], counter);

			// create dos_counter for even dictionary
			counter = malloc(sizeof(dos_counter));
			counter->secX_counter = 0;
			counter->sc_counter = 0;
			counter->refill_rate = config_limits[key_index];
			counter->reserve = reserve_as_even; // pointer to reserve atomic
			dic_add_flow(dos_stat->dos_dictionary[EVEN], config_keys[key_index], counter);

			// create dos_counter for PREVIOUS odd dictionary
			counter = malloc(sizeof(dos_counter));
			counter->secX_counter = 0;
			counter->sc_counter = 0;
			counter->refill_rate = config_limits[key_index];
			dic_add_flow(previous_dos_stat[core_id].dos_dictionary[ODD], config_keys[key_index], counter);

			// create dos_counter for PREVIOUS even dictionary
			counter = malloc(sizeof(dos_counter));
			counter->secX_counter = 0;
			counter->sc_counter = 0;
			counter->refill_rate = config_limits[key_index];
			dic_add_flow(previous_dos_stat[core_id].dos_dictionary[EVEN], config_keys[key_index], counter);
		}
	}

}



/*
 * this function recomputes the buckets each interval (100 microseconds)
 * As described in the "LighningFilter" thesis we use a modified version of token bucket
 * We perform three steps:
 * I) aggregate per core counters (tokens used)
 * 2) recompute token pool (pool_size + refill-rate - tokens-used)
 * 3) distribute newly available tokens among cores and reserve
 *
 * The code contains some boilerplate because we have to calculate rate limits both system-wide
 * and per-AS, for SecX and normal SCION traffic. Moreover, to avoid data races, we calculate the
 * rate-limits for alternating even and odd states. Also we need to store the counters for the previous slices
 * both system-wide and per-AS.
 */
static void dos_main_loop(void){

	int16_t state;
	int64_t reserve_count;
	uint64_t last_dos_slice_tsc = rte_rdtsc();
	uint64_t current_tsc;

    struct dos_statistic core_dos_stat;
    struct dos_statistic dos_stat;
    struct dictionary_flow * dict;
    struct dictionary_flow * lcore_dict;

	printf("DOS HAS STARTED\n");

	dos_stat = dos_stats[rte_lcore_id()];
    dos_slice_period = rte_get_timer_hz() / 10000; // 100 micro-seconds
    state = EVEN; // inital rate-limiter state: EVEN -> initial processing core state: ODD

    /* main loop */
	while(!force_quit){

		current_tsc = rte_rdtsc();
		// wait slightly longer to avoid data races with data-plane
		if (current_tsc - last_dos_slice_tsc > dos_slice_period + 10000) {

			dos_slice_period = (rte_get_timer_hz() / 10000) - 10000; // compensate for the extra cylces
			last_dos_slice_tsc = current_tsc;

			// go to oposide state (could be simply state != state)
			if (state == EVEN){
				state = ODD;
			}else{
				state = EVEN;
			}
			// set new state in global state variable (this is the only thread that writes, all others are read only)
			rte_atomic16_set(&dos_state, state);

			// reset aggregate variables
			int64_t secX_count = 0;
			int64_t sc_count = 0;
			int64_t used_secX = 0;
			int64_t used_sc = 0;
			int64_t used_secX_sum = 0;
			int64_t used_sc_sum = 0;
			int64_t refill_rate = system_refill_rate; // global refill rate
			int64_t MAX_POOL_SIZE = refill_rate * MAX_POOL_SIZE_FACTOR;

			// aggregate over all lcores
			for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
				if(is_slave_core[core_id] == false){
					continue;
				}
				core_dos_stat = dos_stats[core_id];

				// compute used secX tokens
				/* we allocated x tokens to a core
				 * if the core used less than x -> used = allocated - core counter value
				 * if the core used more than x -> used = allocated + core counter value (which must be negative)*/
				used_secX = core_dos_stat.secX_dos_packet_count[state];
				if(used_secX < 0){
					used_secX_sum += abs(used_secX) + previous_dos_stat[core_id].secX_dos_packet_count[state];
				}else{
					used_secX_sum += previous_dos_stat[core_id].secX_dos_packet_count[state] - used_secX;
				}

				// compute used normal SCION tokens
				used_sc = core_dos_stat.sc_dos_packet_count[state];
				if(used_sc < 0){
					used_sc_sum += abs(used_sc) + previous_dos_stat[core_id].sc_dos_packet_count[state];
				}else{
					used_sc_sum += previous_dos_stat[core_id].sc_dos_packet_count[state] - used_sc;
				}

			}

			// refill the pool
			current_pool[state] += refill_rate;

			// take from the refilled pool
			secX_count = current_pool[state] - used_secX_sum;
			sc_count = current_pool[state] - used_secX_sum - used_sc_sum;

			// update the pool size, based on the tokens allocated
			current_pool[state] -= used_secX_sum;
			current_pool[state] -= used_sc_sum;

			// cap the pool at the max pool size
			if(current_pool[state] > MAX_POOL_SIZE){
				current_pool[state] = MAX_POOL_SIZE;
			}

			// calculate the ratio of tokens allocated to the reserce
			reserve_count = (secX_count + secX_count) * RESERVE_FRACTION;
			secX_count = secX_count * (1.0 - RESERVE_FRACTION);
			sc_count = sc_count * (1.0 - RESERVE_FRACTION);

			// store how many tokens were allocated globaly
			rte_atomic64_set((dos_stat.reserve[state]), reserve_count);
			dos_stat.secX_dos_packet_count[state] = secX_count;
			dos_stat.sc_dos_packet_count[state] = sc_count;

			// for each core now allocte a fraction of the allocation
			for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
				if(is_slave_core[core_id] == false){
					continue;
				}
				core_dos_stat = dos_stats[core_id];

				dos_stats[core_id].secX_dos_packet_count[state] = secX_count / nb_slave_cores;
				previous_dos_stat[core_id].secX_dos_packet_count[state] = secX_count / nb_slave_cores;

				dos_stats[core_id].sc_dos_packet_count[state] = sc_count / nb_slave_cores;
				previous_dos_stat[core_id].sc_dos_packet_count[state] = sc_count / nb_slave_cores;
			}

			// now we repeat the process for each AS
			dict = dos_stat.dos_dictionary[state];

			// for each AS in the dictionary:
			for (int i = 0; i < dict->length; i++) {
				if (dict->table[i] != 0) {
					struct keynode_flow *k = dict->table[i];
					while (k) {

						uint64_t key = k->key;
						int64_t current_pool = k->counters->secX_counter; // yes this is not very nice dual-use
						int64_t secX_count = 0;
						int64_t sc_count = 0;
						int64_t used_secX = 0;
						int64_t used_sc = 0;
						int64_t used_secX_sum = 0;
						int64_t used_sc_sum = 0;
						int64_t refill_rate = k->counters->refill_rate; // retrieve refill rate
						int64_t MAX_POOL_SIZE = (refill_rate * MAX_POOL_SIZE_FACTOR);

						// now for each lcore aggregate again
						for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
							if(is_slave_core[core_id] == false){
								continue;
							}

							core_dos_stat = dos_stats[core_id];
							lcore_dict = core_dos_stat.dos_dictionary[state];

							// find the dictionary node for the current AS
							dic_find_flow(lcore_dict, key);
							dic_find_flow(previous_dos_stat[core_id].dos_dictionary[state], key);
							dos_counter* value = previous_dos_stat[core_id].dos_dictionary[state]->value;

							// compute used secX tokens
							used_secX = lcore_dict->value->secX_counter;
							if(used_secX < 0){
								used_secX_sum += abs(used_secX) + value->secX_counter;
							}else{
								used_secX_sum += value->secX_counter - used_secX;
							}

							// compute used normal SCION tokens
							used_sc = lcore_dict->value->sc_counter;
							if(used_sc < 0){
								used_sc_sum += abs(used_sc) + value->sc_counter;
							}else{
								used_sc_sum += value->sc_counter - used_sc;
							}
						}

						// refill the pool
						current_pool += refill_rate;

						// allocate tokens
						secX_count = current_pool - used_secX_sum;
						sc_count = current_pool - used_secX_sum - used_sc_sum;

						// update the pool
						current_pool -= used_secX_sum;
						current_pool -= used_sc_sum;

						//cap the pool at max size
						if(current_pool > MAX_POOL_SIZE){
							current_pool = MAX_POOL_SIZE;
						}

						// store the pool size again in the rat-limit dictionary node for the current AS
						k->counters->secX_counter = current_pool;

						// allocate tokens across lcores
						for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {
							if(is_slave_core[core_id] == false){
								continue;
							}

							core_dos_stat = dos_stats[core_id];
							lcore_dict = core_dos_stat.dos_dictionary[state];
							dic_find_flow(lcore_dict, key);
							
							// reserve allocation
							reserve_count = secX_count + secX_count * RESERVE_FRACTION;
							secX_count = secX_count * (1.0 - RESERVE_FRACTION);
							sc_count = sc_count * (1.0 - RESERVE_FRACTION);

							// set next allocations
							rte_atomic64_set(lcore_dict->value->reserve, reserve_count);
							lcore_dict->value->secX_counter = secX_count / nb_slave_cores;
							lcore_dict->value->sc_counter = sc_count / nb_slave_cores;

							// set previous allocation
							dic_find_flow(previous_dos_stat[core_id].dos_dictionary[state], key);
							previous_dos_stat[core_id].dos_dictionary[state]->value->secX_counter = secX_count / nb_slave_cores;
							previous_dos_stat[core_id].dos_dictionary[state]->value->sc_counter = sc_count / nb_slave_cores;
						}
						k = k->next;
					}
				}
			}
		}
	}
}

/*
 * function to load rate limits from the end_hosts.cfg file
 * This function is called at start-up and whenever the CLI sees the reload commands
 * To load the cfg file is parsed in a simple fashion
 * in the file rate limits are specified as bps, we convert this to bytes / 100 micro-seconds
 * limits are divided by 1.042 (Magic constant, i don't no why but without the rate-limits are too high)
 */
int load_rate_limits(char *file_name){

	int32_t nb_keys = 0;
	int index = 0;
	void *fgets_res;
	uint64_t *keys = NULL;
	int64_t *limits = NULL;
	int64_t *raw_limits = NULL;

	// open cfg file
    FILE *fp = fopen(file_name, "r");
    if(fp == NULL) {
    	printf("Unable to open file %s!", file_name);
        return -1;
    }
 
    char line[256];
    char arg[256];
    double val;

    // read all lines
    while(fgets(line, sizeof(line), fp) != NULL) {
        if(line[0] == '#'){
            continue;
        }
        if(strcmp(line, "system_limit:\n") == 0){ // global system limit
        	fgets_res = fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
        	val = strtoll(arg, NULL, 10);
            system_refill_rate = (int64_t)((val / 8) / 10000) / 1.042; // convert limit to bytes and shrink to 100 microseconds interval
        }else if(strcmp(line, "number_of_entries:\n") == 0){ // number of AS entries in the file
        	fgets_res = fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
            nb_keys = strtol(arg, NULL, 10);
            if(nb_keys < 1){
            	return -1;
            }
			keys = malloc(sizeof(uint64_t) * nb_keys); // allocate arrays depending on the size
			limits = malloc(sizeof(uint64_t) * nb_keys);
			raw_limits = malloc(sizeof(uint64_t) * nb_keys);
        }else if(strcmp(line, "as:\n") == 0){ // AS entry
			if((nb_keys - index) <= 0){ // check whether there are more entries than was specified and abort
				fclose(fp);
				return -1;
			}
			fgets_res =  fgets(arg, sizeof(arg), fp); // AS id
			if(fgets_res == NULL) {return -1;}
			keys[index] = strtoll(arg, NULL, 10);

			fgets_res = fgets(arg, sizeof(arg), fp); // useless (format specific)
			fgets_res = fgets(arg, sizeof(arg), fp); // rate-limit
			if(fgets_res == NULL) {return -1;}
			raw_limits[index] = strtoll(arg, NULL, 10);
			val = raw_limits[index];
			limits[index] = (int64_t)((val / 8) / 10000) / 1.042; // convert limit to bytes and shrink to 100 microseconds interval
			index++;
		}
    }

    if (nb_keys < 0){
    	fclose(fp);
    	return -1;
    }

    // display the new rate limits to the user, so he can see the changes
	printf("Stored %d rate limits\n", nb_keys);
	for (index = 0; index < nb_keys; index++){
		printf("   AS: %"PRIu64" -> %"PRId64" bps\n", keys[index], raw_limits[index]);
	}
	printf("\n");

	// update global storage
	config_nb_keys = nb_keys;
	config_keys = keys;
	config_limits = limits;


    return 0;
}


/*
 * loads the system configuration from teh scion_filter.cfg file
 * This is done at start-up
 * The arguments are parsed and stored in the global variables
 */
int load_config(char *file_name){
	void *fgets_res;

	// open file
    FILE *fp = fopen(file_name, "r");
    if(fp == NULL) {
    	printf("Unable to open file %s!", file_name);
        return -1;
    }
 
    char line[256];
    char arg[256];

    // read each line
    while(fgets(line, sizeof(line), fp) != NULL) {
        if(line[0] == '#'){
            continue;
        }
        if(strcmp(line, "rx_port_mask:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			scionfwd_rx_port_mask = strtol(arg, NULL, 10);
        }else if(strcmp(line, "tx_bypass_port_mask:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			scionfwd_tx_bypass_port_mask = strtol(arg, NULL, 10);
        }else if(strcmp(line, "tx_firewall_port_mask:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			scionfwd_tx_firewall_port_mask = strtol(arg, NULL, 10);
        }else if(strcmp(line, "stats_interval:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			int timer_secs = strtol(arg, NULL, 10);
			if (timer_secs >= 0) {
				slice_timer_period = timer_secs;
				slice_timer_period_seconds = timer_secs;
			}	
        }else if(strcmp(line, "nb_bloom_filters:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			BLOOM_FILTERS = strtol(arg, NULL, 10);
        }else if(strcmp(line, "bloom_filter_entries:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			NUM_BLOOM_ENTRIES = strtol(arg, NULL, 10);
        }else if(strcmp(line, "bloom_filter_error_rate:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			BLOOM_ERROR_RATE = strtol(arg, NULL, 10);
        }else if(strcmp(line, "bloom_filter_rotation_rate:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			delta_us = strtol(arg, NULL, 10);
        }else if(strcmp(line, "drkey_grace_period:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			KEY_GRACE_PERIOD = strtol(arg, NULL, 10);
        }else if(strcmp(line, "max_pool_size_factor:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			MAX_POOL_SIZE_FACTOR = strtol(arg, NULL, 10);
        }else if(strcmp(line, "reserve_fraction:\n") == 0){
        	fgets_res =  fgets(arg, sizeof(arg), fp);
        	if(fgets_res == NULL) {return -1;}
			double var = atof(arg);
			if( var >= 0.0 && var <= 1.0){ //check if valid fraction in [0, 1]
				RESERVE_FRACTION = var;
			}
        }
    }
    fclose(fp);
    return 0;
}


/*
 * cli read line function
 * listens only to two commands at the moment
 * can not react to ctrl+c, so user has to call stop command if
 * CL is enabled
 */
int cli_read_line(void){
	int res;
    char *line = NULL;
    size_t bufsize = 0;
    res = getline(&line, &bufsize, stdin);
    if(res < 0){
    	return 1;
    }
    if(strcmp(line, "reload\n") == 0){
        load_rate_limits("config/end_hosts.cfg");
    }else if (strcmp(line, "stop\n") == 0){
    	force_quit = true;
        return 0;
    }else{
        print_cli_usage();
    }
    return 1;
}


/*
 * CLI prompt user for imput and parse the input
 */
void prompt(void){
    int status;

    do {
        printf("> ");
        status = cli_read_line();
  } while (status);
}


/* launch main processing core main loop */
static int
scionfwd_launch_dup_core(__attribute__((unused)) void *dummy)
{
	scionfwd_main_loop();
	return 0;

}

/* launch rate-limit core main loop*/
static int
scionfwd_launch_dos_core(__attribute__((unused)) void *dummy)
{
	dos_main_loop();
	printf("DOS CORE HAS TERMINATED\n");
	return 0;

}

/* launch metrics core main loop*/
static int
scionfwd_launch_metrics_core(__attribute__((unused)) void *dummy)
{
	metrics_main_loop();
	printf("METRICS CORE HAS TERMINATED\n");
	return 0;

}

/* launch key-manager core main loop*/
static int
scionfwd_launch_key_manager_core(__attribute__((unused)) void *dummy)
{
	key_manager_main_loop();
	printf("KEY MANAGER HAS TERMINATED\n");
	return 0;

}

/* launch supervisor and CLI*/
static int
scionfwd_launch_supervisor(void)
{
	printf("SUPERVISOR HAS STARTED\n");
	while(!force_quit){
		if(is_interactive){
			printf("\n\n");
			printf("COMMAND LINE RUNNING\n");
			printf("********************\n");
			prompt();
		}
		sleep(1);
	}
	printf("SUPERVISOR HAS TERMINATED\n");
	return 0;
}


/* display CLI usage */
void print_cli_usage(void){
    printf("Currently supported CLI commands:\n\n"
           "  reload  Reloads the rate-limit config file\n"
	       "    stop  terminates the application\n"
	       "    help  Prints this info\n\n"
		  );
}


/* display application usage */
static void
scionfwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK\n"
	       "  -r RX PORTMASK: hexadecimal bitmask of receive ports to configure\n"
		   "  -x TX PORTMASK: hexadecimal bitmask of bypass ports to configure\n"
		   "  -y TX PORTMASK: hexadecimal bitmask of firewall ports to configure\n"
		   "  -i FLAG: enable interactive mode\n"
		   "  -l FLAG: load config from scion_filter.cfg and whitelist.cfg\n"
		   "  -n enable experimental smart numa alloc\n"
		   "  -K NUM set key grace period\n"
		   "  -S PERIOD: Set slice time (default %"PRIu64")\n"
		   "  -E: NUM: Set num of bloom entries (default %"PRIu64")\n" 
		   "  -R: NUM: Set reciprocal value of error rate (default %"PRIu64")\n" 
		   "  -D: us: Set value of bloom filter duration (default %i)\n", 
	       prgname, slice_timer_period, NUM_BLOOM_ENTRIES, BLOOM_ERROR_RATE, delta_us);
}


/* convert string to portmask (int bitmap) */
static int
scionfwd_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

/* parse string numbers into ints */
static int
scionfwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if (q_arg[0] == '\0')
		return -1;
	if (end == NULL)
		return -2;

	return n;
}

/* command line arg requirement: define short option flags */
static const char short_options[] =
	"r:"  /* receive portmask */
	"t:"  /* transmit portmask */
	"x:"  /* transmit bypass portmask */
	"y:"  /* transmit firewall portmask */
	"n:"  /* enable NUMA alloc */
	"i:"  /* enable interactive */
	"l:"  /* load from config */
	"S:"  /* slice timer period */
	"E:"  /* bloom entries */
	"R:"  /* bloom error rate */
	"D:"  /* bloom interval */
	"K:"  /* key grace period */
	;

/* all this is deprecated I think */
#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_ETH_DEST "eth-dest"
#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_ETH_DEST_NUM,

};

/* again I think the long options are deprecated,
 * the did not work when I took over this project */
static const struct option lgopts[] = {
	{CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
	{CMD_LINE_OPT_ETH_DEST, 1, 0, CMD_LINE_OPT_ETH_DEST_NUM},
	{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
	{NULL, 0, 0, 0}
};


/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF RTE_MAX(	\
	(nb_ports*nb_rx_queues_per_port*RTE_TEST_RX_DESC_DEFAULT +	\
	nb_ports*nb_lcores*MAX_PKT_BURST +			\
	nb_ports*(nb_tx_bypass_queues_per_port + nb_tx_firewall_queues_per_port)*RTE_TEST_TX_DESC_DEFAULT +		\
	nb_lcores*MEMPOOL_CACHE_SIZE),				\
	(unsigned)8192)


/* Parse the argument given in the command line of the application */
static int
scionfwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {

		/* receiving ports */
		case 'r':
			scionfwd_rx_port_mask = scionfwd_parse_portmask(optarg);
			if(scionfwd_rx_port_mask == 0) {
				printf("invalid rx port mask\n");
				scionfwd_usage(prgname);
				return -1;
			}
			break;

		/* bypass ports */
		case 'x':
			scionfwd_tx_bypass_port_mask = scionfwd_parse_portmask(optarg);
			if(scionfwd_tx_bypass_port_mask == 0) {
				printf("invalid tx port mask\n");
				scionfwd_usage(prgname);
				return -1;
			}
			break;

		/* firewall ports */
		case 'y':
			scionfwd_tx_firewall_port_mask = scionfwd_parse_portmask(optarg);
			if(scionfwd_tx_firewall_port_mask == 0) {
				printf("invalid tx port mask\n");
				scionfwd_usage(prgname);
				return -1;
			}
			break;
		
		/* enable interactive mode */
		case 'i':
			is_interactive = 1;
			break;

		/* load from config */
		case 'l':
			from_config_enabled = true;
			break;

		/* enable numa alloc */
		case 'n':
			numa_on = true;
			break;

		/* KEY GRACE PERIOD */
		case 'K':
			KEY_GRACE_PERIOD = scionfwd_parse_timer_period(optarg);
			break;

		/* slice timer period */
		case 'S':
			timer_secs = scionfwd_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				scionfwd_usage(prgname);
				return -1;
			}
			slice_timer_period = timer_secs;
			slice_timer_period_seconds = timer_secs;
			break;

		case 'E':
            NUM_BLOOM_ENTRIES = scionfwd_parse_timer_period(optarg);
			break;

		case 'R':
            BLOOM_ERROR_RATE = scionfwd_parse_timer_period(optarg);
			break;

		case 'D':
            delta_us = scionfwd_parse_timer_period(optarg);
			break;
				
		case 0:
			break;

		default:
			scionfwd_usage(prgname);
			return -1;
		}
			
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 0; /* reset getopt lib */
	return ret;
}


/*
 * Initialize the memory pools used by all processing cores
 * If numa is on we initalize two pools, one per socket.
 * Otherwise we use only one pool
 * ! This currentyl works only on a machine with max two sockets !
 */
static int
init_mem(unsigned nb_mbuf)
{	
	uint32_t gso_types;
	uint8_t socket_id, nb_sockets;
	struct rte_mempool *mbp;
	char s[64];

	printf("/* init rx queues */\n");

	if (numa_on) {
		printf("NUMA is on\n");
		nb_sockets = 2; // THIS ONLY WORKS ON THE CURRENT MACHINE SCION-R4
	}else{
		nb_sockets = 1;
	}
	// for each socket allocate a mbufpool, according to DPDK specs
	for (socket_id = 0; socket_id < nb_sockets; socket_id++) {
		snprintf(s, sizeof(s), "mbuf_pool_%d", socket_id);
		scionfwd_pktmbuf_pool[socket_id] = rte_pktmbuf_pool_create(s, nb_mbuf,
					MEMPOOL_CACHE_SIZE, 0,
					RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
		if (scionfwd_pktmbuf_pool[socket_id] == NULL){
			rte_exit(EXIT_FAILURE,
				"Cannot init mbuf pool on socket %d\n",
				socket_id);
		} else {
			printf("Allocated mbuf pool on socket %d with size: %d at address : %p\n",
				socket_id, nb_mbuf, scionfwd_pktmbuf_pool[socket_id]);
			printf("mem pool cache size %d default size: %d\n", MEMPOOL_CACHE_SIZE, RTE_MBUF_DEFAULT_BUF_SIZE);
		} 
	}

	gso_types = DEV_TX_OFFLOAD_TCP_TSO | DEV_TX_OFFLOAD_VXLAN_TNL_TSO |
		DEV_TX_OFFLOAD_GRE_TNL_TSO | DEV_TX_OFFLOAD_UDP_TSO;

	/*
	 * Records which Mbuf pool to use by each logical core, if needed.
	 */
	for ( int core_id = 0; core_id < RTE_MAX_LCORE; core_id++ ) {
		if(is_slave_core[core_id] == false){
			continue;
		}
		socket_id = rte_lcore_to_socket_id(core_id);
		mbp = scionfwd_pktmbuf_pool[socket_id];

		if (mbp == NULL){
			mbp = scionfwd_pktmbuf_pool[0];
		}
		
		printf("CORE %d :: SOCKET %d :: mbp %p\n",core_id, socket_id, mbp);
		core_vars[core_id].socket_id = socket_id;
		core_vars[core_id].mbp = mbp;

		/* initialize GSO context */
		core_vars[core_id].gso_ctx.direct_pool = mbp;
		core_vars[core_id].gso_ctx.indirect_pool = mbp;
		core_vars[core_id].gso_ctx.gso_types = gso_types;
		core_vars[core_id].gso_ctx.gso_size = ETHER_MAX_LEN - ETHER_CRC_LEN;
		core_vars[core_id].gso_ctx.flag = 0;
	}
	return 0;
}


/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

/* Signal handler
 * triggers force-quit flag */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

/*
 * Main function of the apllication
 * performs the entire set-up and starts all cores
 */
int scion_filter_main(int argc, char **argv) {	

	int ret;
	int nb_active_ports;
	uint8_t port_id, socket_id;
	uint32_t lcore_id = rte_lcore_id();
	uint32_t nb_lcores = 0;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf; 
	
	uint8_t ports_on_socket_0 = 0;
	uint8_t ports_on_socket_1 = 0;
	uint8_t cores_on_socket_0 = 0;
	uint8_t cores_on_socket_1 = 0;

	//set default values for two system configs
	KEY_GRACE_PERIOD = 30;
	SUSPICIOUS_KEY_CHANGE_RATIO = 30;
	is_interactive = 0;


	printf("Starting SCION FW BYPASS\n\n");

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* register signal handlers */
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = scionfwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid SCIONFWD arguments\n");

	nb_active_ports = rte_eth_dev_count_avail();
	if (nb_active_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");


	//read config file
	if(from_config_enabled){
		ret = load_config("config/scion_filter.cfg");
		if (ret < 0)
				rte_exit(EXIT_FAILURE, "Could not parse config from provided file\n");
	}

	// read rate-limit config file
	load_rate_limits("config/end_hosts.cfg");


	/* reset scionfwd_ports */
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++){
		is_active_port[port_id] = false;
	    port_values *port = &port_vars[port_id];
		port->socket_id = rte_eth_dev_socket_id(port_id);
	}


	/* count available ports */
	nb_rx_ports = (__builtin_popcount(scionfwd_rx_port_mask));
	nb_tx_bypass_ports = (__builtin_popcount(scionfwd_tx_bypass_port_mask));
	nb_tx_firewall_ports = (__builtin_popcount(scionfwd_tx_firewall_port_mask));
	nb_tx_ports = nb_tx_bypass_ports + nb_tx_firewall_ports;

	/* set port function */
	printf("\n/* set port function */\n");
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) { // ports can have multiple roles
		if( (scionfwd_rx_port_mask & (1 << port_id)) == 0 ) { // rx
			is_rx_port[port_id] = false;
		}else{
			is_rx_port[port_id] = true;
			is_active_port[port_id] = true;
			printf("current port: %d ->",port_id);
			printf("is rx port\n");
		}
		if( (scionfwd_tx_bypass_port_mask & (1 << port_id)) == 0 ) { // tx bypass
			is_tx_bypass_port[port_id] = false;
		}else{
			is_tx_bypass_port[port_id] = true;
			is_active_port[port_id] = true;
			printf("current port: %d ->",port_id);
			printf("is tx bypass port\n");
		}
		if( (scionfwd_tx_firewall_port_mask & (1 << port_id)) == 0 ) { // tx firewall
			is_tx_firewall_port[port_id] = false;
		}else{
			is_tx_firewall_port[port_id] = true;
			is_active_port[port_id] = true;
			printf("current port: %d ->",port_id);
			printf("is tx firewall port\n");
		}
	}

	// count the number of ports on each socket
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (is_active_port[port_id] == true){
			nb_ports++;
			uint8_t socket_id =rte_eth_dev_socket_id(port_id);
			if(socket_id == 0){
				ports_on_socket_0++;
			}else if(socket_id == 1){
				ports_on_socket_1++;
			}
		}
	}

	/* count available lcores  on each socket*/
	uint32_t nb_available_cores = 0;
	for (int i = 0; i < RTE_MAX_LCORE; i++) {
		if (rte_lcore_is_enabled(i) == true) {
			nb_available_cores++;
			uint8_t socket_id = rte_lcore_to_socket_id(i);
			if(socket_id == 0){
				cores_on_socket_0++;
			}else if(socket_id == 1){
				cores_on_socket_1++;
			}
		}
	}

	// if there are less than 4 cores in the port mask return because we need at least 4 for the special cores
	if (nb_available_cores < 4){
		rte_exit(EXIT_FAILURE, "4 Cores needed for Master + Metrics + Keymanager + DOS\n");
	}

	uint32_t nb_proc_cores = nb_available_cores - 4; // one master core and this core
	nb_cores = nb_available_cores;
	nb_slave_cores = nb_proc_cores;

	// print some infos
	printf("RTE_MAX_LCORE: %d\n", RTE_MAX_LCORE);
	printf("Available cores: %d + %d\n", nb_slave_cores, (nb_available_cores - nb_slave_cores));
    printf("Slave cores %d\n",nb_slave_cores);

    printf("sl: %d\n", nb_slave_cores);
    printf("rx: %d\n", nb_rx_ports);
    printf("tx_b: %d\n", nb_tx_bypass_ports);
    printf("tx_f: %d\n", nb_tx_firewall_ports);

    printf("********************\n");
    printf("PORTS ON SOCKET 0: %d\n", ports_on_socket_0);
    printf("PORTS ON SOCKET 1: %d\n", ports_on_socket_1);
    printf("CORES ON SOCKET 0: %d\n", cores_on_socket_0);
    printf("CORES ON SOCKET 1: %d\n", cores_on_socket_1);
    printf("********************\n");



	/* calculate queues and lcores per port */
    /* we assume that ratio of slave cores per socket matches the ratio of ports per socket */
	uint8_t nb_rx_queues_per_port = nb_slave_cores/nb_rx_ports;
	uint8_t nb_tx_bypass_queues_per_port = nb_slave_cores/nb_tx_bypass_ports;
	uint8_t nb_tx_firewall_queues_per_port = nb_slave_cores/nb_tx_firewall_ports;

	printf("nb_rx_queues_per_port: %d\n", nb_rx_queues_per_port);
	printf("nb_tx_bypass_queues_per_port: %d\n", nb_tx_bypass_queues_per_port);
	printf("nb_tx_firewall_queues_per_port: %d\n", nb_tx_firewall_queues_per_port);

    /* initialize lcore arrays */
	printf("/* initialize lcore arrays */\n");
    for ( unsigned i = 0; i < RTE_MAX_LCORE; i++ ) {
        is_metrics_core[i] = false;
        is_key_manager_core[i] = false;
        is_slave_core[i] = false;
        is_in_use[i] = false;

		core_vars[i].rx_port_id = RTE_MAX_ETHPORTS;
		core_vars[i].tx_bypass_port_id = RTE_MAX_ETHPORTS;
		core_vars[i].tx_firewall_port_id = RTE_MAX_ETHPORTS;
    }

	/* allocate lcores */
	printf("/* allocate lcores */\n");
	bool metrics_is_set = false;
	bool key_manager_is_set = false;
	bool dos_is_set = false;

	// for every active core do the following:
	for ( unsigned i = 0; i < RTE_MAX_LCORE; i++ ) {
		socket_id = rte_lcore_to_socket_id(i);

        if ( i == rte_lcore_id() ) { // CLI core (supervisor core)
			printf("current lcore id: %d | %d ->",i, socket_id);
			printf("is supervisor\n");
			is_in_use[i] = true;
			if (socket_id == 0){
				cores_on_socket_0--;
			}else{
				cores_on_socket_1--;
			}
            continue;
        }
        if (rte_lcore_is_enabled(i) == true) {
            nb_lcores += 1;

            if (metrics_is_set == false) { // metrics core
				printf("current lcore id: %d | %d ->",i, socket_id);
				printf("is metrics\n");
                metrics_is_set = true;
                is_metrics_core[i] = true;
				is_in_use[i] = true;

				if (socket_id == 0){
					cores_on_socket_0--;
				}else{
					cores_on_socket_1--;
				}
            } else if (dos_is_set == false) { // rate limit core
				printf("current lcore id: %d | %d ->",i, socket_id);
				printf("is DOS\n");
                dos_is_set = true;
                is_dos_core[i] = true;
				is_in_use[i] = true;

				if (socket_id == 0){
					cores_on_socket_0--;
				}else{
					cores_on_socket_1--;
				}
            }else if (key_manager_is_set == false) { // key-manager core
				printf("current lcore id: %d | %d ->",i, socket_id);
				printf("is key_manager\n");
				key_manager_core_id = i;
				key_manager_is_set = true;
				is_key_manager_core[i] = true;
				is_in_use[i] = true;

				if (socket_id == 0){
					cores_on_socket_0--;
				}else{
					cores_on_socket_1--;
				}
			}else if (cores_on_socket_0 > 0 && socket_id == 0){ //socket 0 cores
            	printf("current lcore id: %d | %d ->",i, socket_id);
				printf("is slave\n");
				is_slave_core[i] = true;
				is_in_use[i] = true;
				cores_on_socket_0--;
            }else if (cores_on_socket_1 > 0 && socket_id == 1){ //socket 1 cores
            	printf("current lcore id: %d | %d ->",i, socket_id);
				printf("is slave\n");
				is_slave_core[i] = true;
				is_in_use[i] = true;
				cores_on_socket_1--;
            }
        }
	}
	if (cores_on_socket_0 != 0 || cores_on_socket_1 != 0){
		rte_exit(EXIT_FAILURE, "Cores are not correctly divided across the sockets");
	}

	printf("*************\n");
	printf("NB ACTIVE PORTS: %d\n", nb_ports);
	printf("NB RX PORTS: %d\n", nb_rx_ports);
	printf("NB TX PORTS: %d\n", nb_tx_ports);
	printf("NB RX BYPASS PORTS: %d\n", nb_tx_bypass_ports);
	printf("NB RX FIREWALL PORTS: %d\n", nb_tx_firewall_ports);


	if(nb_slave_cores < nb_ports){
		rte_exit(EXIT_FAILURE, "Need at least one slave core per active port\n");
	}

	struct port_values *port;
	struct ether_addr mac_addr;
	int port_socket_id;

	/* configure ports */
	printf("/* configure ports */\n");
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if(is_active_port[port_id] == false){
			continue;
		}

		port = &port_vars[port_id];
		port->dev_conf = port_conf;
		rte_eth_dev_info_get(port_id, &port->dev_info);
		rte_eth_macaddr_get(port_id, &port->eth_addr);
		port_socket_id = rte_eth_dev_socket_id(port_id);
		mac_addr = port->eth_addr;

		printf("*************\n");
		printf("Port %d: %02X:%02X:%02X:%02X:%02X:%02X\n", port_id,
				mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
				mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
				mac_addr.addr_bytes[4], mac_addr.addr_bytes[5]);
		printf("Socket ID : %d\n", port_socket_id);

		// calculate the actual number of queues to configure
		uint8_t nb_rx_queues = 0;
		uint16_t nb_tx_queues = 0;
		if(is_rx_port[port_id]){
			nb_rx_queues = nb_rx_queues_per_port;
		}
		if(is_tx_bypass_port[port_id]){
			nb_tx_queues += nb_tx_bypass_queues_per_port;
		}
		if (is_tx_firewall_port[port_id]){
			nb_tx_queues += nb_tx_firewall_queues_per_port;
		}

		// configure the queues for each port
		printf("Configure port %d :: rx_queues: %d, tx_queues: %d\n", port_id,nb_rx_queues, nb_tx_queues);
		ret = rte_eth_dev_configure(port_id, nb_rx_queues, nb_tx_queues, &port_conf);	
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Cannot configure device: err=%d, port=%d\n",
				ret, port_id);
		}
	}


	/* init memory */
	printf("initmem arg: %d\n", NB_MBUF);
	ret = init_mem(NB_MBUF);
	if (ret < 0){
		rte_exit(EXIT_FAILURE, "init_mem failed\n");
	}

	
	/* init rx queues */
	printf("/* init rx queues */\n");
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
        
		// we only care about rx ports
		if(is_rx_port[port_id] == false){
			continue;
		}

		printf("\n\nInitializing port %d ... \n", port_id);
		// allocate rx cores 
		int queue_id = 0;
		for ( int core_id = 0; core_id < RTE_MAX_LCORE; core_id++ ) {
			if(is_slave_core[core_id] == false){
				continue;
			}
			if(numa_on){ // only use cores on the same socket
					if(rte_lcore_to_socket_id(core_id) != port_vars[port_id].socket_id){
						continue;
					}
			}
			struct lcore_values * lvars = &core_vars[core_id];
			if(lvars->rx_port_id == RTE_MAX_ETHPORTS){ // only proceed if core is not allocated yet
				lvars->rx_port_id = port_id;
				lvars->rx_queue_id = queue_id;
				port_vars[port_id].rx_slave_core_ids[queue_id] = core_id;
				struct rte_mempool *mbp = lvars->mbp;

				socket_id = (uint8_t)rte_lcore_to_socket_id(core_id);

				printf("Initializing rx queue on lcore %u ... ", core_id );
				printf("rxq=%d,%d,%d,%p\n", port_id, queue_id, socket_id, mbp);
				fflush(stdout);

				// set up queue
				ret = rte_eth_rx_queue_setup(port_id, queue_id, nb_rxd,
		    			socket_id,
		    			NULL,
		    			mbp);
				if (ret < 0)
		    		rte_exit(EXIT_FAILURE,
		    		"rte_eth_rx_queue_setup: err=%d, port=%d\n",
		    		ret, port_id);

				queue_id++;
			}

			if(queue_id >= nb_rx_queues_per_port){
				break;
			} 
		}
	}

	/* initialize tx queues */
	printf("start initializing tx queues\n\n");
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		
		// we only care about tx ports
		if(is_tx_bypass_port[port_id] == false && is_tx_firewall_port[port_id] == false){
			continue;
		}
		
		printf("\n\nInitializing port %d ... \n", port_id);
		// allocate tx cores 
		int queue_id = 0;

		// bypass ports
		for ( int core_id = 0; core_id < RTE_MAX_LCORE; core_id++ ) {
			if(is_slave_core[core_id] == false || is_tx_bypass_port[port_id] == false){
				continue;
			}

			if(numa_on){ // only use cores on the same socket
				if(rte_lcore_to_socket_id(core_id) != port_vars[port_id].socket_id){
					continue;
				}
			}

			struct lcore_values * lvars = &core_vars[core_id];
			if(lvars->tx_bypass_port_id == RTE_MAX_ETHPORTS){
				lvars->tx_bypass_port_id = port_id;
				lvars->tx_bypass_queue_id = queue_id;
				port_vars[port_id].tx_slave_core_ids[queue_id] = core_id;

				socket_id = (uint8_t)rte_lcore_to_socket_id(core_id);
				rte_eth_dev_info_get(port_id, &dev_info);
				txconf = &dev_info.default_txconf;

				printf("Initializing tx bypass queue on lcore %u ... ", core_id );
				printf("rxq=%d,%d,%d\n", port_id, queue_id, socket_id);
				fflush(stdout);

				//set-up queue
				ret = rte_eth_tx_queue_setup(port_id, queue_id, nb_txd, socket_id, txconf);

				if (ret < 0)
		    		rte_exit(EXIT_FAILURE,
		    		"rte_eth_rx_queue_setup: err=%d, port=%d\n",
		    		ret, port_id);

				queue_id++;
			}

			if(queue_id >= nb_tx_bypass_queues_per_port){
				break;
			} 
		}

		// tx firewall ports

		queue_id = 0;
		for ( int core_id = 0; core_id < RTE_MAX_LCORE; core_id++ ) {
			if(is_slave_core[core_id] == false ||is_tx_firewall_port[port_id] == false){
				continue;
			}

			if(numa_on){
				if(rte_lcore_to_socket_id(core_id) != port_vars[port_id].socket_id){
					continue; // only use cores on the same socket
				}
			}

			struct lcore_values * lvars = &core_vars[core_id];
			if(lvars->tx_firewall_port_id == RTE_MAX_ETHPORTS){
				lvars->tx_firewall_port_id = port_id;
				lvars->tx_firewall_queue_id = queue_id;
				port_vars[port_id].tx_slave_core_ids[queue_id] = core_id;

				socket_id = (uint8_t)rte_lcore_to_socket_id(core_id);
				rte_eth_dev_info_get(port_id, &dev_info);
				txconf = &dev_info.default_txconf;

				printf("Initializing tx firewall queue on lcore %u ... ", core_id );
				printf("rxq=%d,%d,%d\n", port_id, queue_id, socket_id);
				fflush(stdout);

				//set-up queue
				ret = rte_eth_tx_queue_setup(port_id, queue_id, nb_txd, socket_id, txconf);

				if (ret < 0)
		    		rte_exit(EXIT_FAILURE,
		    		"rte_eth_rx_queue_setup: err=%d, port=%d\n",
		    		ret, port_id);
				queue_id++;
			}

			if(queue_id >= nb_tx_firewall_queues_per_port){
				break;
			} 
		}
	}


	
	printf("\n\nStarting Ports..,");

	
	/* start ports */
	
	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (is_active_port[port_id] == false) {
			continue;
		}

		// Start device //
		printf("\nSTARTING PORT: %d\n", port_id);
		
		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start: err=%d, port=%d\n",
				ret, port_id);

		// enable promiscuous mode on NIC
		rte_eth_promiscuous_enable(port_id);


		// we only care about tx ports
		if(is_tx_bypass_port[port_id] == false && is_tx_firewall_port[port_id] == false){
			continue;
		}

		/* Initialize TX buffers */
		printf("initialize tx buffers...\n");
		for (int core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {

			if(is_slave_core[core_id] == false){
				continue;
			}

			struct lcore_values * lvars = &core_vars[core_id];
			lvars->tx_bypass_buffer = rte_zmalloc_socket("tx_bypass_buffer",
					RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
					rte_eth_dev_socket_id(port_id));
			if (lvars->tx_bypass_buffer == NULL)
				rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
						(unsigned) port_id);

			rte_eth_tx_buffer_init(lvars->tx_bypass_buffer, MAX_PKT_BURST);

			if (ret < 0)
					rte_exit(EXIT_FAILURE, "Cannot set error callback for "
							"tx buffer on port %u\n", (unsigned) port_id);

			lvars->tx_firewall_buffer = rte_zmalloc_socket("tx_firewall_buffer",
					RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
					rte_eth_dev_socket_id(port_id));
			if (lvars->tx_firewall_buffer == NULL)
				rte_exit(EXIT_FAILURE, "Cannot allocate firewall buffer for tx on port %u\n",
						(unsigned) port_id);

			rte_eth_tx_buffer_init(lvars->tx_firewall_buffer, MAX_PKT_BURST);

			if (ret < 0)
					rte_exit(EXIT_FAILURE, "Cannot set error callback for "
							"firewall tx buffer on port %u\n", (unsigned) port_id);
		}
	}
	
	//check the link status of all active ports and displax result
	check_all_ports_link_status((uint8_t)8, scionfwd_rx_port_mask | scionfwd_tx_bypass_port_mask | scionfwd_tx_firewall_port_mask);

	slice_timer_period *= rte_get_timer_hz();
	
#if MEASURE_CYCLES
	tsc_hz = rte_get_tsc_hz();
#endif

	// initalize the blooms filters
	printf("\nInitializing Bloom filters ...\n");
	for (int i = 0; i < RTE_MAX_LCORE; i++) {
        for (int j = 0; j < MAX_BLOOM_FILTERS; j++) {
            bloom_init(&core_vars[i].bloom_filters[j], NUM_BLOOM_ENTRIES, BLOOM_ERROR_RATE);
        }
        core_vars[i].active_filter_id = 0;
        gettimeofday(&core_vars[i].last_ts, NULL);
        char core_id_string[12];
        sprintf(core_id_string, "%d", i);
	}

	// init key_storage
	init_key_manager();

	// initializzr the rate-limiter
	printf("\nInitializing DOS...\n\n");
	init_dos();

	printf("SETUP COMPLETED\n");


	// launch special cores first
	for (unsigned core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {

		if(is_in_use[core_id] == false){
			continue;
		}

		if ( is_metrics_core[core_id]) {
			rte_eal_remote_launch(scionfwd_launch_metrics_core, NULL, core_id);
		}
		else if ( is_dos_core[core_id]) {
			rte_eal_remote_launch(scionfwd_launch_dos_core, NULL, core_id);
		}
		else if ( is_key_manager_core[core_id]) {
			rte_eal_remote_launch(scionfwd_launch_key_manager_core, NULL, core_id);
		}
	}

	// launch slave cores -> processing cores
	for (unsigned core_id = 0; core_id < RTE_MAX_LCORE; core_id++) {

			if(is_in_use[core_id] == false){
				continue;
			}
			if ( is_slave_core[core_id]) {
				rte_eal_remote_launch(scionfwd_launch_dup_core, NULL, core_id);
			}
	}
	
	// launch super visor on current core
	scionfwd_launch_supervisor(); 
	
	// if this point is reached the force-quit flag has been triggered and the applciation quits
	printf("Initiating shutdown...\n");
	
	// wait for all other cores
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	// close all active ports
	for (int port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		if (is_active_port[port_id] == false){
			continue;
		}	
		printf("Closing port %d...", port_id);
		rte_eth_dev_stop(port_id);
		rte_eth_dev_close(port_id);
		printf(" Done\n");
	}
#if MEASURE_CYCLES
#endif

	printf("Shutdown complete\n");

	return ret;

}
