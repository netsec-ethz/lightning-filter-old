#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void cmd_arg_correct(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	int argc = 3;
	const char *argv[3] = { "./build/scionfwd","-r", "0x36" };


	res = scionfwd_parse_args(argc, argv);
	assert_true(res != -1);
}

static void cmd_arg_wrong(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	int argc = 3;
	const char *argv[3] = { "./build/scionfwd","-q", "0x36" };


	res = scionfwd_parse_args(argc, argv);
	assert_true(res == -1);
}

static void cmd_arg_port_masks(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	int argc = 7;
	const char *argv[7] = { "./build/scionfwd","-r", "0x36", "-x", "0x36", "-y", "0x36" };


	res = scionfwd_parse_args(argc, argv);
	assert_true(res != -1);
	assert_true(scionfwd_rx_port_mask != 0);
	assert_true(scionfwd_tx_bypass_port_mask != 0);
	assert_true(scionfwd_tx_firewall_port_mask != 0);
}

static void cmd_arg_port_numbers(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	int argc = 11;
	const char *argv[11] = { "./build/scionfwd","-S", "5", "-K", "1", "-E", "1000", "-R", "1000", "-D", "1000" };


	res = scionfwd_parse_args(argc, argv);
	assert_true(res != -1);

	assert_true(slice_timer_period_seconds == 5);
	assert_true(KEY_GRACE_PERIOD == 1);
	assert_true(NUM_BLOOM_ENTRIES == 1000);
	assert_true(BLOOM_ERROR_RATE == 1000);
	assert_true(delta_us == 1000);

}

static void cmd_arg_invalid_time(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	int argc = 7;
	const char *argv[7] = { "./build/scionfwd","-S", "-5"};


	res = scionfwd_parse_args(argc, argv);
	assert_true(res == -1);
}

static void cmd_arg_flags(void **state)
{
	if(state == NULL){
		state = NULL;
	}
	int res;
	int argc = 6;
	const char *argv[6] = { "./build/scionfwd","-i", "-l", "-n", "-S", "5"};


	res = scionfwd_parse_args(argc, argv);

	assert_true(res != -1);
	assert_true(is_interactive == 0);
	assert_true(from_config_enabled);
	assert_true(numa_on);


}
