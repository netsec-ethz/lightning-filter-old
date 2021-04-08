#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void cmd_arg_correct(void **state)
{
	(void)state;

	int res;
	int argc = 3;
	static char arg0[] = "./build/scionfwd";
	static char arg1[] = "-r";
	static char arg2[] = "0x36";
	char *argv[] = { arg0, arg1, arg2 };

	res = scionfwd_parse_args(argc, argv);

	assert_true(res != -1);
}

static void cmd_arg_wrong(void **state)
{
	(void)state;

	int res;
	int argc = 3;
	static char arg0[] = "./build/scionfwd";
	static char arg1[] = "-q";
	static char arg2[] = "0x36";
	char *argv[] = { arg0, arg1, arg2 };

	res = scionfwd_parse_args(argc, argv);

	assert_true(res == -1);
}

static void cmd_arg_port_masks(void **state)
{
	(void)state;

	scionfwd_rx_port_mask = 0;
	scionfwd_tx_bypass_port_mask = 0;
	scionfwd_tx_firewall_port_mask = 0;

	int res;
	int argc = 7;
	static char arg0[] = "./build/scionfwd";
	static char arg1[] = "-r";
	static char arg2[] = "0x36";
	static char arg3[] = "-x";
	static char arg4[] = "0x36";
	static char arg5[] = "-y";
	static char arg6[] = "0x36";
	char *argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6 };

	res = scionfwd_parse_args(argc, argv);

	assert_true(res != -1);
	assert_true(scionfwd_rx_port_mask == 0x36);
	assert_true(scionfwd_tx_bypass_port_mask == 0x36);
	assert_true(scionfwd_tx_firewall_port_mask == 0x36);
}

static void cmd_arg_port_numbers(void **state)
{
	(void)state;

	slice_timer_period = 0;
	slice_timer_period_seconds = 0;
	KEY_GRACE_PERIOD = 0;
	NUM_BLOOM_ENTRIES = 0;
	BLOOM_ERROR_RATE = 0;
	delta_us = 0;

	int res;
	int argc = 11;
	static char arg0[] = "./build/scionfwd";
	static char arg1[] = "-S";
	static char arg2[] = "5";
	static char arg3[] = "-K";
	static char arg4[] = "1";
	static char arg5[] = "-E";
	static char arg6[] = "1000";
	static char arg7[] = "-R";
	static char arg8[] = "2000";
	static char arg9[] = "-D";
	static char arg10[] = "3000";
	char *argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10 };

	res = scionfwd_parse_args(argc, argv);

	assert_true(res != -1);
	assert_true(slice_timer_period == 5);
	assert_true(slice_timer_period_seconds == 5);
	assert_true(KEY_GRACE_PERIOD == 1);
	assert_true(NUM_BLOOM_ENTRIES == 1000);
	assert_true(BLOOM_ERROR_RATE == 2000);
	assert_true(delta_us == 3000);
}

static void cmd_arg_invalid_time(void **state)
{
	(void)state;

	slice_timer_period = 0;
	slice_timer_period_seconds = 0;

	int res;
	int argc = 7;
	static char arg0[] = "./build/scionfwd";
	static char arg1[] = "-S";
	static char arg2[] = "5";
	static char arg3[] = "";
	static char arg4[] = "";
	static char arg5[] = "";
	static char arg6[] = "";
	char *argv[] = { arg0, arg1, arg2, arg3, arg4, arg5, arg6 };

	res = scionfwd_parse_args(argc, argv);
	assert_true(slice_timer_period == 5);
	assert_true(slice_timer_period_seconds == 5);
	assert_true(res != -1);
}

static void cmd_arg_flags(void **state)
{
	(void)state;

	is_interactive = 0;
	from_config_enabled = false;
	numa_on = false;

	int res;
	int argc = 6;
	static char arg0[] = "./build/scionfwd";
	static char arg1[] = "-i";
	static char arg2[] = "-l";
	static char arg3[] = "-n";
	static char arg4[] = "-S";
	static char arg5[] = "5";
	char *argv[] = { arg0, arg1, arg2, arg3, arg4, arg5 };

	res = scionfwd_parse_args(argc, argv);

	assert_true(res != -1);
	assert_true(is_interactive == 1);
	assert_true(from_config_enabled);
	assert_true(numa_on);
}
