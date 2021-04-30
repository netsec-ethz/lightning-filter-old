#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "framework_test.c"
#include "hashdict_test.c"
#include "bloom_filter_test.c"
#include "key_manager_test.c"
#include "cmd_arg_test.c"
#include "cfg_parse_test.c"
#include "packet_handle_test.c"
#include "secX_check_test.c"

int unit_test_main(void);

int unit_test_main(void)
{
	const struct CMUnitTest tests[] = {

		//framework tests
		cmocka_unit_test(test_simple),
		cmocka_unit_test(test_negative),
		cmocka_unit_test(test_null),

		//parse cmd
		cmocka_unit_test(cmd_arg_correct),
		cmocka_unit_test(cmd_arg_wrong),
		cmocka_unit_test(cmd_arg_port_masks),
		cmocka_unit_test(cmd_arg_port_numbers),
		cmocka_unit_test(cmd_arg_invalid_time),
		cmocka_unit_test(cmd_arg_flags),

		cmocka_unit_test(cfg_end_hosts),
		cmocka_unit_test(cfg_end_hosts_too_many),
		cmocka_unit_test(cfg_end_hosts_mismatch),
		cmocka_unit_test(cfg_end_hosts_not_found),
		cmocka_unit_test(cfg_scion_filter),
		cmocka_unit_test(cfg_scion_filter_set_all),

		cmocka_unit_test(test_packet),
		cmocka_unit_test(test_copy_host_addrs),
		cmocka_unit_test(test_derive_lvl2DRKey),
		cmocka_unit_test(test_compute_cmac),


		//bloom filter tests
		cmocka_unit_test(test_bloom_init),
		cmocka_unit_test(test_bloom_free),
		cmocka_unit_test(test_bloom_add),
		cmocka_unit_test(test_bloom_check),
		cmocka_unit_test(test_bloom_add_two_filters),
		cmocka_unit_test(test_bloom_reset_two_filters),

		cmocka_unit_test(test_in_epoch_in),
		cmocka_unit_test(test_in_epoch_out_before),
		cmocka_unit_test(test_in_epoch_out_after),
		cmocka_unit_test(test_in_epoch_border_begin),
		cmocka_unit_test(test_in_epoch_border_end),
		cmocka_unit_test(test_check_and_fetch),
		cmocka_unit_test(test_check_and_fetch_grace_period),
		cmocka_unit_test(test_check_and_fetch_grace_suspicious_short),
		cmocka_unit_test(test_check_and_fetch_grace_suspicious_long),
		cmocka_unit_test(test_fetch_delegation_secret),
		cmocka_unit_test(test_fetch_delegation_secret_mock_AS),
		cmocka_unit_test(test_fetch_delegation_secret_mock_epoch),
		cmocka_unit_test(test_fetch_delegation_secret_mock_key_state),

		// hashdict
        cmocka_unit_test(hashdict_create),
        cmocka_unit_test(hashdict_add_node),
		cmocka_unit_test(hashdict_add_twice),
		cmocka_unit_test(hashdict_find_node),
        cmocka_unit_test(hashdict_delete_node),
		cmocka_unit_test(hashdict_resize),
		cmocka_unit_test(hashdict_full),
    };
	int failed_tests = cmocka_run_group_tests(tests, NULL, NULL);
    return failed_tests;
}
