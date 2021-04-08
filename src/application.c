#define RUN_UNIT_TESTS 0

#if RUN_UNIT_TESTS
	// Building unit tests is currently not supported.
	// #include "scionfwd.c"
	// #include "../test/unit_test_main.c"
#else
	int scion_filter_main(int argc, char **argv);
#endif

int main(int argc, char **argv) {
	#if RUN_UNIT_TESTS
		(void)argc; (void)argv;
		// int res = unit_test_main();
		// printf("%d tests have failed\n\n" ,res);
	#else
		scion_filter_main(argc, argv);
	#endif
}
