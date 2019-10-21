#include "scionfwd.c"
#include "../test/unit_test_main.c"

int main(int argc, char **argv) {

	int res = unit_test_main();
	printf("%d tests have failed\n\n" ,res);


	//scion_filter_main(argc, argv);
}
