project (tests)

# Include code coverage
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/scripts/cmake)
SET(CMAKE_CXX_FLAGS "-g -O0 -Wall -Werror -Wpedantic -std=c99 -fprofile-arcs -ftest-coverage")
SET(CMAKE_C_FLAGS "-g -O0 -Wall -Werror -Wpedantic -std=c99 -fprofile-arcs -ftest-coverage")
#INCLUDE(CodeCoverage)

include_directories ("../src")
set(TEST_SRCS unit_test.c)
add_executable(unit_test ${TEST_SRCS})
target_link_libraries(unit_test scion_filter_src cmocka --coverage)
add_test(unit_test unit_test)
add_test(test_state_valgrind valgrind
         --error-exitcode=1 --read-var-info=yes
         --leak-check=full --show-leak-kinds=all
         ./unit_test)
