#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
  assert(argc >= 1);
  printf("Testing %s: ", argv[0]);
  fflush(stdout);
  assert(true);
  printf("done\n");
  exit(EXIT_SUCCESS);
}
