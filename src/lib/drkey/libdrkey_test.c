#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/time.h>

#include "libdrkey.h"

struct delegation_secret {
  int64_t validity_not_before;
  int64_t validity_not_after;
  unsigned char key[16];
};

static int32_t get_isd_num(char *str, size_t length) {
  int32_t isd_num;
  if (length == 0) {
    isd_num = -1;
  } else {
    isd_num = 0;
    size_t i = 0;
    do {
      int x = str[i];
      if (('0' <= x) && (x <= '9')) {
        x = x - '0';
        if (isd_num <= (65535 - x) / 10) {
          isd_num = 10 * isd_num + x;
        } else {
          isd_num = -1;
        }
      } else {
        isd_num = -1;
      }
      i++;
    } while ((isd_num >= 0) && (i != length));
  }
  return isd_num;
}

static int64_t get_bgp_as_num(char *str, size_t length) {
  int64_t as_num;
  if (length == 0) {
    as_num = -1;
  } else {
    as_num = 0;
    size_t i = 0;
    do {
      int x = str[i];
      if (('0' <= x) && (x <= '9')) {
        x = x - '0';
        if (as_num <= (4294967295 - x) / 10) {
          as_num = 10 * as_num + x;
        } else {
          as_num = -1;
        }
      } else {
        as_num = -1;
      }
      i++;
    } while ((as_num >= 0) && (i != length));
  }
  return as_num;
}

static int32_t get_as_num_part(char *str, size_t length) {
  int32_t as_num_part;
  if ((length == 0) || (length > 4)) {
    as_num_part = -1;
  } else {
    as_num_part = 0;
    size_t i = 0;
    do {
      int x = str[i];
      if (('0' <= x) && (x <= '9')) {
        as_num_part = (as_num_part << 4) | (x - '0');
      } else if (('A' <= x) && (x <= 'F')) {
        as_num_part = (as_num_part << 4) | (x - 'A' + 10);
      } else if (('a' <= x) && (x <= 'f')) {
        as_num_part = (as_num_part << 4) | (x - 'a' + 10);
      } else {
        as_num_part = -1;
      }
      i++;
    } while ((as_num_part >= 0) && (i != length));
  }
  return as_num_part;
}

static int get_isd_as_num(char *iastr, int64_t *val) {
  size_t i = 0;
  size_t j = 0;
  while ((iastr[j] != '\0') && (iastr[j] != '-')) {
    j++;
  }
  if (iastr[j] == '\0') {
    return -1;
  }
  int64_t isd = get_isd_num(&iastr[i], j - i);
  if (isd < 0) {
    return -1;
  }
  j++;
  i = j;
  while ((iastr[j] != '\0') && (iastr[j] != ':')) {
    j++;
  }
  int64_t as;
  if (iastr[j] == '\0') {
    as = get_bgp_as_num(&iastr[i], j - i);
    if (as < 0) {
      return -1;
    }
  } else {
    int64_t as0 = get_as_num_part(&iastr[i], j - i);
    if (as0 < 0) {
      return -1;
    }
    j++;
    i = j;
    while ((iastr[j] != '\0') && (iastr[j] != ':')) {
      j++;
    }
    if (iastr[j] == '\0') {
      return -1;
    }
    int64_t as1 = get_as_num_part(&iastr[i], j - i);
    if (as1 < 0) {
      return -1;
    }
    j++;
    i = j;
    while (iastr[j] != '\0') {
      j++;
    }
    int64_t as2 = get_as_num_part(&iastr[i], j - i);
    if (as2 < 0) {
      return -1;
    }
    as = (as0 << 32) | (as1 << 16) | as2;
  }
  *val = (isd << 48) | as;
  return 0;
}

int main(int argc, char *argv[]) {
  int r;

  if (argc != 7) {
    exit(EXIT_FAILURE);
  }
  if (strcmp(argv[1], "-sciond") != 0) {
    exit(EXIT_FAILURE);
  }
  char *sciond = argv[2];
  if (strcmp(argv[3], "-src-ia") != 0) {
    exit(EXIT_FAILURE);
  }
  int64_t src_ia;
  r = get_isd_as_num(argv[4], &src_ia);
  if (r != 0) {
    assert(r == -1);
    exit(EXIT_FAILURE);
  }
  if (strcmp(argv[5], "-dst-ia") != 0) {
    exit(EXIT_FAILURE);
  }
  int64_t dst_ia;
  r = get_isd_as_num(argv[6], &dst_ia);
  if (r != 0) {
    assert(r == -1);
    exit(EXIT_FAILURE);
  }

  struct timeval tv;
  r = gettimeofday(&tv, NULL);
  if (r != 0) {
    assert(r == -1);
    printf("Syscall gettimeofday failed.\n");
    exit(EXIT_FAILURE);
  }
  assert((INT64_MIN <= tv.tv_sec) && (tv.tv_sec <= INT64_MAX));
  int64_t t_now = tv.tv_sec;

  struct delegation_secret ds;

  memset(&ds, 0, sizeof ds);

  assert(sizeof ds.validity_not_before == sizeof(GoInt64));
  assert(sizeof ds.validity_not_after == sizeof(GoInt64));
  /* clang-format off */
  r = GetDelegationSecret(
    sciond, src_ia, dst_ia, t_now,
    (GoInt64 *)&ds.validity_not_before,
    (GoInt64 *)&ds.validity_not_after,
    ds.key);
  /* clang-format on */
  if (r != 0) {
    assert(r == -1);
    printf("GetDelegationSecret failed.\n");
    exit(EXIT_FAILURE);
  }

  printf("DS key = ");
  for (size_t i = 0; i < sizeof ds.key; i++) {
    printf("%02x", ds.key[i]);
  }
  printf(", epoch = [");
  struct tm *gmt;
  gmt = gmtime((time_t *)&ds.validity_not_before);
  if (gmt != NULL) {
    /* clang-format off */
    printf("%04d-%02d-%02d'T'%02d:%02d:%02d'Z'",
      1900 + gmt->tm_year, 1 + gmt->tm_mon, gmt->tm_mday,
      gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
    /* clang-format on */
  }
  printf(", ");
  gmt = gmtime((time_t *)&ds.validity_not_after);
  if (gmt != NULL) {
    /* clang-format off */
    printf("%04d-%02d-%02d'T'%02d:%02d:%02d'Z'",
      1900 + gmt->tm_year, 1 + gmt->tm_mon, gmt->tm_mday,
      gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
    /* clang-format on */
  }
  printf("]\n");
}

/*
cc -o libdrkey_test -Wall -Werror libdrkey_test.c -L . -ldrkey -lpthread
*/
