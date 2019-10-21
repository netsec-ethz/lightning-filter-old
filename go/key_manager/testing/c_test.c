#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "go_key_manager.h"

int main() {
    printf("Using test lib from C:\n");

    printf("Start test\n");
    
    uint8_t key_type = 0;
    char* protocol = "scion_filter";
    uint32_t val_time = time(NULL);
    uint64_t srcIA = 1;
    uint64_t dstIA = 6;


    char epoch_b[4];
    char epoch_e[4];
    char srcia[8];
    char dstia[8];
    char DRKey[16];
    uint32_t epoch_begin;
    uint32_t epoch_end;
    uint64_t src_ia;
    uint64_t dst_ia;

    char *ptr = (char *) malloc(40 * sizeof (char));
    int res;
    res = GetLvl1DRKey(key_type, val_time, srcIA, dstIA, ptr);

    char *tmp_ptr = ptr;
    printf("received: ");
    for(int i = 0; i < 40; i++){
        printf("%x",*(tmp_ptr++));
    }
    printf("\n\n");

    epoch_begin = *(uint32_t*)(memcpy(epoch_b, ptr, 4));
    epoch_end = *(uint32_t*)(memcpy(epoch_e, ptr+4, 4));
    src_ia = *(uint64_t*)(memcpy(srcia, ptr+8, 8));
    dst_ia = *(uint64_t*)(memcpy(dstia, ptr+16, 8));
    memcpy(DRKey, ptr+24, 16);
    printf("epoch begin: %u\n", epoch_begin);
    printf("epoch end: %u\n", epoch_end);
    printf("srcIA: %zu\n", src_ia);
    printf("dstIA: %zu\n", dst_ia);

    printf("DRKey: ");
    for(int i = 0; i < 16; i++){
        printf("%c",DRKey[i]);
    }
    printf("\n");
    printf("test complete: %u\n", res);
}
