// Measures the performance of CBCMAC and a CMAC implementation in C

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>

#include "../aesni.h"


#if (INT_MAX != 0x7fffffff)
#error -- Assumes 4-byte int
#endif


/////////////////////////////////////////////////

#define AES_128 0
unsigned char const_Rb[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};
unsigned char const_Zero[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static void xor_128(unsigned char *a, unsigned char *b, unsigned char *out)
{
    int i;
    for (i=0;i<16; i++)
    {
	out[i] = a[i] ^ b[i];
    }
}

/* AES-CMAC Generation Function */

static void leftshift_onebit(unsigned char *input,unsigned char *output)
{
    int i;
    unsigned char overflow = 0;

    for ( i=15; i>=0; i-- )
    {
	output[i] = input[i] << 1;
	output[i] |= overflow;
	overflow = (input[i] & 0x80)?1:0;
    }
}

static void generate_subkey(unsigned char *key, unsigned char *K1, unsigned char *K2)
{
    unsigned char L[16];
    unsigned char Z[16];
    unsigned char tmp[16];
    int i;

    for ( i=0; i<16; i++ ) Z[i] = 0;

    //CBCMAC(Z, L, key, 1);
	CBCMAC(key, 1, Z, L);

    if ( (L[0] & 0x80) == 0 ) /* If MSB(L) = 0, then K1 = L << 1 */
    {
	leftshift_onebit(L,K1);
    } else {    /* Else K1 = ( L << 1 ) (+) Rb */
	leftshift_onebit(L,tmp);
	xor_128(tmp,const_Rb,K1);
    }

    if ( (K1[0] & 0x80) == 0 )
    {
	leftshift_onebit(K1,K2);
    } else {
	leftshift_onebit(K1,tmp);
	xor_128(tmp,const_Rb,K2);
    }
}

static void padding ( unsigned char *lastb, unsigned char *pad, int length )
{
    int j;

    /* original last block */
    for ( j=0; j<16; j++ )
    {
	if ( j < length )
	{
	    pad[j] = lastb[j];
	} else if ( j == length ) {
	    pad[j] = 0x80;
	} else {
	    pad[j] = 0x00;
	}
    }
}
////////////////////////////////////////////////////////

void AES_CMAC ( unsigned char *rk, unsigned char *input, int length, unsigned char *mac )
{
    unsigned char X[16],Y[16], M_last[16], padded[16];
    unsigned char K1[16], K2[16];
    int n, i, flag;
    generate_subkey(rk,K1,K2);

    n = (length+15) / 16;       /* n is number of rounds */

    if ( n == 0 )
    {
	n = 1;
	flag = 0;
    } else {
	if ( (length%16) == 0 ) { /* last block is a complete block */
	    flag = 1;
	} else { /* last block is not complete block */
	    flag = 0;
	}

    }

    if ( flag ) { /* last block is complete block */
	xor_128(&input[16*(n-1)],K1,M_last);
    } else {
	padding(&input[16*(n-1)],padded,length%16);
	xor_128(padded,K2,M_last);
    }

    for ( i=0; i<16; i++ ) X[i] = 0;
    for ( i=0; i<n-1; i++ )
    {
	xor_128(X,&input[16*i],Y); /* Y := Mi (+) X  */
	//CBCMAC(Y, X, rk, 1); /* X := AES-128(KEY, Y); */
    CBCMAC(rk,1,Y,X);
    }

    xor_128(X,M_last,Y);
    //CBCMAC(Y, X, rk, 1);
    CBCMAC(rk,1,Y,X);

    for ( i=0; i<16; i++ ) {
	mac[i] = X[i];
    }
}


//////////////










void *malloc_aligned(size_t alignment, size_t bytes)
{
    const size_t total_size = bytes + (2 * alignment) + sizeof(size_t);

    // use malloc to allocate the memory.
    char *data = malloc(sizeof(char) * total_size);

    if (data)
    {
        // store the original start of the malloc'd data.
        const void * const data_start = data;

        // dedicate enough space to the book-keeping.
        data += sizeof(size_t);

        // find a memory location with correct alignment. the alignment minus
        // the remainder of this mod operation is how many bytes forward we need
        // to move to find an aligned byte.
        const size_t offset = alignment - (((size_t)data) % alignment);

        // set data to the aligned memory.
        data += offset;

        // write the book-keeping.
        size_t *book_keeping = (size_t*)(data - sizeof(size_t));
        *book_keeping = (size_t)data_start;
    }

    return data;
}

void free_aligned(void *raw_data)
{
    if (raw_data)
    {
        char *data = raw_data;

        // we have to assume this memory was allocated with malloc_aligned.
        // this means the sizeof(size_t) bytes before data are the book-keeping
        // which points to the location we need to pass to free.
        data -= sizeof(size_t);

        // set data to the location stored in book-keeping.
        data = (char*)(*((size_t*)data));

        // free the memory.
        free(data);
    }
}

unsigned char* aes_assembly_init(void *enc_key)
{
    if (enc_key != NULL) {
    	unsigned char* roundkey = (unsigned char*)malloc_aligned(16, 10*16*sizeof(char));
    	memset(roundkey, 0, sizeof(10*16*sizeof(char)));
    	ExpandKey128(enc_key, roundkey);
    	return roundkey;
    }
}



int main()
{
	unsigned char key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F}; //"0123456789abcdef";
		
	struct keystruct rk;
	rk.roundkey = aes_assembly_init(key);

	unsigned char input[] = {0x6b,0xc1,0xbe,0xe2, 0x2e,0x40,0x9f,0x96, 0xe9,0x3d,0x7e,0x11, 0x73,0x93,0x17,0x2a};
	unsigned char mac[32];

	unsigned long long t1 = _do_rdtsc();
	int tmp;
	int i;
	for(i=0;i<100000;i++){
		CBCMAC(rk.roundkey, 1, input, mac);
		tmp += mac[2];
	}
	unsigned long long t2 = _do_rdtsc();

	printf("cycle(CBCMAC) = %f\n", (double)(t2-t1)/100000);



	t1 = _do_rdtsc();
	for(i=0;i<100000;i++){
		AES_CMAC ( rk.roundkey, input, 1, mac);
		tmp += mac[2];
	}
	t2 = _do_rdtsc();

	printf("cycle(CMAC) = %f\n", (double)(t2-t1)/100000);


	free_aligned(rk.roundkey);
	return 0;
}

