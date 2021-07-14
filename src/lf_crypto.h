#ifndef LF_CRYPTO_H
#define LF_CRYPTO_H

#include <openssl/evp.h>

#define LF_CRYPTO_CBCMAC_BLOCK_SIZE 16
#define LF_CRYPTO_CBCMAC_KEY_LENGTH 16

void lf_crypto_cbcmac(EVP_CIPHER_CTX *ctx, unsigned char key[LF_CRYPTO_CBCMAC_KEY_LENGTH],
	void *data, size_t data_len, unsigned char mac[LF_CRYPTO_CBCMAC_BLOCK_SIZE]);

#endif
