#include <assert.h>
#include <string.h>

#include "lf_crypto.h"

#define LF_CRYPTO_CBCMAC_IV_LENGTH 16

void lf_crypto_cbcmac(EVP_CIPHER_CTX *ctx, unsigned char key[LF_CRYPTO_CBCMAC_KEY_LENGTH],
	void *data, size_t data_len, unsigned char mac[LF_CRYPTO_CBCMAC_BLOCK_SIZE]) {
	const EVP_CIPHER *cipher = EVP_aes_128_cbc();
	assert(EVP_CIPHER_block_size(cipher) == LF_CRYPTO_CBCMAC_BLOCK_SIZE);
	assert(EVP_CIPHER_key_length(cipher) == LF_CRYPTO_CBCMAC_KEY_LENGTH);
	assert(EVP_CIPHER_iv_length(cipher) == LF_CRYPTO_CBCMAC_IV_LENGTH);
	unsigned char iv[LF_CRYPTO_CBCMAC_IV_LENGTH];
	(void)memset(iv, 0, LF_CRYPTO_CBCMAC_IV_LENGTH);
	(void)memset(mac, 0, LF_CRYPTO_CBCMAC_BLOCK_SIZE);
	assert(data_len % LF_CRYPTO_CBCMAC_BLOCK_SIZE == 0);
	size_t i = 0;
	while (i != data_len) {
		int r = EVP_CIPHER_CTX_reset(ctx);
		assert(r == 1);
		r = EVP_EncryptInit(ctx, cipher, key, iv);
		assert(r == 1);
		r = EVP_CIPHER_CTX_set_padding(ctx, 0);
		assert(r == 1);
		unsigned char block[LF_CRYPTO_CBCMAC_BLOCK_SIZE];
		size_t j = 0;
		do {
			block[j] = ((unsigned char *)data)[i] ^ mac[j];
			i++;
			j++;
		} while (j != LF_CRYPTO_CBCMAC_BLOCK_SIZE);
		int n;
		r = EVP_EncryptUpdate(ctx, mac, &n, block, LF_CRYPTO_CBCMAC_BLOCK_SIZE);
		assert((r == 1) && (n == LF_CRYPTO_CBCMAC_BLOCK_SIZE));
		r = EVP_EncryptFinal(ctx, mac, &n);
		assert((r == 1) && (n == 0));
	}
}
