#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <signal/signal_protocol.h>

int
random_generator(uint8_t *data, size_t len, void *user_data);

int
hmac_sha256_init(void **hmac_context, const uint8_t *key,
                      size_t key_len, void *user_data);

int
hmac_sha256_update(void *hmac_context, const uint8_t *data, size_t data_len,
                   void *user_data);

int
hmac_sha256_final(void *hmac_context, signal_buffer **output, void *user_data);

void
hmac_sha256_cleanup(void *hmac_context, void *user_data);


void
sha512_digest_cleanup(void *digest_context, void *user_data);

int
sha512_digest_init(void **digest_context, void *user_data);

int
sha512_digest_update(void *digest_context, const uint8_t *data,
                              size_t data_len, void *user_data);

int
sha512_digest_final(void *digest_context, signal_buffer **output,
                              void *user_data);

void
sha512_digest_cleanup(void *digest_context, void *user_data);

int
encrypt(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *plaintext, size_t plaintext_len,
        void *user_data);

int
decrypt(signal_buffer **output,
        int cipher,
        const uint8_t *key, size_t key_len,
        const uint8_t *iv, size_t iv_len,
        const uint8_t *ciphertext, size_t ciphertext_len,
        void *user_data);
