/*
 * author: Paul May
 */

#include <signal/signal_protocol.h>
#include <pthread.h>
#include <math.h>
#include "crypto_provider.h"

pthread_mutex_t global_mutex;

static signal_protocol_address addr = {
	"+15104576918", 12, 1
};

int main()
{
	signal_context *global_context;

	void* user_data;
	int result;

	result = signal_context_create(&global_context, user_data);

	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}
signal_crypto_provider provider =
{
  .random_func = random_generator,
  .hmac_sha256_init_func =  hmac_sha256_init,
  .hmac_sha256_update_func = hmac_sha256_update,
  .hmac_sha256_final_func = hmac_sha256_final,
  .hmac_sha256_cleanup_func = hmac_sha256_cleanup,
  .sha512_digest_init_func = sha512_digest_init,
  .sha512_digest_update_func = sha512_digest_update,
  .sha512_digest_cleanup_func = sha512_digest_cleanup,
  .encrypt_func = encrypt,
  .decrypt_func = decrypt,
  .user_data = user_data
};
	result = signal_context_set_crypto_provider(global_context, &provider);

}
