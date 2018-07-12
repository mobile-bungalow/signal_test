/*
 * author: Paul May
 */
#include <signal/signal_protocol.h>
#include <signal/key_helper.h>
#include <pthread.h>
#include <math.h>
#include <time.h>
#include <pthread.h>
#include "session.h"
#include "crypto_provider.h"
#include "pre_key.h"
#include "signed_pre_key.h"
#include "identity_key.h"


pthread_mutex_t global_mutex;

void
lock(void *user_data)
{
    pthread_mutex_lock(&global_mutex);
}

void
unlock(void *user_data)
{
    pthread_mutex_unlock(&global_mutex);
}

static signal_protocol_address addr = {
	"+15104576818", 12, 1
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

	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}

	result = signal_context_set_locking_functions(global_context,lock,unlock);



	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}

	printf("everything initialized okay.\n");

	ratchet_identity_key_pair *identity_key_pair;
	uint32_t registration_id;
	signal_protocol_key_helper_pre_key_list_node *pre_keys_head;
	session_signed_pre_key *signed_pre_key;

	result = signal_protocol_key_helper_generate_identity_key_pair
	(&identity_key_pair, global_context);

	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}

   result = signal_protocol_key_helper_generate_registration_id
	(&registration_id, 0, global_context);


	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}

  result = signal_protocol_key_helper_generate_pre_keys
	(&pre_keys_head, 1, 1, global_context);


	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}


	int64_t timestamp = (unsigned long)time(NULL);

	result = signal_protocol_key_helper_generate_signed_pre_key
	(&signed_pre_key, identity_key_pair, 5, timestamp, global_context);


	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}


	signal_protocol_store_context *store_context;

result =	signal_protocol_store_context_create
	(&store_context, global_context);

	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}

	signal_protocol_session_store session_store = {
		 .load_session_func = session_store_load_session,
		 .get_sub_device_sessions_func = session_store_get_sub_device_sessions,
		 .store_session_func = session_store_store_session,
		 .contains_session_func = session_store_contains_session,
		 .delete_session_func = session_store_delete_session,
		 .delete_all_sessions_func = session_store_delete_all_sessions,
		 .destroy_func = session_store_destroy,
		 .user_data = user_data
 };

result =	signal_protocol_store_context_set_session_store
	(store_context, &session_store);

	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}

	signal_protocol_pre_key_store pre_key_store = {
		.load_pre_key = pre_key_store_load_pre_key,
		.store_pre_key = pre_key_store_store_pre_key,
		.contains_pre_key = pre_key_store_contains_pre_key,
		.remove_pre_key = pre_key_store_remove_pre_key,
		.destroy_func = pre_key_store_destroy,
		.user_data = user_data
};

	result = signal_protocol_store_context_set_pre_key_store
	(store_context, &pre_key_store);


		if(result != 0)
		{
			printf("fuck\n");
			return 1;
		}


	 signal_protocol_signed_pre_key_store spk_store = {
		    .load_signed_pre_key = signed_pre_key_store_load_signed_pre_key,
		    .store_signed_pre_key = signed_pre_key_store_store_signed_pre_key,
		    .contains_signed_pre_key = signed_pre_key_store_contains_signed_pre_key,
        .remove_signed_pre_key = signed_pre_key_store_remove_signed_pre_key,
        .destroy_func = signed_pre_key_store_destroy,
		    .user_data = user_data
		};

	result = signal_protocol_store_context_set_signed_pre_key_store
	(store_context, &spk_store);

	if(result != 0)
	{
		printf("fuck\n");
		return 1;
	}

	identity_store_data *data = malloc(sizeof(identity_store_data));
  memset(data, 0, sizeof(identity_store_data));

  ec_key_pair *identity_key_pair_keys = 0;
  curve_generate_key_pair(global_context, &identity_key_pair_keys);

  ec_public_key *identity_key_public = ec_key_pair_get_public(identity_key_pair_keys);
  ec_private_key *identity_key_private = ec_key_pair_get_private(identity_key_pair_keys);

  ec_public_key_serialize(&data->identity_key_public, identity_key_public);
  ec_private_key_serialize(&data->identity_key_private, identity_key_private);
  SIGNAL_UNREF(identity_key_pair_keys);

  data->local_registration_id = (rand() % 16380) + 1;

  signal_protocol_identity_key_store identity_key_store = {
				.get_identity_key_pair = identity_key_store_get_identity_key_pair,
				.get_local_registration_id = identity_key_store_get_local_registration_id,
				.save_identity = identity_key_store_save_identity,
				.is_trusted_identity = identity_key_store_is_trusted_identity,
				.destroy_func = identity_key_store_destroy,
				.user_data = data
};

		result = signal_protocol_store_context_set_identity_key_store
  (store_context, &identity_key_store);

	if(result != 0)
	{
		printf("problem with identity_key\n");
		return 1;
	}

}
