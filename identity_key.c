#include <signal/signal_protocol.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>
#include "uthash.h"

typedef struct {
    int64_t recipient_id;
    signal_buffer *identity_key;
    UT_hash_handle hh;
} identity_store_key;

typedef struct {
    identity_store_key *keys;
    signal_buffer *identity_key_public;
    signal_buffer *identity_key_private;
    uint32_t local_registration_id;
} identity_store_data;

int identity_key_store_get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data)
{
    identity_store_data *data = user_data;
    *public_data = signal_buffer_copy(data->identity_key_public);
    *private_data = signal_buffer_copy(data->identity_key_private);
    return 0;
}

int identity_key_store_get_local_registration_id(void *user_data, uint32_t *registration_id)
{
    identity_store_data *data = user_data;
    *registration_id = data->local_registration_id;
    return 0;
}

int identity_key_store_save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    identity_store_data *data = user_data;

    identity_store_key *s;

    signal_buffer *key_buf = signal_buffer_create(key_data, key_len);
    if(!key_buf) {
        return SG_ERR_NOMEM;
    }

    int64_t recipient_hash = jenkins_hash(address->name, address->name_len);

    HASH_FIND(hh, data->keys, &recipient_hash, sizeof(int64_t), s);
    if(s) {
        signal_buffer_free(s->identity_key);
        s->identity_key = key_buf;
    }
    else {
        s = malloc(sizeof(identity_store_key));
        if(!s) {
            signal_buffer_free(key_buf);
            return SG_ERR_NOMEM;
        }
        memset(s, 0, sizeof(identity_store_key));
        s->recipient_id = recipient_hash;
        s->identity_key = key_buf;
        HASH_ADD(hh, data->keys, recipient_id, sizeof(int64_t), s);
    }

    return 0;
}

int identity_key_store_is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data)
{
    identity_store_data *data = user_data;

    int64_t recipient_hash = jenkins_hash(address->name, address->name_len);

    identity_store_key *s;
    HASH_FIND(hh, data->keys, &recipient_hash, sizeof(int64_t), s);

    if(s) {
        uint8_t *store_data = signal_buffer_data(s->identity_key);
        size_t store_len = signal_buffer_len(s->identity_key);
        if(store_len != key_len) {
            return 0;
        }
        if(memcmp(key_data, store_data, key_len) == 0) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else {
        return 1;
    }
}

void identity_key_store_destroy(void *user_data)
{
    identity_store_data *data = user_data;

    identity_store_key *cur_node;
    identity_store_key *tmp_node;
    HASH_ITER(hh, data->keys, cur_node, tmp_node) {
        HASH_DEL(data->keys, cur_node);
        signal_buffer_free(cur_node->identity_key);
        free(cur_node);
    }
    signal_buffer_free(data->identity_key_public);
    signal_buffer_free(data->identity_key_private);
    free(data);
}

void setup_identity_key_store(signal_protocol_store_context *context, signal_context *global_context)
{
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

    signal_protocol_identity_key_store store = {
            .get_identity_key_pair = identity_key_store_get_identity_key_pair,
            .get_local_registration_id = identity_key_store_get_local_registration_id,
            .save_identity = identity_key_store_save_identity,
            .is_trusted_identity = identity_key_store_is_trusted_identity,
            .destroy_func = identity_key_store_destroy,
            .user_data = data
    };

    signal_protocol_store_context_set_identity_key_store(context, &store);
}
