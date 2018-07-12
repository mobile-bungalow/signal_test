#include <signal/signal_protocol.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>
#include "uthash.h"

int
identity_key_store_get_identity_key_pair(signal_buffer **public_data, signal_buffer **private_data, void *user_data);

int
identity_key_store_get_local_registration_id(void *user_data, uint32_t *registration_id);

int
identity_key_store_save_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);

int
identity_key_store_is_trusted_identity(const signal_protocol_address *address, uint8_t *key_data, size_t key_len, void *user_data);

void
identity_key_store_destroy(void *user_data);


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
