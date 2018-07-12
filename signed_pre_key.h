#include <signal/signal_protocol.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>
#include "uthash.h"


int
signed_pre_key_store_load_signed_pre_key(signal_buffer **record, uint32_t signed_pre_key_id, void *user_data);

int
 signed_pre_key_store_store_signed_pre_key(uint32_t signed_pre_key_id, uint8_t *record, size_t record_len, void *user_data);

int
signed_pre_key_store_contains_signed_pre_key(uint32_t signed_pre_key_id, void *user_data);

int
signed_pre_key_store_remove_signed_pre_key(uint32_t signed_pre_key_id, void *user_data);

void
signed_pre_key_store_destroy(void *user_data);
