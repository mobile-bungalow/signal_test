#include <signal/signal_protocol.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>
#include "uthash.h"

typedef struct {
    uint32_t key_id;
    signal_buffer *key_record;
    UT_hash_handle hh;
} pre_key_store_key;

typedef struct {
    pre_key_store_key *keys;
} pre_key_store_data;

int
pre_key_store_load_pre_key(signal_buffer **record, uint32_t pre_key_id, void *user_data)
{
    pre_key_store_data *data = user_data;

    pre_key_store_key *s;

    HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);
    if(s) {
        *record = signal_buffer_copy(s->key_record);
        return SG_SUCCESS;
    }
    else {
        return SG_ERR_INVALID_KEY_ID;
    }
}

int
pre_key_store_store_pre_key(uint32_t pre_key_id, uint8_t *record, size_t record_len, void *user_data)
{
    pre_key_store_data *data = user_data;

    pre_key_store_key *s;

    signal_buffer *key_buf = signal_buffer_create(record, record_len);
    if(!key_buf) {
        return SG_ERR_NOMEM;
    }

    HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);
    if(s) {
        signal_buffer_free(s->key_record);
        s->key_record = key_buf;
    }
    else {
        s = malloc(sizeof(pre_key_store_key));
        if(!s) {
            signal_buffer_free(key_buf);
            return SG_ERR_NOMEM;
        }
        memset(s, 0, sizeof(pre_key_store_key));
        s->key_id = pre_key_id;
        s->key_record = key_buf;
        HASH_ADD(hh, data->keys, key_id, sizeof(uint32_t), s);
    }

    return 0;
}

int
pre_key_store_contains_pre_key(uint32_t pre_key_id, void *user_data)
{
    pre_key_store_data *data = user_data;

    pre_key_store_key *s;
    HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);

    return (s == 0) ? 0 : 1;
}

int
pre_key_store_remove_pre_key(uint32_t pre_key_id, void *user_data)
{
    pre_key_store_data *data = user_data;

    pre_key_store_key *s;
    HASH_FIND(hh, data->keys, &pre_key_id, sizeof(uint32_t), s);
    if(s) {
        HASH_DEL(data->keys, s);
        signal_buffer_free(s->key_record);
        free(s);
    }

    return 0;
}

void
pre_key_store_destroy(void *user_data)
{
    pre_key_store_data *data = user_data;

    pre_key_store_key *cur_node;
    pre_key_store_key *tmp_node;
    HASH_ITER(hh, data->keys, cur_node, tmp_node) {
        HASH_DEL(data->keys, cur_node);
        signal_buffer_free(cur_node->key_record);
        free(cur_node);
    }
    free(data);
}
