#include <signal/signal_protocol.h>
#include <stdlib.h>
#include <string.h>
#include <check.h>
#include "uthash.h"
typedef struct {
    int64_t recipient_id;
    int32_t device_id;
} session_store_session_key;

typedef struct {
    session_store_session_key key;
    signal_buffer *record;
    UT_hash_handle hh;
} session_store_session;

typedef struct {
    session_store_session *sessions;
} session_store_data;


int64_t jenkins_hash(const char *key, size_t len)
{
    uint64_t hash, i;
    for(hash = i = 0; i < len; ++i) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}


int
session_store_get_sub_device_sessions(signal_int_list **sessions,
    const char *name, size_t name_len, void *user_data)
{
    session_store_data *data = user_data;

    signal_int_list *result = signal_int_list_alloc();
    if(!result) {
        return SG_ERR_NOMEM;
    }

    int64_t recipient_hash = jenkins_hash(name, name_len);
    session_store_session *cur_node;
    session_store_session *tmp_node;
    HASH_ITER(hh, data->sessions, cur_node, tmp_node) {
        if(cur_node->key.recipient_id == recipient_hash) {
            signal_int_list_push_back(result, cur_node->key.device_id);
        }
    }

    *sessions = result;
    return 0;
}

int session_store_load_session(signal_buffer **record, signal_buffer
   **user_record, const signal_protocol_address *address, void *user_data)
{
    session_store_data *data = user_data;

    session_store_session *s;

    session_store_session l;
    memset(&l, 0, sizeof(session_store_session));
    l.key.recipient_id = jenkins_hash(address->name, address->name_len);
    l.key.device_id = address->device_id;
    HASH_FIND(hh, data->sessions, &l.key, sizeof(session_store_session_key), s);

    if(!s) {
        return 0;
    }
    signal_buffer *result = signal_buffer_copy(s->record);
    if(!result) {
        return SG_ERR_NOMEM;
    }
    *record = result;
    return 1;
}


int session_store_store_session(const signal_protocol_address *address,
    uint8_t *record, size_t record_len, uint8_t *user_record_data,
     size_t user_record_len, void *user_data)
{
    session_store_data *data = user_data;

    session_store_session *s;

    session_store_session l;
    memset(&l, 0, sizeof(session_store_session));
    l.key.recipient_id = jenkins_hash(address->name, address->name_len);
    l.key.device_id = address->device_id;

    signal_buffer *record_buf = signal_buffer_create(record, record_len);
    if(!record_buf) {
        return SG_ERR_NOMEM;
    }

    HASH_FIND(hh, data->sessions, &l.key, sizeof(session_store_session_key), s);

    if(s) {
        signal_buffer_free(s->record);
        s->record = record_buf;
    }
    else {
        s = malloc(sizeof(session_store_session));
        if(!s) {
            signal_buffer_free(record_buf);
            return SG_ERR_NOMEM;
        }
        memset(s, 0, sizeof(session_store_session));
        s->key.recipient_id = jenkins_hash(address->name, address->name_len);
        s->key.device_id = address->device_id;
        s->record = record_buf;
        HASH_ADD(hh, data->sessions, key, sizeof(session_store_session_key), s);
    }

    return 0;
}

int session_store_contains_session(const signal_protocol_address *address, void *user_data)
{
    session_store_data *data = user_data;
    session_store_session *s;

    session_store_session l;
    memset(&l, 0, sizeof(session_store_session));
    l.key.recipient_id = jenkins_hash(address->name, address->name_len);
    l.key.device_id = address->device_id;

    HASH_FIND(hh, data->sessions, &l.key, sizeof(session_store_session_key), s);

    return (s == 0) ? 0 : 1;
}

int session_store_delete_session(const signal_protocol_address *address, void *user_data)
{
    int result = 0;
    session_store_data *data = user_data;
    session_store_session *s;

    session_store_session l;
    memset(&l, 0, sizeof(session_store_session));
    l.key.recipient_id = jenkins_hash(address->name, address->name_len);
    l.key.device_id = address->device_id;

    HASH_FIND(hh, data->sessions, &l.key, sizeof(session_store_session_key), s);

    if(s) {
        HASH_DEL(data->sessions, s);
        signal_buffer_free(s->record);
        free(s);
        result = 1;
    }
    return result;
}



int session_store_delete_all_sessions(const char *name, size_t name_len, void *user_data)
{
    int result = 0;
    session_store_data *data = user_data;

    int64_t recipient_hash = jenkins_hash(name, name_len);
    session_store_session *cur_node;
    session_store_session *tmp_node;
    HASH_ITER(hh, data->sessions, cur_node, tmp_node) {
        if(cur_node->key.recipient_id == recipient_hash) {
            HASH_DEL(data->sessions, cur_node);
            signal_buffer_free(cur_node->record);
            free(cur_node);
            result++;
        }
    }

    return result;
}

void session_store_destroy(void *user_data)
{
    session_store_data *data = user_data;

    session_store_session *cur_node;
    session_store_session *tmp_node;
    HASH_ITER(hh, data->sessions, cur_node, tmp_node) {
        HASH_DEL(data->sessions, cur_node);
        signal_buffer_free(cur_node->record);
        free(cur_node);
    }

    free(data);
}

void setup_session_store(signal_protocol_store_context *context)
{
    session_store_data *data = malloc(sizeof(session_store_data));
    memset(data, 0, sizeof(session_store_data));

    signal_protocol_session_store store = {
        .load_session_func = session_store_load_session,
        .get_sub_device_sessions_func = session_store_get_sub_device_sessions,
        .store_session_func = session_store_store_session,
        .contains_session_func = session_store_contains_session,
        .delete_session_func = session_store_delete_session,
        .delete_all_sessions_func = session_store_delete_all_sessions,
        .destroy_func = session_store_destroy,
        .user_data = data
    };

    signal_protocol_store_context_set_session_store(context, &store);
}
