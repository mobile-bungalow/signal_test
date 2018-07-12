#include <signal/signal_protocol.h>


int
session_store_get_sub_device_sessions(signal_int_list **sessions,
    const char *name, size_t name_len, void *user_data);

int session_store_load_session(signal_buffer **record, signal_buffer
   **user_record, const signal_protocol_address *address, void *user_data);


int test_session_store_load_session(signal_buffer **record,
   signal_buffer **user_record, const signal_protocol_address *address, void *user_data);

int session_store_store_session(const signal_protocol_address *address,
    uint8_t *record, size_t record_len, uint8_t *user_record_data,
     size_t user_record_len, void *user_data);

int session_store_contains_session(const signal_protocol_address *address, void *user_data);


int session_store_delete_session(const signal_protocol_address *address, void *user_data);


int session_store_delete_all_sessions(const char *name, size_t name_len, void *user_data);


void session_store_destroy(void *user_data);

void setup_session_store(signal_protocol_store_context *context);
