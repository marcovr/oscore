#ifndef RS_HTTP_RS_TYPES_H
#define RS_HTTP_RS_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include "ecc.h"


typedef struct edhoc_msg_t {
    char* data;
    size_t size;
} edhoc_msg_t;

typedef struct conn_id_t {
    uint8_t* conn_id;
    size_t conn_size;
} conn_id_t;

struct edhoc_session_state {
    ecc_key key;
    ecc_key peer_key;
    ecc_key eph_key;
    conn_id_t connection;
    char* shared_secret;
    edhoc_msg_t message1;
    edhoc_msg_t message2;
    edhoc_msg_t message3;
};

typedef struct edhoc_session_state edhoc_u_session_state;
typedef struct edhoc_session_state edhoc_v_session_state;

typedef struct oscore_context {
    uint8_t master_secret[16];
    uint8_t master_salt[8];
} oscore_context;

#endif //RS_HTTP_RS_TYPES_H