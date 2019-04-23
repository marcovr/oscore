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

typedef struct edhoc_context_t {
    ecc_key key;
    ecc_key peer_key;
    ecc_key eph_key;
    conn_id_t connection;
    char* shared_secret;
    edhoc_msg_t message1;
    edhoc_msg_t message2;
    edhoc_msg_t message3;
} edhoc_context_t;

typedef struct oscore_context_t {
    uint8_t master_secret[16];
    uint8_t master_salt[8];
} oscore_context_t;

typedef struct edhoc_context_t edhoc_u_context_t;
typedef struct edhoc_context_t edhoc_v_context_t;

#endif //RS_HTTP_RS_TYPES_H