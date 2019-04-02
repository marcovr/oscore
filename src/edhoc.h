#ifndef RS_HTTP_EDHOC_H
#define RS_HTTP_EDHOC_H

#include "types.h"
#include "cose.h"

typedef struct edhoc_msg_1 {
    uint8_t tag;
    session_t session;
    uint8_t* nonce;
    size_t nonce_size;
    uint8_t* cose_eph_key;
    size_t cose_eph_key_size;
} edhoc_msg_1;

typedef struct edhoc_msg_2 {
    uint8_t tag;
    session_t session;
    session_t peer_session;
    uint8_t* peer_nonce;
    size_t peer_nonce_size;
    uint8_t* cose_peer_key;
    size_t cose_peer_key_size;
    uint8_t* cose_enc_2;
    size_t cose_enc_2_size;
} edhoc_msg_2;

typedef struct msg_2_context {
    uint8_t* shared_secret;
    uint8_t* enc_key;
    uint8_t* enc_iv;
    size_t enc_iv_size;
    uint8_t* message1;
    size_t message1_size;
} msg_2_context;

typedef struct edhoc_msg_3 {
    uint8_t tag;
    session_t peer_session;
    uint8_t* cose_enc_3;
    size_t cose_enc_3_size;
} edhoc_msg_3;

typedef struct msg_3_context {
    uint8_t* shared_secret;
    uint8_t* message1;
    size_t message1_size;
    uint8_t* message2;
    size_t message2_size;
} msg_3_context;

void edhoc_msg_1_free(edhoc_msg_1 *msg1);
void edhoc_msg_2_free(edhoc_msg_2 *msg2);
void edhoc_msg_3_free(edhoc_msg_3 *msg3);

size_t edhoc_serialize_msg_1(edhoc_msg_1 *msg1, unsigned char* buffer, size_t buf_size);
size_t edhoc_serialize_msg_2(edhoc_msg_2 *msg2, msg_2_context* context, ecc_key sigkey, unsigned char* buffer, size_t buf_size);
size_t edhoc_serialize_msg_3(edhoc_msg_3 *msg3, msg_3_context* context, ecc_key sigkey, unsigned char* buffer, size_t buf_size);

void edhoc_deserialize_msg1(edhoc_msg_1 *msg1, uint8_t* buffer, size_t len);
void edhoc_deserialize_msg2(edhoc_msg_2 *msg2, uint8_t* buffer, size_t len);
void edhoc_deserialize_msg3(edhoc_msg_3 *msg3, uint8_t* buffer, size_t len);

void edhoc_aad2(edhoc_msg_2* msg2, uint8_t* message1, size_t message1_size, uint8_t* out_hash);
void edhoc_msg_sig(uint8_t* aad, ecc_key sigkey,
                   uint8_t* out, size_t buf_size, size_t* out_size);

void edhoc_msg_enc_0(uint8_t* aad, uint8_t* signature, size_t signature_size, uint8_t* key, uint8_t* iv, size_t iv_size,
                      uint8_t* out, size_t buf_size, size_t* out_size);

void edhoc_aad3(edhoc_msg_3* msg3, uint8_t* message1, size_t message1_size, uint8_t* message2, size_t message2_size,
                uint8_t* out_hash);

void oscore_exchange_hash(uint8_t* msg1, size_t msg1_size, uint8_t* msg2, size_t msg2_size, uint8_t* msg3, size_t msg3_size, uint8_t* out_hash);

#endif //RS_HTTP_EDHOC_H
