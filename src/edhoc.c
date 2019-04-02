#include <stdlib.h>

#include "edhoc.h"
#include "cose.h"
#include "tinycbor/cbor.h"
#include "utils.h"

#define DIGEST_SIZE 32

void edhoc_msg_1_free(edhoc_msg_1 *msg1) {
    //free(msg1->connection.conn_id);
    free(msg1->nonce);
    free(msg1->cose_eph_key);
    //free(msg1);
}

void edhoc_msg_2_free(edhoc_msg_2 *msg2) {
    //free(msg2->connection.conn_id);
    //free(msg2->peer_connection.conn_id);
    free(msg2->peer_nonce);
    free(msg2->cose_peer_key);
    free(msg2->cose_enc_2);
    //free(msg2);
}

void edhoc_msg_3_free(edhoc_msg_3 *msg3) {
    //free(msg3->peer_connection.conn_id);
    free(msg3->cose_enc_3);
    //free(msg3);
}

void edhoc_deserialize_msg1(edhoc_msg_1 *msg1, uint8_t* buffer, size_t len) {
    CborParser parser;
    CborValue value;

    uint8_t* copy = buffer;
    cbor_parser_init(copy, len, 0, &parser, &value);

    CborValue elem;
    cbor_value_enter_container(&value, &elem);

    cbor_value_get_uint64(&elem, (uint64_t *) &msg1->tag);
    cbor_value_advance(&elem);

    cbor_value_dup_byte_string(&elem, &(msg1->connection.conn_id), &(msg1->connection.conn_size)/*double-check*/, &elem);
    cbor_value_dup_byte_string(&elem, &(msg1->nonce), &(msg1->nonce_size), &elem);
    cbor_value_dup_byte_string(&elem, &(msg1->cose_eph_key), &(msg1->cose_eph_key_size)/*triple-check*/, &elem);

    // must free msg.conn_id
    // must free msg.nonce
    // must free msg.eph_key
}

void edhoc_deserialize_msg2(edhoc_msg_2 *msg2, uint8_t* buffer, size_t size) {
    CborParser parser;
    CborValue value;

    uint8_t* copy = buffer;
    cbor_parser_init(copy, size, 0, &parser, &value);

    CborValue element;
    cbor_value_enter_container(&value, &element);

    cbor_value_get_uint64(&element, (uint64_t *) &msg2->tag);
    cbor_value_advance(&element); // TODO: double-check

    uint8_t* conn_id;
    size_t conn_size;
    cbor_value_dup_byte_string(&element, &conn_id, &conn_size, &element);

    uint8_t* peer_conn_id;
    size_t peer_conn_size;
    cbor_value_dup_byte_string(&element, &peer_conn_id, &peer_conn_size, &element);

    uint8_t* peer_nonce;
    size_t peer_nonce_size;
    cbor_value_dup_byte_string(&element, &peer_nonce, &peer_nonce_size, &element);

    uint8_t* peer_key;
    size_t peer_key_size;
    cbor_value_dup_byte_string(&element, &peer_key, &peer_key_size, &element);

    uint8_t* cose_enc_2;
    size_t cose_enc_2_size;
    cbor_value_dup_byte_string(&element, &cose_enc_2, &cose_enc_2_size, &element);

    msg2->connection = (conn_id_t) {conn_id, conn_size};
    msg2->peer_connection = (conn_id_t) {peer_conn_id, peer_conn_size};
    msg2->peer_nonce = peer_nonce;
    msg2->peer_nonce_size = peer_nonce_size;
    msg2->cose_peer_key = peer_key;
    msg2->cose_peer_key_size = peer_key_size;
    msg2->cose_enc_2 = cose_enc_2;
    msg2->cose_enc_2_size = cose_enc_2_size;

    // must free msg.peer_conn_id
    // must free msg.cose_enc_2
}

void edhoc_deserialize_msg3(edhoc_msg_3 *msg3, uint8_t* buffer, size_t len) {
    CborParser parser;
    CborValue value;

    uint8_t* copy = buffer;
    cbor_parser_init(copy, len, 0, &parser, &value);

    CborValue element;
    cbor_value_enter_container(&value, &element);

    cbor_value_get_uint64(&element, (uint64_t *) &msg3->tag);
    cbor_value_advance(&element);

    uint8_t* peer_conn_id;
    size_t peer_conn_size;
    cbor_value_dup_byte_string(&element, &peer_conn_id, &peer_conn_size, &element);

    uint8_t* cose_enc_3;
    size_t cose_enc_3_size;
    cbor_value_dup_byte_string(&element, &cose_enc_3, &cose_enc_3_size, &element);

    msg3->peer_connection = (conn_id_t) {peer_conn_id, peer_conn_size};
    msg3->cose_enc_3      = cose_enc_3;
    msg3->cose_enc_3_size = cose_enc_3_size;
    
    // must free msg.peer_conn_id
    // must free msg.cose_enc_3
}

size_t edhoc_serialize_msg_1(edhoc_msg_1 *msg1, unsigned char* buffer, size_t buf_size) {
    // Serialize
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_uint(&ary, msg1->tag);

    cbor_encode_byte_string(&ary, msg1->connection.conn_id, msg1->connection.conn_size);
    cbor_encode_byte_string(&ary, msg1->nonce, msg1->nonce_size);
    cbor_encode_byte_string(&ary, msg1->cose_eph_key, msg1->cose_eph_key_size/*double-check*/);

    cbor_encoder_close_container(&enc, &ary);

    return cbor_encoder_get_buffer_size(&enc, buffer);
}

size_t edhoc_serialize_msg_2(edhoc_msg_2 *msg2, msg_2_context* context, ecc_key sigkey, unsigned char* buffer, size_t buf_size) {
    // Compute AAD
    uint8_t aad2[DIGEST_SIZE];

    edhoc_aad2(msg2, context->message1, context->message1_size, aad2);
    // Compute Signature
    uint8_t sig_v[256];
    size_t sig_v_size;
    edhoc_msg_sig(aad2, sigkey, sig_v, sizeof(sig_v), &sig_v_size);

    uint8_t context_info_k2[128];
    size_t ci_k2_size;
    cose_kdf_context("AES-CCM-64-64-128", 16, aad2, DIGEST_SIZE, context_info_k2, sizeof(context_info_k2), &ci_k2_size);

    uint8_t context_info_iv2[128];
    size_t ci_iv2_size;
    cose_kdf_context("IV-Generation", 7, aad2, DIGEST_SIZE, context_info_iv2, sizeof(context_info_iv2), &ci_iv2_size);

    uint8_t k2[16];
    derive_key(context->shared_secret, context_info_k2, ci_k2_size, k2, sizeof(k2));

    uint8_t iv2[7];
    derive_key(context->shared_secret, context_info_iv2, ci_iv2_size, iv2, sizeof(iv2));

    //printf("AAD2: ");
    //phex(aad2, DIGEST_SIZE);
    printf("K2: ");
    phex(k2, 16);
    printf("IV2: ");
    phex(iv2, 7);

    // Encrypt
    uint8_t enc_2[256];
    size_t enc_2_size;
    edhoc_msg_enc_0(aad2, sig_v, sig_v_size, k2, iv2, 7, enc_2, sizeof(enc_2), &enc_2_size);

    // Serialize
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 6);

    cbor_encode_int(&ary, msg2->tag);
    cbor_encode_byte_string(&ary, msg2->connection.conn_id, msg2->connection.conn_size);
    cbor_encode_byte_string(&ary, msg2->peer_connection.conn_id, msg2->peer_connection.conn_size);
    cbor_encode_byte_string(&ary, msg2->peer_nonce, msg2->peer_nonce_size);
    cbor_encode_byte_string(&ary, msg2->cose_peer_key, msg2->cose_peer_key_size);
    cbor_encode_byte_string(&ary, enc_2, enc_2_size);

    cbor_encoder_close_container(&enc, &ary);

    return cbor_encoder_get_buffer_size(&enc, buffer);
}

size_t edhoc_serialize_msg_3(edhoc_msg_3 *msg3, msg_3_context* context, ecc_key key, unsigned char* buffer, size_t buf_size) {
    // Compute AAD
    uint8_t aad3[DIGEST_SIZE];
    edhoc_aad3(msg3, context->message1, context->message1_size, context->message2, context->message2_size, aad3);

    // Compute Signature
    uint8_t sig_u[256];
    size_t sig_u_size;
    edhoc_msg_sig(aad3, key, sig_u, sizeof(sig_u), &sig_u_size);

    //bytes b_sig_u = {sig_u, sig_u_len};
    //printf("sig_v: ");
    //phex(sig_v, sig_v_len);

    uint8_t context_info_k3[128];
    size_t ci_k3_size;
    cose_kdf_context("AES-CCM-64-64-128", 16, aad3, DIGEST_SIZE, context_info_k3, sizeof(context_info_k3), &ci_k3_size);

    uint8_t context_info_iv3[128];
    size_t ci_iv3_size;
    cose_kdf_context("IV-Generation", 7, aad3, DIGEST_SIZE, context_info_iv3, sizeof(context_info_iv3), &ci_iv3_size);

    uint8_t k3[16];
    derive_key(context->shared_secret, context_info_k3, ci_k3_size, k3, sizeof(k3));

    uint8_t iv3[7];
    derive_key(context->shared_secret, context_info_iv3, ci_iv3_size, iv3, sizeof(iv3));

    //printf("AAD2: ");
    //phex(aad2, DIGEST_SIZE);
    printf("K3: ");
    phex(k3, 16);
    printf("IV3: ");
    phex(iv3, 7);

    // Encrypt
    uint8_t enc_3[256];
    size_t enc_3_size;
    edhoc_msg_enc_0(aad3, sig_u, sig_u_size, k3, iv3, 7, enc_3, sizeof(enc_3), &enc_3_size);

    // Serialize
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_int(&ary, msg3->tag);
    cbor_encode_byte_string(&ary, msg3->peer_connection.conn_id, msg3->peer_connection.conn_size);
    cbor_encode_byte_string(&ary, enc_3, enc_3_size);

    cbor_encoder_close_container(&enc, &ary);

    return cbor_encoder_get_buffer_size(&enc, buffer);
}

void edhoc_aad2(edhoc_msg_2 *msg2, uint8_t* message1, size_t message1_size, uint8_t *out_hash) {
    uint8_t data2[256];

    // Compute data2
    CborEncoder enc;
    cbor_encoder_init(&enc, data2, sizeof(data2), 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 5);

    cbor_encode_int(&ary, msg2->tag);
    cbor_encode_byte_string(&ary, msg2->connection.conn_id, msg2->connection.conn_size);
    cbor_encode_byte_string(&ary, msg2->peer_connection.conn_id, msg2->peer_connection.conn_size);
    cbor_encode_byte_string(&ary, msg2->peer_nonce, msg2->peer_nonce_size);
    cbor_encode_byte_string(&ary, msg2->cose_peer_key, msg2->cose_peer_key_size/*double-check*/);

    cbor_encoder_close_container(&enc, &ary);
    size_t data2_size = cbor_encoder_get_buffer_size(&enc, data2);

    //printf("data2: ");
    //phex(data2, data2_len);

    //printf("message1: ");
    //phex(message1.buf, message1.len);

    // Compute aad2
    uint8_t aad2[message1_size + data2_size];

    memcpy(aad2, message1, message1_size);
    memcpy((aad2+message1_size), data2, data2_size);

    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, aad2, sizeof(aad2));
    wc_Sha256Final(&sha, out_hash);
    //atcab_sha((uint16_t) sizeof(aad2), (const uint8_t*) aad2, out_hash);
}

void edhoc_msg_sig(uint8_t* aad, ecc_key key,
                      uint8_t* out, size_t buf_size, size_t* out_size) {

    uint8_t *prot_header, *unprot_header;
    size_t prot_size = hexstring_to_buffer(&prot_header, "a10126", strlen("a10126"));
    size_t unprot_size = hexstring_to_buffer(&unprot_header, "a104524173796d6d65747269634543445341323536", strlen("a104524173796d6d65747269634543445341323536"));

    cose_sign1 signature;
    signature.payload_size = 0;
    signature.protected_header = prot_header;
    signature.protected_header_size = prot_size;
    signature.unprotected_header = unprot_header;
    signature.unprotected_header_size = unprot_size;
    signature.external_aad = aad;
    signature.external_aad_size = DIGEST_SIZE;

    cose_encode_signed(&signature, key, out, buf_size, out_size);

    free(prot_header);
    free(unprot_header);
}

void edhoc_msg_enc_0(uint8_t* aad, uint8_t* signature, size_t signature_size, uint8_t* key, uint8_t* iv, size_t iv_size,
                      uint8_t* out, size_t buf_size, size_t* out_size) {
    cose_encrypt0 enc = {
            .external_aad = aad,
            .external_aad_size = DIGEST_SIZE,/*double-check*/
            .plaintext = signature,
            .plaintext_size = signature_size/*triple-check*/
    };

    cose_encode_encrypted(&enc, key, iv, iv_size, out, buf_size, out_size);
}

void edhoc_aad3(edhoc_msg_3* msg3, uint8_t* message1, size_t message1_size, uint8_t* message2, size_t message2_size,
                uint8_t* out_hash) {

    // Combine msg1+msg2;
    uint8_t combined[message1_size + message2_size];
    memcpy(combined, message1, message1_size);
    memcpy(combined+message1_size, message2, message2_size);

    uint8_t digest[DIGEST_SIZE];
    //atcab_sha((uint16_t) sizeof(combined), (const uint8_t*) combined, digest);
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, combined, sizeof(combined));
    wc_Sha256Final(&sha, digest);

    // Compute data3
    uint8_t data3[64];

    CborEncoder enc;
    cbor_encoder_init(&enc, data3, sizeof(data3), 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 2);

    cbor_encode_int(&ary, msg3->tag);
    cbor_encode_byte_string(&ary, msg3->peer_connection.conn_id, msg3->peer_connection.conn_size);

    cbor_encoder_close_container(&enc, &ary);
    size_t data3_len = cbor_encoder_get_buffer_size(&enc, data3);

    // Combine with data3
    uint8_t final[DIGEST_SIZE + data3_len];
    memcpy(final, digest, DIGEST_SIZE);
    memcpy(final+DIGEST_SIZE, data3, data3_len);
    
    //atcab_sha((uint16_t) sizeof(final), (const uint8_t*) final, out_hash);
    Sha256 sha2;
    wc_InitSha256(&sha2);
    wc_Sha256Update(&sha2, final, sizeof(final));
    wc_Sha256Final(&sha2, out_hash);
}

void oscore_exchange_hash(uint8_t* message1, size_t message1_size, uint8_t* message2, size_t message2_size, uint8_t* message3, size_t message3_size, uint8_t *out_hash) {
    // Combine msg1+msg2;
    uint8_t combined[message1_size + message2_size];
    memcpy(combined, message1, message1_size);
    memcpy(combined+message1_size, message2, message2_size);
    
    uint8_t digest[DIGEST_SIZE];
    
    //atcab_sha((uint16_t) sizeof(combined), (const uint8_t*) combined, digest);
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, combined, sizeof(combined));
    wc_Sha256Final(&sha, digest);

    // Comine with msg3
    uint8_t final[DIGEST_SIZE + message3_size];
    memcpy(final, digest, DIGEST_SIZE);
    memcpy(final+DIGEST_SIZE, message3, message3_size);
    
    //atcab_sha((uint16_t) sizeof(final), (const uint8_t*) final, out_hash);
    Sha256 sha2;
    wc_InitSha256(&sha2);
    wc_Sha256Update(&sha2, final, sizeof(final));
    wc_Sha256Final(&sha2, out_hash);
}
