#ifndef RS_HTTP_COSE_H
#define RS_HTTP_COSE_H

#include "types.h"
#include "ecc.h"

typedef struct cose_sign1 {
    uint8_t* payload;
    size_t payload_size;
    uint8_t* external_aad;
    size_t external_aad_size;
    uint8_t* protected_header;
    size_t protected_header_size;
    uint8_t* unprotected_header;
    size_t unprotected_header_size;
} cose_sign1;

typedef struct cose_encrypt0 {
    uint8_t* plaintext;
    size_t plaintext_size;
    uint8_t* external_aad;
    size_t external_aad_size;
    uint8_t* protected_header;
    size_t protected_header_size;
    uint8_t* unprotected_header;
    size_t unprotected_header_size;
} cose_encrypt0;

void cose_encode_signed(cose_sign1* sign1,
                        ecc_key* key,
                        uint8_t* out,
                        size_t buf_size,
                        size_t* out_size);

void cose_sign1_structure(const char* context,
                          uint8_t* body_protected,
                          size_t body_protected_size,
                          uint8_t* external_aad,
                          size_t external_aad_size,
                          uint8_t* payload,
                          size_t payload_size,
                          uint8_t* out,
                          size_t buf_size,
                          size_t* out_size);

void cose_encode_encrypted(cose_encrypt0 *enc0, uint8_t *key, 
                           uint8_t *iv, size_t iv_size,
                           uint8_t *out, size_t buf_size, size_t *out_size);
void cose_compress_encrypted(cose_encrypt0 *enc0, uint8_t *key,
                             uint8_t *iv, size_t iv_size,
                             uint8_t *out, size_t buf_size, size_t *out_size);
void cose_enc0_structure(uint8_t* body_protected, size_t body_protected_size, uint8_t* external_aad, size_t external_aad_size,
                         uint8_t* out, size_t buf_size, size_t* out_size);

void cose_kdf_context(const char* algorithm_id, int key_length, uint8_t* other, size_t other_size, uint8_t* out, size_t buf_size, size_t *out_size);
void derive_key(uint8_t *input_key, uint8_t *info, size_t info_size, uint8_t* out, size_t out_size);

void cose_decrypt_enc0(uint8_t* enc0, size_t enc0_size, uint8_t *key, uint8_t *iv, size_t iv_len, uint8_t* external_aad, size_t external_aad_size,
                       uint8_t* out, size_t buf_size, size_t *out_size);
int cose_verify_sign1(uint8_t* sign1, size_t sign1_size, ecc_key *peer_key, uint8_t* external_aad, size_t external_aad_size);


#endif //RS_HTTP_COSE_H

//TODO:
// - write methods: cose_decode_encrypted, cose_decode_signed
// - write documentation
// - COSE compression (https://tools.ietf.org/html/rfc8613#section-6)
