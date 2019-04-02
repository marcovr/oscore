#include <stdlib.h>

#include "cose.h"
#include "utils.h"
#include "tinycbor/cbor.h"

#if defined(USE_CRYPTOAUTH)
#include "cryptoauthlib.h"
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wolfmath.h>
#include <wolfssl/wolfcrypt/aes.h>

#define DIGEST_SIZE 32
#define TAG_SIZE 8

void cose_encode_signed(cose_sign1* sign1, ecc_key key,
                        uint8_t* out, size_t out_size, size_t* out_len) {
    uint8_t sign_structure[256];
    size_t sign_struct_size;

    cose_sign1_structure("Signature1", sign1->protected_header, sign1->protected_header_size, sign1->external_aad, sign1->external_aad_size, sign1->payload, sign1->payload_size,
                         sign_structure, sizeof(sign_structure), &sign_struct_size);

    //printf("to_verify: ");
    //phex(sign_structure, sign_struct_len);

    // Hash sign structure
    //atcab_sha((uint16_t) sign_struct_len, (const uint8_t*) sign_structure, digest);
    uint8_t digest[DIGEST_SIZE];
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, sign_structure, sign_struct_size);
    wc_Sha256Final(&sha, digest);

    // Compute signature
    uint8_t signature[64];
#if defined(USE_CRYPTOAUTH)
    atcab_sign(key.slot, digest, signature);
#else
    RNG rng;
    wc_InitRng(&rng);

    mp_int r, s;
    mp_init(&r); mp_init(&s);
    int ret = wc_ecc_sign_hash_ex(digest, DIGEST_SIZE, &rng, &key, &r, &s);
    mp_to_unsigned_bin_len(&r, signature, 32);
    mp_to_unsigned_bin_len(&s, signature+32, 32);
#endif
    // Encode sign1 structure
    CborEncoder enc;
    cbor_encoder_init(&enc, out, out_size, 0);
    cbor_encode_tag(&enc, 18);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_byte_string(&ary, sign1->protected_header, sign1->protected_header_size);
    cbor_encode_byte_string(&ary, sign1->unprotected_header, sign1->unprotected_header_size);
    cbor_encode_byte_string(&ary, sign1->payload, sign1->payload_size);
    cbor_encode_byte_string(&ary, signature, sizeof(signature));

    cbor_encoder_close_container(&enc, &ary);
    *out_len = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_sign1_structure(const char* context,
                          uint8_t* body_protected, size_t body_protected_size,
                          uint8_t* external_aad, size_t external_aad_size,
                          uint8_t* payload, size_t payload_size,
                          uint8_t* out,
                          size_t buf_size,
                          size_t* out_size) {

    CborEncoder enc;
    cbor_encoder_init(&enc, out, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);

    cbor_encode_text_stringz(&ary, context);
    cbor_encode_byte_string(&ary, body_protected, body_protected_size);
    cbor_encode_byte_string(&ary, external_aad, external_aad_size);
    cbor_encode_byte_string(&ary, payload, payload_size);

    cbor_encoder_close_container(&enc, &ary);
    *out_size = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_encode_encrypted(cose_encrypt0 *enc0, uint8_t *key, uint8_t *iv, size_t iv_size, uint8_t *out, size_t buf_size, size_t *out_size) {
    uint8_t* prot_header;
    size_t prot_size = hexstring_to_buffer(&prot_header, "a1010c", strlen("a1010c"));

    // Compute aad
    uint8_t aad[128];
    size_t aad_len;
    cose_enc0_structure(prot_header, prot_size, enc0->external_aad, enc0->external_aad_size, aad, sizeof(aad), &aad_len);

    // Encrypt
    uint8_t ciphertext[enc0->plaintext_size + TAG_SIZE];

    Aes aes;
    wc_AesCcmSetKey(&aes, key, 16);
    wc_AesCcmEncrypt(&aes, ciphertext, enc0->plaintext, enc0->plaintext_size, iv, iv_size, ciphertext + enc0->plaintext_size, TAG_SIZE , aad, aad_len);

    // Encode
    CborEncoder enc;
    cbor_encoder_init(&enc, out, buf_size, 0);
    cbor_encode_tag(&enc, 16);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_byte_string(&ary, prot_header, prot_size);
    cbor_encode_byte_string(&ary, NULL, 0);
    cbor_encode_byte_string(&ary, ciphertext, sizeof(ciphertext));

    cbor_encoder_close_container(&enc, &ary);

    *out_size = cbor_encoder_get_buffer_size(&enc, out);

    // Cleanup
    free(prot_header);
}

void cose_enc0_structure(uint8_t* body_protected, size_t body_protected_size, uint8_t* external_aad, size_t external_aad_size,
                         uint8_t* out, size_t buf_size, size_t* out_size) {

    CborEncoder enc;
    cbor_encoder_init(&enc, out, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 3);

    cbor_encode_text_stringz(&ary, "Encrypt0");
    cbor_encode_byte_string(&ary, body_protected, body_protected_size);
    cbor_encode_byte_string(&ary, external_aad, external_aad_size);

    cbor_encoder_close_container(&enc, &ary);
    *out_size = cbor_encoder_get_buffer_size(&enc, out);
}

void cose_kdf_context(const char* algorithm_id, int key_length, uint8_t* other, size_t other_size, uint8_t* out, size_t buf_size, size_t *out_size) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);
    cbor_encode_text_stringz(&ary, algorithm_id);

    CborEncoder partyUInfo;
    cbor_encoder_create_array(&ary, &partyUInfo, 3);
    cbor_encode_null(&partyUInfo);
    cbor_encode_null(&partyUInfo);
    cbor_encode_null(&partyUInfo);
    cbor_encoder_close_container(&ary, &partyUInfo);

    CborEncoder partyVInfo;
    cbor_encoder_create_array(&ary, &partyVInfo, 3);
    cbor_encode_null(&partyVInfo);
    cbor_encode_null(&partyVInfo);
    cbor_encode_null(&partyVInfo);
    cbor_encoder_close_container(&ary, &partyVInfo);

    CborEncoder suppPubInfo;
    cbor_encoder_create_array(&ary, &suppPubInfo, 3);
    cbor_encode_int(&suppPubInfo, key_length);
    cbor_encode_byte_string(&suppPubInfo, NULL, 0);
    cbor_encode_byte_string(&suppPubInfo, other, other_size);
    cbor_encoder_close_container(&ary, &suppPubInfo);

    cbor_encoder_close_container(&enc, &ary);

    *out_size = cbor_encoder_get_buffer_size(&enc, out);
}

void derive_key(uint8_t* input_key, uint8_t* info, size_t info_size, uint8_t* out, size_t out_size) {
    wc_HKDF(WC_HASH_TYPE_SHA256, input_key, 32/*double-check*/, NULL, 0, info, info_size, out, out_size);
}

void cose_decrypt_enc0(uint8_t* enc0, size_t enc0_size, uint8_t *key, uint8_t *iv, size_t iv_size, uint8_t* external_aad, size_t external_aad_size,
                       uint8_t* out, size_t buf_size, size_t *out_len) {
    // Parse encoded enc0
    CborParser parser;
    CborValue val;
    cbor_parser_init(enc0, enc0_size, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    uint8_t* protected;
    size_t protected_size;
    cbor_value_dup_byte_string(&e, &protected, &protected_size, &e);

    // Skip unprotected header
    cbor_value_advance(&e);

    uint8_t* ciphertext;
    size_t ciphertext_size;
    cbor_value_dup_byte_string(&e, &ciphertext, &ciphertext_size, &e);
    cbor_value_leave_container(&val, &e);

    // Compute AAD
    uint8_t aad[64];
    size_t aad_size;
    cose_enc0_structure(protected, protected_size, external_aad, external_aad_size, aad, sizeof(aad), &aad_size);

    // Allocate Resources
    uint8_t plaintext[ciphertext_size - TAG_SIZE];
    uint8_t auth_tag[TAG_SIZE];
    memcpy(auth_tag, ciphertext + ciphertext_size - TAG_SIZE, TAG_SIZE);

    // Decrypt
    Aes aes;
    wc_AesCcmSetKey(&aes, key, 16);
    wc_AesCcmDecrypt(&aes, plaintext, ciphertext, sizeof(plaintext), iv, 7/*iv_size*/, auth_tag, TAG_SIZE, aad, aad_size);

    phex(plaintext, sizeof(plaintext));

    // Return plaintext to caller
    memcpy(out, plaintext, sizeof(plaintext));
    *out_len = sizeof(plaintext);

    // Clean up
    free(protected);
    free(ciphertext);
}

int cose_verify_sign1(uint8_t* sign1, size_t sign1_size, ecc_key *peer_key, uint8_t* external_aad, size_t external_aad_size) {
    /// Parse
    CborParser parser;
    CborValue val;
    cbor_parser_init(sign1, sign1_size, 0, &parser, &val);

    CborTag tag;
    cbor_value_get_tag(&val, &tag);
    cbor_value_advance(&val);

    CborValue e;
    cbor_value_enter_container(&val, &e);

    uint8_t* protected;
    size_t protected_size;
    cbor_value_dup_byte_string(&e, &protected, &protected_size, &e);

    // Skip unprotected header
    cbor_value_advance(&e);

    uint8_t* payload;
    size_t payload_size;
    cbor_value_dup_byte_string(&e, &payload, &payload_size, &e);

    uint8_t* signature;
    size_t signature_size;
    cbor_value_dup_byte_string(&e, &signature, &signature_size, &e);

    // Verify
    uint8_t to_verify[256];
    size_t to_verify_size;
    cose_sign1_structure("Signature1", protected, protected_size, external_aad, external_aad_size, payload, payload_size, to_verify, sizeof(to_verify), &to_verify_size);

    // Compute digest
    uint8_t digest[DIGEST_SIZE];
    //atcab_sha((uint16_t) to_verify_len, (const uint8_t*) to_verify, digest);
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, to_verify, to_verify_size);
    wc_Sha256Final(&sha, digest);

    int verified = 0;
    //atcab_verify_extern(digest, signature.buf, NULL, &verified);
    mp_int r, s;
    mp_init(&r); mp_init(&s);
    mp_read_unsigned_bin (&r, signature, 32);
    mp_read_unsigned_bin (&s, signature+32, 32);
    int ret = wc_ecc_verify_hash_ex(&r, &s, digest, DIGEST_SIZE, &verified, peer_key);
    if (!verified)
        return -1;

    // Cleanup
    free(protected);
    free(payload);
    free(signature);

    return verified;
}
