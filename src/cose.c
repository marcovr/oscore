#include <stdlib.h>

#include "cose.h"
#include "utils.h"
#include "tinycbor/cbor.h"

#if defined(USE_CRYPTOAUTH)
#include "cryptoauthlib.h"
#include "basic/atca_basic_aes_gcm.h"
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

void cose_encode_signed(cose_sign1* sign1, ecc_key* key,
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
    ATCA_STATUS status = ATCA_GEN_FAIL;
    status = atcab_nonce_load(NONCE_MODE_TARGET_MSGDIGBUF, digest, 32);
    status = atcab_sign_base(SIGN_MODE_EXTERNAL | SIGN_MODE_SOURCE_MSGDIGBUF, key->slot, signature);
#else
    RNG rng;
    wc_InitRng(&rng);

    uint8_t sig_buf[wc_ecc_sig_size(key)];
    int sig_size = sizeof(sig_buf);
    int ret = wc_ecc_sign_hash(digest, sizeof(digest), sig_buf, &sig_size, &rng, key);
    int r_size=32, s_size=32;
    ret = wc_ecc_sig_to_rs(sig_buf, sig_size, signature, &r_size, signature+32, &s_size);
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
    size_t aad_size;
    cose_enc0_structure(prot_header, prot_size, enc0->external_aad, enc0->external_aad_size, aad, sizeof(aad), &aad_size);

    // Encrypt
    uint8_t ciphertext[enc0->plaintext_size + TAG_SIZE];

#if defined(USE_CRYPTOAUTH)
    ATCA_STATUS status = ATCA_GEN_FAIL;
    atca_aes_gcm_ctx_t aes_gcm_ctx;
    status = atcab_aes_gcm_init(&aes_gcm_ctx, ATCA_TEMPKEY_KEYID, 0, iv, iv_size);
    status = atcab_aes_gcm_aad_update(&aes_gcm_ctx, aad, aad_size);
    status = atcab_aes_gcm_encrypt_update(&aes_gcm_ctx, enc0->plaintext, enc0->plaintext_size, ciphertext);
    status = atcab_aes_gcm_encrypt_finish(&aes_gcm_ctx, ciphertext + enc0->plaintext_size, TAG_SIZE);
#else
    Aes aes;
    wc_AesCcmSetKey(&aes, key, 16);
    wc_AesCcmEncrypt(&aes, ciphertext, enc0->plaintext, enc0->plaintext_size, iv, iv_size, ciphertext + enc0->plaintext_size, TAG_SIZE, aad, aad_size);
#endif

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
printf("info_size: %i\n", info_size);
#if defined(USE_CRYPTOAUTH)
    ATCA_STATUS status;
    uint8_t buf[32];
    status = atcab_kdf(
        KDF_MODE_ALG_HKDF | KDF_MODE_SOURCE_TEMPKEY | KDF_MODE_TARGET_OUTPUT,
        0x0000, // K_2 stored in slot 4
                // Source key slot is the LSB and target key slot is the MSB.
        KDF_DETAILS_HKDF_MSG_LOC_INPUT | ((uint32_t)info_size << 24), /* Actual size
                                        of message is 16 bytes for AES algorithm or is encoded
                                        in the MSB of the details parameter for other
                                        algorithms.*/
        info,
        buf,
        NULL);
printf("derive_key: %02x\n", status);
    memcpy(out, buf, out_size);
#else
    wc_HKDF(WC_HASH_TYPE_SHA256, input_key, 32/*double-check*/, NULL, 0, info, info_size, out, out_size);
#endif
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

#if defined(USE_CRYPTOAUTH)
    ATCA_STATUS status;
    bool verified;
    atca_aes_gcm_ctx_t aes_gcm_ctx;
    status = atcab_aes_gcm_init(&aes_gcm_ctx, ATCA_TEMPKEY_KEYID, 0, iv, 7);
    status = atcab_aes_gcm_aad_update(&aes_gcm_ctx, aad, aad_size);
    status = atcab_aes_gcm_decrypt_update(&aes_gcm_ctx, ciphertext, sizeof(plaintext), plaintext);
    status = atcab_aes_gcm_decrypt_finish(&aes_gcm_ctx, auth_tag, TAG_SIZE, &verified);
#else
    Aes aes;
    wc_AesCcmSetKey(&aes, key, 16);
    wc_AesCcmDecrypt(&aes, plaintext, ciphertext, sizeof(plaintext), iv, 7/*iv_size*/, auth_tag, TAG_SIZE, aad, aad_size);
#endif

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
    uint8_t sig_buf[wc_ecc_sig_size(peer_key)];
    int sig_size = sizeof(sig_buf);
    wc_ecc_rs_raw_to_sig(signature, 32, signature+32, 32, sig_buf, &sig_size);
    wc_ecc_verify_hash(sig_buf, sig_size, digest, DIGEST_SIZE, &verified, peer_key);
    if (!verified)
        return -1;

    // Cleanup
    free(protected);
    free(payload);
    free(signature);

    return verified;
}
