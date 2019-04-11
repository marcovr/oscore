//
// Created by Urs Gerber on 08.03.18.
//
#include <stdlib.h>
#include <assert.h>

#include "cwt.h"
#include "utils.h"
#include "tinycbor/cbor.h"
#include "ecc.h"

#if defined(USE_CRYPTOAUTH)
    #include "cryptoauthlib.h"
#elif defined(USE_WOLFSSL)
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/random.h>
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

#define CBOR_LABEL_COSE_KEY 25
#define CBOR_LABEL_AUDIENCE 3

void cwt_parse(rs_cwt* cwt, uint8_t* encoded, size_t len) {
    CborParser parser;
    CborValue value;

    uint8_t* enc = encoded;
    cbor_parser_init(enc, len, 0, &parser, &value);

    CborTag tag;
    cbor_value_get_tag(&value, &tag);
    cbor_value_advance(&value);

    CborValue elem;
    cbor_value_enter_container(&value, &elem);

    cwt->h_protected = elem;
    cbor_value_advance(&elem);

    cwt->h_unprotected = elem;
    cbor_value_advance(&elem);

    cwt->payload = elem;
    cbor_value_advance(&elem);

    cwt->signature = elem;
}

int cwt_verify(rs_cwt* cwt, uint8_t* eaad, size_t eaad_size, ecc_key *peer_key) {
    CborEncoder enc;
    uint8_t buffer[256];
    cbor_encoder_init(&enc, buffer, 256, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 4);
    cbor_encode_text_stringz(&ary, "Signature1");

    uint8_t* protected;
    size_t len;
    cbor_value_dup_byte_string(&cwt->h_protected, &protected, &len, NULL);
    cbor_encode_byte_string(&ary, protected, len);
    free(protected);

    cbor_encode_byte_string(&ary, eaad, eaad_size);

    uint8_t* payload;
    size_t p_len;
    cbor_value_dup_byte_string(&cwt->payload, &payload, &p_len, NULL);
    cbor_encode_byte_string(&ary, payload, p_len);
    free(payload);

    cbor_encoder_close_container(&enc, &ary);
    size_t buf_len = cbor_encoder_get_buffer_size(&enc, buffer);

    // Compute digest
    uint8_t digest[32];
#if defined(USE_CRYPTOAUTH)
    atcab_sha(buf_len, buffer, digest);
#elif defined(USE_WOLFSSL)
    Sha256 sha;
    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, buffer, buf_len);
    wc_Sha256Final(&sha, digest);
#endif

    // Extract Signature
    uint8_t* signature;
    size_t sig_len;
    cbor_value_dup_byte_string(&cwt->signature, &signature, &sig_len, NULL);

    int verified = 0;
#if defined(USE_CRYPTOAUTH)
    ATCA_STATUS status = ATCA_GEN_FAIL;
    status = atcab_nonce_load(NONCE_MODE_TARGET_MSGDIGBUF, digest, 32);
    uint8_t public_key[64];
    int coord_size = 32;
    status = atcab_verify(VERIFY_MODE_EXTERNAL | VERIFY_MODE_SOURCE_MSGDIGBUF, VERIFY_KEY_P256, signature, peer_key->pubkey_raw, NULL, NULL);
    verified = (status==ATCA_SUCCESS);
 #else
    uint8_t sig_buf[wc_ecc_sig_size(peer_key)];
    int sig_size = sizeof(sig_buf);
    wc_ecc_rs_raw_to_sig(signature, 32, signature+32, 32, sig_buf, &sig_size);
    wc_ecc_verify_hash(sig_buf, sig_size, digest, SHA256_DIGEST_SIZE, &verified, peer_key);
#endif
    assert(verified);
    
    free(signature);

    return verified;
}

void cwt_parse_payload(rs_cwt* cwt, rs_payload* out) {
    uint8_t* payload;
    size_t len;

    cbor_value_dup_byte_string(&cwt->payload, &payload, &len, NULL);

    CborParser parser;
    CborValue map;
    cbor_parser_init(payload, len, 0, &parser, &map);

    CborValue elem;
    cbor_value_enter_container(&map, &elem);

    while (!cbor_value_at_end(&elem)) {
        int label;
        cbor_value_get_int(&elem, &label);
        cbor_value_advance(&elem);

        if (label == CBOR_LABEL_AUDIENCE) {
            char* audience;
            size_t aud_len;
            cbor_value_dup_text_string(&elem, &audience, &aud_len, &elem);
            out->aud = audience;
        } else if (label == CBOR_LABEL_COSE_KEY) {
            CborValue cnf_elem;
            cbor_value_enter_container(&elem, &cnf_elem);

            int cnf_tag;
            cbor_value_get_int(&cnf_elem, &cnf_tag);
            cbor_value_advance(&cnf_elem);

            uint8_t* cnf;
            size_t cnf_size;
            cbor_value_dup_byte_string(&cnf_elem, &cnf, &cnf_size, &cnf_elem);
            out->cnf = cnf;
            out->cnf_size = cnf_size;

            cbor_value_leave_container(&elem, &cnf_elem);
        } else {
            cbor_value_advance(&elem);
        }
    }

    free(payload);
}

#define CBOR_LABEL_COSE_KEY_KTY 1
#define CBOR_LABEL_COSE_KEY_KID 2
#define CBOR_LABEL_COSE_KEY_CRV (-1)
#define CBOR_LABEL_COSE_KEY_X (-2)
#define CBOR_LABEL_COSE_KEY_Y (-3)

void cwt_parse_cose_key(uint8_t* encoded, size_t encoded_size, cose_key* out) {
    out->kid_size = 0;

    CborParser parser;
    CborValue map;

    cbor_parser_init(encoded, encoded_size, 0, &parser, &map);

    CborValue elem;
    cbor_value_enter_container(&map, &elem);

    while (!cbor_value_at_end(&elem)) {
        int label;
        cbor_value_get_int(&elem, &label);
        cbor_value_advance(&elem);

        if (label == CBOR_LABEL_COSE_KEY_KTY) {
            int kty;
            cbor_value_get_int(&elem, &kty);
            cbor_value_advance(&elem);
            out->kty = (uint8_t) kty;
        } else if (label == CBOR_LABEL_COSE_KEY_KID) {
            uint8_t* kid;
            size_t kid_size;
            cbor_value_dup_byte_string(&elem, &kid, &kid_size, &elem);
            out->kid = kid;
            out->kid_size = kid_size;
        } else if (label == CBOR_LABEL_COSE_KEY_CRV) {
            int crv;
            cbor_value_get_int(&elem, &crv);
            cbor_value_advance(&elem);
            out->crv = (uint8_t) crv;
        } else if (label == CBOR_LABEL_COSE_KEY_X) {
            uint8_t* x;
            size_t x_size;
            cbor_value_dup_byte_string(&elem, &x, &x_size, &elem);

            out->x = x;
        } else if (label == CBOR_LABEL_COSE_KEY_Y) {
            uint8_t* y;
            size_t y_size;
            cbor_value_dup_byte_string(&elem, &y, &y_size, &elem);

            out->y = y;
        } else {
            cbor_value_advance(&elem);
        }
    }
}

void cwt_encode_cose_key(cose_key* key, uint8_t* buffer, size_t buf_size, size_t* len) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);
    
    CborEncoder map;
    cbor_encoder_create_map(&enc, &map, 5);
    
    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_KTY);
    cbor_encode_int(&map, key->kty);
    
    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_CRV);
    cbor_encode_int(&map, key->crv);

    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_X);
    cbor_encode_byte_string(&map, key->x, 32/*double-check*/);

    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_Y);
    cbor_encode_byte_string(&map, key->y, 32/*double-check*/);

    cbor_encode_int(&map, CBOR_LABEL_COSE_KEY_KID);
    cbor_encode_byte_string(&map, key->kid, key->kid_size);

    cbor_encoder_close_container(&enc, &map);

    *len = cbor_encoder_get_buffer_size(&enc, buffer);
}

void cwt_encode_ecc_key(uint8_t* key, uint8_t* buffer, size_t buf_size, size_t* len) {
    cose_key cose = {
            .crv = 1, // P-256
            .kid = "abcd",
            .kid_size = 4,
            .kty = 2, // EC2
            .x = key,
            .y = key+32
    };

    cwt_encode_cose_key(&cose, buffer, buf_size, len);
}

void cwt_import_key(uint8_t* key, cose_key* cose) {
    memcpy(key, cose->x, 32);
    memcpy(key+32, cose->y, 32);
}
