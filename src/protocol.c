#include <stdlib.h>

#include "protocol.h"
#include "utils.h"
#include "cwt.h"
#include "cose.h"
#include "edhoc.h"
#include "tinycbor/cbor.h"

#if defined(USE_CRYPTOAUTH)
#include "cryptoauthlib.h"
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>


size_t initiate_edhoc(edhoc_u_session_state* ctx, uint8_t* out, size_t out_size) {
    // Generate random connection id
    uint8_t conn_id[32];
#if defined(USE_CRYPTOAUTH)
    atcab_random(conn_id);
#else
    RNG rng;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, conn_id, 32);
#endif
    ctx->connection.conn_id = malloc(CONN_IDENTIFIER_SIZE);
    memcpy(ctx->connection.conn_id, conn_id, CONN_IDENTIFIER_SIZE);
    ctx->connection.conn_size = CONN_IDENTIFIER_SIZE;

    // Generate nonce
    uint8_t nonce[32];
#if defined(USE_CRYPTOAUTH)
    atcab_random(nonce);
#else
    wc_RNG_GenerateBlock(&rng, nonce, 8);
#endif
    // Generate session key
    byte eph_key_pub[64];
#if defined(USE_CRYPTOAUTH)
    atcab_genkey(2, eph_key_pub);
    ctx->eph_key.slot = 2;
#else
    wc_ecc_init(&ctx->eph_key);
    wc_ecc_make_key(&rng, 32, &ctx->eph_key);
    int coordLen = 32;
    wc_ecc_export_public_raw(&ctx->eph_key, eph_key_pub, &coordLen, eph_key_pub + 32, &coordLen);
#endif
    // Encode session key
    uint8_t enc_sess_key[256];
    size_t es_key_size;
    cwt_encode_ecc_key(eph_key_pub, enc_sess_key, sizeof(enc_sess_key), &es_key_size);

    edhoc_msg_1 msg1 = {
            .tag = 1,
            .connection = ctx->connection,
            .nonce = nonce,
            .nonce_size = 8,
            .cose_eph_key = enc_sess_key,//triple-check
            .cose_eph_key_size = es_key_size//triple-check
    };

    size_t size = edhoc_serialize_msg_1(&msg1, out, out_size);

    ctx->message1.size = size;
    ctx->message1.data = out;

    printf("Sending EDHOC MSG1: ");
    phex(out, size);

    // Cleanup
    //free(msg1.connection.conn_id);
    //free(msg1.nonce.buf);
    //free(msg1.eph_key.buf);

    return size;
}

size_t edhoc_handler_message_1(edhoc_v_session_state* ctx, const uint8_t* buffer_in, size_t in_size, uint8_t* out, size_t out_size) {
    // Read msg1
    edhoc_msg_1 msg1;
    edhoc_deserialize_msg1(&msg1, /*triple-check*/(void*)buffer_in, in_size);

    // Save message1 for later
    ctx->message1.size = in_size;
    memcpy(ctx->message1.data, buffer_in, in_size);

    uint8_t conn_id[32];
    // Initialize random generator
#if defined(USE_CRYPTOAUTH)
    atcab_random(conn_id);
#else
    RNG rng;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, conn_id, 2);/*double-check*/
#endif
    ctx->connection.conn_id = malloc(CONN_IDENTIFIER_SIZE);/*triple-check*/
    memcpy(ctx->connection.conn_id, conn_id, CONN_IDENTIFIER_SIZE);
    ctx->connection.conn_size = CONN_IDENTIFIER_SIZE;

    // Generate nonce
    uint8_t nonce[32];
#if defined(USE_CRYPTOAUTH)
    atcab_random(nonce);
#else
    wc_RNG_GenerateBlock(&rng, nonce, 32);
#endif

    // Generate session key
    byte eph_key_pub[64];
#if defined(USE_CRYPTOAUTH)
    atcab_genkey(3, eph_key_pub);
    ctx->eph_key.slot = 3;
#else
    wc_ecc_init(&ctx->eph_key);
    wc_ecc_make_key(&rng, 32, &ctx->eph_key);
    int coordLen = 32;
    wc_ecc_export_public_raw(&ctx->eph_key, eph_key_pub, &coordLen, eph_key_pub + 32, &coordLen);
#endif
    // Decode peer key
    cose_key cose_eph_key;
    cwt_parse_cose_key(msg1.cose_eph_key, msg1.cose_eph_key_size, &cose_eph_key);

    uint8_t peer_eph_key[64];
    cwt_import_key(peer_eph_key, &cose_eph_key);

    printf("Party U Ephemeral Key: {X:");
    for (int i = 0; i < 32; i++)
        printf("%02x", peer_eph_key[i]);
    printf(", Y:");
    for (int i = 0; i < 32; i++)
        printf("%02x", peer_eph_key[32 + i]);
    printf("}\n");

    // Compute shared secret
    int slen = 32;
    uint8_t secret[slen];
#if defined(USE_CRYPTOAUTH)
    atcab_ecdh(3, peer_eph_key, secret);
#else
    ecc_key ecc_peer_key;
    wc_ecc_import_unsigned(&ecc_peer_key, peer_eph_key, peer_eph_key+32, NULL, ECC_SECP256R1);
    wc_ecc_shared_secret(&ctx->eph_key, &ecc_peer_key, secret, &slen);
#endif

    printf("Shared Secret: ");
    phex(secret, 32);

    // Save shared secret to state
    memcpy(ctx->shared_secret, secret, 32);

    // Encode session key
    uint8_t enc_sess_key[256];
    size_t es_key_size;
    cwt_encode_ecc_key(eph_key_pub, enc_sess_key, sizeof(enc_sess_key), &es_key_size);

    edhoc_msg_2 msg2 = {
            .tag = 2,
            .connection = msg1.connection,
            .peer_connection = ctx->connection,/*triple-check*/
            .peer_nonce = nonce,
            .peer_nonce_size = 8,
            .cose_peer_key = enc_sess_key,//{enc_sess_key, n},
            .cose_peer_key_size = es_key_size//{enc_sess_key, n},
    };

    msg_2_context ctx2 = {
            .shared_secret = secret,//(bytes) {secret, 32},
            .message1 = ctx->message1.data,
            .message1_size = ctx->message1.size
    };

    size_t size = edhoc_serialize_msg_2(&msg2, &ctx2, ctx->key, out, out_size);

    ctx->message2.size = size;
    ctx->message2.data = out;

    printf("Sending EDHOC MSG2: ");
    phex(out, size);

    // Cleanup
    //free(msg1.connection.conn_id);
    free(msg1.nonce);
    free(msg1.cose_eph_key);

    return size;
}

size_t edhoc_handler_message_2(edhoc_u_session_state* ctx, const uint8_t* buffer_in, size_t in_size, uint8_t* out, size_t out_size) {
    // Read msg2
    edhoc_msg_2 msg2;
    edhoc_deserialize_msg2(&msg2, (void*)buffer_in, in_size);

    // Save message2 for later
    ctx->message2.size = in_size;
    memcpy(ctx->message2.data, buffer_in, in_size);

    // Compute shared secret
    cose_key cose_peer_key;
    cwt_parse_cose_key(msg2.cose_peer_key, msg2.cose_peer_key_size, &cose_peer_key);

    uint8_t eph_key[64];
    cwt_import_key(eph_key, &cose_peer_key);

    printf("Party V Ephemeral Key: {X:");
    for (int i = 0; i < 32; i++)
        printf("%02x", eph_key[i]);
    printf(", Y:");
    for (int i = 0; i < 32; i++)
        printf("%02x", eph_key[32 + i]);
    printf("}\n");

    int slen = 32;
    uint8_t secret[slen];
#if defined(USE_CRYPTOAUTH)
    atcab_ecdh(2, eph_key, secret);
#else
    ecc_key ecc_peer_key;
    wc_ecc_import_unsigned(&ecc_peer_key, eph_key, eph_key+32, NULL, ECC_SECP256R1);
    wc_ecc_shared_secret(&ctx->eph_key, &ecc_peer_key, secret, &slen);
#endif
    printf("Shared Secret: ");
    phex(secret, 32);

    // Save shared secret to state
    memcpy(ctx->shared_secret, secret, 32);

    // Compute aad2
    uint8_t aad2[SHA256_DIGEST_SIZE];
    edhoc_aad2(&msg2, ctx->message1.data, ctx->message1.size, aad2);
    // Derive k2, iv2
    uint8_t context_info_k2[128];
    size_t ci_k2_size;
    cose_kdf_context("AES-CCM-64-64-128", 16, aad2, SHA256_DIGEST_SIZE, context_info_k2, sizeof(context_info_k2), &ci_k2_size);

    uint8_t context_info_iv2[128];
    size_t ci_iv2_size;
    cose_kdf_context("IV-Generation", 7, aad2, SHA256_DIGEST_SIZE, context_info_iv2, sizeof(context_info_iv2), &ci_iv2_size);

    uint8_t k2[16];
    derive_key(ctx->shared_secret, context_info_k2, ci_k2_size, k2, sizeof(k2));

    uint8_t iv2[7];
    derive_key(ctx->shared_secret, context_info_iv2, ci_iv2_size, iv2, sizeof(iv2));

    printf("K2: ");
    phex(k2, 16);
    printf("IV2: ");
    phex(iv2, 7);

    uint8_t sig_v[256];
    size_t sig_v_size;
    cose_decrypt_enc0(msg2.cose_enc_2, msg2.cose_enc_2_size, k2, iv2, sizeof(iv2), aad2, SHA256_DIGEST_SIZE, sig_v, sizeof(sig_v), &sig_v_size);

    int verified = cose_verify_sign1(sig_v, sig_v_size, &ctx->peer_key/*id_v*//*edhoc_state.pop_key*/, aad2, SHA256_DIGEST_SIZE);

    if (verified != 1) {
        return -1;
    }

    edhoc_msg_3 msg3 = {
            .tag = 3,
            .peer_connection = ctx->connection
    };

    msg_3_context ctx3 = {
            .shared_secret = ctx->shared_secret,
            .message1 = ctx->message1.data,
            .message1_size = ctx->message1.size,
            .message2 = ctx->message2.data,
            .message2_size = ctx->message2.size
    };
    size_t size = edhoc_serialize_msg_3(&msg3, &ctx3, ctx->key, out, out_size);

    ctx->message3.size = size;
    ctx->message3.data = out;

    printf("Sending EDHOC MSG3: ");
    phex(out, size);

    // Cleanup
    //free(msg2.connection.conn_id);
    //free(msg2.peer_connection.conn_id);
    free(msg2.peer_nonce);
    free(msg2.cose_peer_key);
    free(msg2.cose_enc_2);

    return size;
}

void edhoc_handler_message_3(edhoc_v_session_state* ctx, const uint8_t* buffer_in, size_t in_size) {
    // Read msg3
    edhoc_msg_3 msg3;
    edhoc_deserialize_msg3(&msg3, (void*)buffer_in, in_size);

    // Save message3 for later
    ctx->message3.size = in_size;
    memcpy(ctx->message3.data, buffer_in, in_size);

    // Compute aad3
    uint8_t aad3[SHA256_DIGEST_SIZE];
    edhoc_aad3(&msg3, ctx->message1.data, ctx->message1.size, ctx->message2.data, ctx->message2.size, aad3);

    uint8_t context_info_k3[128];
    size_t ci_k3_size;
    cose_kdf_context("AES-CCM-64-64-128", 16, aad3, SHA256_DIGEST_SIZE, context_info_k3, sizeof(context_info_k3), &ci_k3_size);

    uint8_t context_info_iv3[128];
    size_t ci_iv3_size;
    cose_kdf_context("IV-Generation", 7, aad3, SHA256_DIGEST_SIZE, context_info_iv3, sizeof(context_info_iv3), &ci_iv3_size);

    uint8_t k3[16];
    derive_key(ctx->shared_secret, context_info_k3, ci_k3_size, k3, sizeof(k3));

    uint8_t iv3[7];
    derive_key(ctx->shared_secret, context_info_iv3, ci_iv3_size, iv3, sizeof(iv3));

    // printf("AAD3: ");
    // phex(aad3, SHA256_DIGEST_SIZE);
    printf("K3: ");
    phex(k3, 16);
    printf("IV3: ");
    phex(iv3, 7);


    uint8_t sig_u[256];
    size_t sig_u_size;
    cose_decrypt_enc0(msg3.cose_enc_3, msg3.cose_enc_3_size, k3, iv3, sizeof(iv3), aad3, SHA256_DIGEST_SIZE, sig_u, sizeof(sig_u), &sig_u_size);

    int verified = cose_verify_sign1(sig_u, sig_u_size, &ctx->peer_key/*id_u*//*edhoc_state.pop_key*/, aad3, SHA256_DIGEST_SIZE);

    if (verified != 1) {
        return;
    }

    // Cleanup
    //free(msg3.peer_connection.conn_id);
    free(msg3.cose_enc_3);
}