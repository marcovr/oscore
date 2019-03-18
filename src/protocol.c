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


size_t initiate_edhoc(edhoc_client_session_state* ctx, uint8_t* out, size_t out_size) {
    // Generate random session id
    uint8_t session_id[32];
#if defined(USE_CRYPTOAUTH)
    atcab_random(session_id);
#else
    RNG rng;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, session_id, 2);
#endif
    ctx->session_id = (bytes){ session_id, 2 };

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
    size_t n;
    cwt_encode_ecc_key(eph_key_pub, enc_sess_key, sizeof(enc_sess_key), &n);

    edhoc_msg_1 msg1 = {
            .tag = 1,
            .session_id = (bytes){ session_id, 2 },
            .nonce = {nonce, 8},
            .eph_key = {enc_sess_key, n},
    };

    size_t len = edhoc_serialize_msg_1(&msg1, out, out_size);

    ctx->message1.len = len;
    ctx->message1.buf = out;

    printf("Sending EDHOC MSG1: ");
    phex(out, len);

    // Cleanup
    //free(msg1.session_id.buf);
    //free(msg1.nonce.buf);
    //free(msg1.eph_key.buf);

    return len;
}

size_t edhoc_handler_message_1(edhoc_server_session_state* ctx, const uint8_t* buffer_in, size_t in_len, uint8_t* out, size_t out_size) {
    // Read msg1
    edhoc_msg_1 msg1;
    edhoc_deserialize_msg1(&msg1, (void*)buffer_in, in_len);

    // Save message1 for later
    ctx->message1.len = in_len;
    memcpy(ctx->message1.buf, buffer_in, in_len);

    uint8_t session_id[32];
    // Initialize random generator
#if defined(USE_CRYPTOAUTH)
    atcab_random(session_id);
#else
    RNG rng;
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, session_id, 32);
#endif
    ctx->session_id = (bytes){ session_id, 2 };

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
    cwt_parse_cose_key(&msg1.eph_key, &cose_eph_key);

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
    memcpy(ctx->shared_secret.buf, secret, 32);

    // Encode session key
    uint8_t enc_sess_key[256];
    size_t n;
    cwt_encode_ecc_key(eph_key_pub, enc_sess_key, sizeof(enc_sess_key), &n);

    edhoc_msg_2 msg2 = {
            .tag = 2,
            .session_id = msg1.session_id,
            .peer_session_id = ctx->session_id,
            .peer_nonce = {nonce, 8},
            .peer_key = {enc_sess_key, n},
    };

    msg_2_context ctx2 = {
            .shared_secret = (bytes) {secret, 32},
            .message1 = ctx->message1
    };

    size_t len = edhoc_serialize_msg_2(&msg2, &ctx2, ctx->key, out, out_size);

    ctx->message2.len = len;
    ctx->message2.buf = out;

    printf("Sending EDHOC MSG2: ");
    phex(out, len);

    // Cleanup
    free(msg1.session_id.buf);
    free(msg1.nonce.buf);
    free(msg1.eph_key.buf);

    return len;
}

size_t edhoc_handler_message_2(edhoc_client_session_state* ctx, const uint8_t* buffer_in, size_t in_len, uint8_t* out, size_t out_size) {
    // Read msg2
    edhoc_msg_2 msg2;
    edhoc_deserialize_msg2(&msg2, (void*)buffer_in, in_len);

    // Save message2 for later
    ctx->message2.len = in_len;
    memcpy(ctx->message2.buf, buffer_in, in_len);

    // Compute shared secret
    cose_key cose_peer_key;
    cwt_parse_cose_key(&msg2.peer_key, &cose_peer_key);

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
    memcpy(ctx->shared_secret.buf, secret, 32);

    // Compute aad2
    uint8_t aad2[SHA256_DIGEST_SIZE];
    edhoc_aad2(&msg2, ctx->message1, aad2);
    // Derive k2, iv2
    bytes other = {aad2, SHA256_DIGEST_SIZE};
    uint8_t context_info_k2[128];
    size_t ci_k2_len;
    cose_kdf_context("AES-CCM-64-64-128", 16, &other, context_info_k2, sizeof(context_info_k2), &ci_k2_len);

    uint8_t context_info_iv2[128];
    size_t ci_iv2_len;
    cose_kdf_context("IV-Generation", 7, &other, context_info_iv2, sizeof(context_info_iv2), &ci_iv2_len);

    bytes b_ci_k2 = {context_info_k2, ci_k2_len};
    bytes b_ci_iv2 = {context_info_iv2, ci_iv2_len};

    uint8_t k2[16];
    derive_key(&ctx->shared_secret, &b_ci_k2, k2, sizeof(k2));

    uint8_t iv2[7];
    derive_key(&ctx->shared_secret, &b_ci_iv2, iv2, sizeof(iv2));

    printf("K2: ");
    phex(k2, 16);
    printf("IV2: ");
    phex(iv2, 7);

    bytes b_aad2 = {aad2, SHA256_DIGEST_SIZE};

    uint8_t sig_v[256];
    size_t sig_v_len;
    cose_decrypt_enc0(&msg2.cose_enc_2, k2, iv2, &b_aad2, sig_v, sizeof(sig_v), &sig_v_len);

    bytes b_sig_v = {sig_v, sig_v_len};
    int verified = cose_verify_sign1(&b_sig_v, &ctx->peer_key/*id_v*//*edhoc_state.pop_key*/, &b_aad2);
    if (verified != 1) {
        return -1;
    }

    edhoc_msg_3 msg3 = {
            .tag = 3,
            .peer_session_id = ctx->session_id
    };

    msg_3_context ctx3 = {
            .shared_secret = (bytes) {secret, 32},
            .message1 = ctx->message1,
            .message2 = ctx->message2
    };
    size_t len = edhoc_serialize_msg_3(&msg3, &ctx3, ctx->key, out, out_size);

    ctx->message3.len = len;
    ctx->message3.buf = out;

    printf("Sending EDHOC MSG3: ");
    phex(out, len);

    // Cleanup
    free(msg2.session_id.buf);
    free(msg2.peer_session_id.buf);
    free(msg2.peer_nonce.buf);
    free(msg2.peer_key.buf);
    free(msg2.cose_enc_2.buf);

    return len;
}

void edhoc_handler_message_3(edhoc_server_session_state* ctx, const uint8_t* buffer_in, size_t in_len) {
    // Read msg3
    edhoc_msg_3 msg3;
    edhoc_deserialize_msg3(&msg3, (void*)buffer_in, in_len);

    // Save message3 for later
    ctx->message3.len = in_len;
    memcpy(ctx->message3.buf, buffer_in, in_len);

    // Compute aad3
    uint8_t aad3[SHA256_DIGEST_SIZE];
    edhoc_aad3(&msg3, ctx->message1, ctx->message2, aad3);

    // Derive k3, iv3
    bytes other = {aad3, SHA256_DIGEST_SIZE};

    uint8_t context_info_k3[128];
    size_t ci_k3_len;
    cose_kdf_context("AES-CCM-64-64-128", 16, &other, context_info_k3, sizeof(context_info_k3), &ci_k3_len);

    uint8_t context_info_iv3[128];
    size_t ci_iv3_len;
    cose_kdf_context("IV-Generation", 7, &other, context_info_iv3, sizeof(context_info_iv3), &ci_iv3_len);

    bytes b_ci_k3 = {context_info_k3, ci_k3_len};
    bytes b_ci_iv3 = {context_info_iv3, ci_iv3_len};

    uint8_t k3[16];
    derive_key(&ctx->shared_secret, &b_ci_k3, k3, sizeof(k3));

    uint8_t iv3[7];
    derive_key(&ctx->shared_secret, &b_ci_iv3, iv3, sizeof(iv3));

    // printf("AAD3: ");
    // phex(aad3, SHA256_DIGEST_SIZE);
    printf("K3: ");
    phex(k3, 16);
    printf("IV3: ");
    phex(iv3, 7);

    bytes b_aad3 = {aad3, SHA256_DIGEST_SIZE};

    uint8_t sig_u[256];
    size_t sig_u_len;
    cose_decrypt_enc0(&msg3.cose_enc_3, k3, iv3, &b_aad3, sig_u, sizeof(sig_u), &sig_u_len);

    bytes b_sig_u = {sig_u, sig_u_len};
    int verified = cose_verify_sign1(&b_sig_u, &ctx->peer_key/*id_u*//*edhoc_state.pop_key*/, &b_aad3);

    if (verified != 1) {
        return;
    }

    // Cleanup
    free(msg3.peer_session_id.buf);
    free(msg3.cose_enc_3.buf);
}