#include "oscore_test.h"
#include "utils.h"
#include "oscore.h"
#include "stdio.h"
#include <string.h>

//rfc8613#appendix-C.1.1
int oscore_test_1() {
    uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t master_salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
    uint8_t sender_id[0] = {};
    uint8_t recipient_id[1] = {0x01};

    uint8_t key_S[16];
    uint8_t key_R[16];
    uint8_t common_IV[13];
    uint8_t nonce[13];

    uint8_t expected_key_S[16] = {0xf0, 0x91, 0x0e, 0xd7, 0x29, 0x5e, 0x6a, 0xd4,
                                  0xb5, 0x4f, 0xc7, 0x93, 0x15, 0x43, 0x02, 0xff};
    uint8_t expected_key_R[16] = {0xff, 0xb1, 0x4e, 0x09, 0x3c, 0x94, 0xc9, 0xca,
                                  0xc9, 0x47, 0x16, 0x48, 0xb4, 0xf9, 0x87, 0x10};
    uint8_t expected_IV[13] = {0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x7c};
    uint8_t expected_nonce[13] = {0x46, 0x22, 0xd4, 0xdd, 0x6d, 0x94, 0x41, 0x68, 0xee, 0xfb, 0x54, 0x98, 0x7c};

    oscore_c_ctx_t c_ctx = {
            .alg_aead = AES_CCM_16_64_128,
            .master_secret = master_secret,
            .secret_size = sizeof(master_secret),
            .master_salt = master_salt,
            .salt_size = sizeof(master_salt),
            .common_iv = common_IV,
            .common_iv_size = sizeof(common_IV)
    };
    oscore_s_ctx_t s_ctx = {
            .id = sender_id,
            .id_size = sizeof(sender_id),
            .key = key_S,
            .key_size = sizeof(key_S)
    };
    oscore_r_ctx_t r_ctx = {
            .id = recipient_id,
            .id_size = sizeof(recipient_id),
            .key = key_R,
            .key_size = sizeof(key_R)
    };
    derive_context(&c_ctx, &s_ctx, &r_ctx);
    derive_nonce(&c_ctx, &s_ctx, nonce);

    /*printf("Sender\n");
    phex(s_ctx.key, s_ctx.key_size);
    phex(expected_key_S, sizeof(expected_key_S));
    printf("Recipient\n");
    phex(r_ctx.key, r_ctx.key_size);
    phex(expected_key_R, sizeof(expected_key_R));
    printf("IV\n");
    phex(c_ctx.common_iv, c_ctx.common_iv_size);
    phex(expected_IV, sizeof(expected_IV));
    printf("NONCE\n");
    phex(nonce, sizeof(nonce));
    phex(expected_nonce, sizeof(expected_nonce));*/

    int sk = memcmp(s_ctx.key, expected_key_S, sizeof(expected_key_S));
    int rk = memcmp(r_ctx.key, expected_key_R, sizeof(expected_key_R));
    int iv = memcmp(c_ctx.common_iv, expected_IV, sizeof(expected_IV));
    int nc = memcmp(nonce, expected_nonce, sizeof(expected_nonce));

    return sk || rk || iv || nc;
}

//rfc8613#appendix-C.2.1
int oscore_test_2() {
    uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t master_salt[0] = {};
    uint8_t sender_id[1] = {0x00};
    uint8_t recipient_id[1] = {0x01};

    uint8_t key_S[16];
    uint8_t key_R[16];
    uint8_t common_IV[13];
    uint8_t nonce[13];

    uint8_t expected_key_S[16] = {0x32, 0x1b, 0x26, 0x94, 0x32, 0x53, 0xc7, 0xff,
                                  0xb6, 0x00, 0x3b, 0x0b, 0x64, 0xd7, 0x40, 0x41};
    uint8_t expected_key_R[16] = {0xe5, 0x7b, 0x56, 0x35, 0x81, 0x51, 0x77, 0xcd,
                                  0x67, 0x9a, 0xb4, 0xbc, 0xec, 0x9d, 0x7d, 0xda};
    uint8_t expected_IV[13] = {0xbe, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9, 0x10, 0xc5, 0x2e, 0x99, 0xf9};
    uint8_t expected_nonce[13] = {0xbf, 0x35, 0xae, 0x29, 0x7d, 0x2d, 0xac, 0xe9, 0x10, 0xc5, 0x2e, 0x99, 0xf9};

    oscore_c_ctx_t c_ctx = {
            .alg_aead = AES_CCM_16_64_128,
            .master_secret = master_secret,
            .secret_size = sizeof(master_secret),
            .master_salt = master_salt,
            .salt_size = sizeof(master_salt),
            .common_iv = common_IV,
            .common_iv_size = sizeof(common_IV)
    };
    oscore_s_ctx_t s_ctx = {
            .id = sender_id,
            .id_size = sizeof(sender_id),
            .key = key_S,
            .key_size = sizeof(key_S)
    };
    oscore_r_ctx_t r_ctx = {
            .id = recipient_id,
            .id_size = sizeof(recipient_id),
            .key = key_R,
            .key_size = sizeof(key_R)
    };
    derive_context(&c_ctx, &s_ctx, &r_ctx);
    derive_nonce(&c_ctx, &s_ctx, nonce);

    /*printf("Sender\n");
    phex(s_ctx.key, s_ctx.key_size);
    phex(expected_key_S, sizeof(expected_key_S));
    printf("Recipient\n");
    phex(r_ctx.key, r_ctx.key_size);
    phex(expected_key_R, sizeof(expected_key_R));
    printf("IV\n");
    phex(c_ctx.common_iv, c_ctx.common_iv_size);
    phex(expected_IV, sizeof(expected_IV));
    printf("NONCE\n");
    phex(nonce, sizeof(nonce));
    phex(expected_nonce, sizeof(expected_nonce));*/

    int sk = memcmp(s_ctx.key, expected_key_S, sizeof(expected_key_S));
    int rk = memcmp(r_ctx.key, expected_key_R, sizeof(expected_key_R));
    int iv = memcmp(c_ctx.common_iv, expected_IV, sizeof(expected_IV));
    int nc = memcmp(nonce, expected_nonce, sizeof(expected_nonce));

    return sk || rk || iv || nc;
}

//rfc8613#appendix-C.3.1
int oscore_test_3() {
    uint8_t master_secret[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t master_salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40};
    uint8_t sender_id[0] = {};
    uint8_t recipient_id[1] = {0x01};
    uint8_t ID_context[8] = {0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3};

    uint8_t key_S[16];
    uint8_t key_R[16];
    uint8_t common_IV[13];
    uint8_t nonce[13];

    uint8_t expected_key_S[16] = {0xaf, 0x2a, 0x13, 0x00, 0xa5, 0xe9, 0x57, 0x88,
                                  0xb3, 0x56, 0x33, 0x6e, 0xee, 0xcd, 0x2b, 0x92};
    uint8_t expected_key_R[16] = {0xe3, 0x9a, 0x0c, 0x7c, 0x77, 0xb4, 0x3f, 0x03,
                                  0xb4, 0xb3, 0x9a, 0xb9, 0xa2, 0x68, 0x69, 0x9f};
    uint8_t expected_IV[13] = {0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c, 0x0b, 0x71, 0x81, 0xb8, 0x5e};
    uint8_t expected_nonce[13] = {0x2c, 0xa5, 0x8f, 0xb8, 0x5f, 0xf1, 0xb8, 0x1c, 0x0b, 0x71, 0x81, 0xb8, 0x5e};

    oscore_c_ctx_t c_ctx = {
            .alg_aead = AES_CCM_16_64_128,
            .master_secret = master_secret,
            .secret_size = sizeof(master_secret),
            .master_salt = master_salt,
            .salt_size = sizeof(master_salt),
            .common_iv = common_IV,
            .common_iv_size = sizeof(common_IV),
            .id_context = ID_context,
            .id_ctx_size = sizeof(ID_context)
    };
    oscore_s_ctx_t s_ctx = {
            .id = sender_id,
            .id_size = sizeof(sender_id),
            .key = key_S,
            .key_size = sizeof(key_S)
    };
    oscore_r_ctx_t r_ctx = {
            .id = recipient_id,
            .id_size = sizeof(recipient_id),
            .key = key_R,
            .key_size = sizeof(key_R)
    };
    derive_context(&c_ctx, &s_ctx, &r_ctx);
    derive_nonce(&c_ctx, &s_ctx, nonce);

    /*printf("Sender\n");
    phex(s_ctx.key, s_ctx.key_size);
    phex(expected_key_S, sizeof(expected_key_S));
    printf("Recipient\n");
    phex(r_ctx.key, r_ctx.key_size);
    phex(expected_key_R, sizeof(expected_key_R));
    printf("IV\n");
    phex(c_ctx.common_iv, c_ctx.common_iv_size);
    phex(expected_IV, sizeof(expected_IV));
    printf("NONCE\n");
    phex(nonce, sizeof(nonce));
    phex(expected_nonce, sizeof(expected_nonce));*/

    int sk = memcmp(s_ctx.key, expected_key_S, sizeof(expected_key_S));
    int rk = memcmp(r_ctx.key, expected_key_R, sizeof(expected_key_R));
    int iv = memcmp(c_ctx.common_iv, expected_IV, sizeof(expected_IV));
    int nc = memcmp(nonce, expected_nonce, sizeof(expected_nonce));

    return sk || rk || iv || nc;
}