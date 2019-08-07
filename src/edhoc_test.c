#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "utils.h"
#include "ecc.h"
#include "cwt.h"
#include "edhoc.h"
#include "edhoc_protocol.h"
#include "tinycbor/cbor.h"

#if defined(USE_CRYPTOAUTH)
    #include "cryptoauthlib.h"
#elif defined(USE_WOLFSSL)
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/random.h>
    #include <wolfssl/wolfcrypt/ecc.h>
#endif

static edhoc_u_context_t edhoc_u_ctx;
static edhoc_v_context_t edhoc_v_ctx;
uint8_t state_mem[512 * 3];
uint8_t c_state_mem[512 * 3];

uint8_t id_u[64];
uint8_t id_v[64];
uint8_t AS_ID[64] = {0x5a, 0xee, 0xc3, 0x1f, 0x9e, 0x64, 0xaa, 0xd4, 0x5a, 0xba, 0x2d, 0x36, 0x5e, 0x71, 0xe8, 0x4d, 0xee, 0x0d, 0xa3, 0x31, 0xba, 0xda, 0xb9, 0x11, 0x8a, 0x25, 0x31, 0x50, 0x1f, 0xd9, 0x86, 0x1d,
                     0x02, 0x7c, 0x99, 0x77, 0xca, 0x32, 0xd5, 0x44, 0xe6, 0x34, 0x26, 0x76, 0xef, 0x00, 0xfa, 0x43, 0x4b, 0x3a, 0xae, 0xd9, 0x9f, 0x48, 0x23, 0x75, 0x05, 0x17, 0xca, 0x33, 0x90, 0x37, 0x47, 0x53};


static size_t error_buffer(uint8_t* buf, size_t buf_len, char* text) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, buf_len, 0);

    CborEncoder map;
    cbor_encoder_create_map(&enc, &map, 1);

    cbor_encode_text_stringz(&map, "error");
    cbor_encode_text_stringz(&map, text);
    cbor_encoder_close_container(&enc, &map);

    return cbor_encoder_get_buffer_size(&enc, buf);
}

int edhoc_test() {
    // Allocate space for stored messages
    edhoc_v_ctx.message1.data = state_mem;
    edhoc_v_ctx.message2.data = state_mem + 512;
    edhoc_v_ctx.message3.data = state_mem + 1024;
    edhoc_v_ctx.shared_secret = malloc(32);

    edhoc_u_ctx.message1.data = c_state_mem;
    edhoc_u_ctx.message2.data = c_state_mem + 512;
    edhoc_u_ctx.message3.data = c_state_mem + 1024;
    edhoc_u_ctx.shared_secret = malloc(32);

#if defined(USE_CRYPTOAUTH)
    uint32_t revision;
    uint32_t serial[(ATCA_SERIAL_NUM_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
    bool config_is_locked, data_is_locked;
    ATCA_STATUS status;

    ATCAIfaceCfg cfg = cfg_ateccx08a_i2c_default;
    cfg.atcai2c.bus = 1;
    cfg.atcai2c.baud = 400000;
    //cfg.devtype = ATECC608A;

    status = atcab_init(&cfg);
    if (status != ATCA_SUCCESS) {
        printf("ATCA: Library init failed\n");
        goto out;
    }

    status = atcab_info((uint8_t *) &revision);
    if (status != ATCA_SUCCESS) {
        printf("ATCA: Failed to get chip info\n");
        goto out;
    }

    status = atcab_read_serial_number((uint8_t *) serial);
    if (status != ATCA_SUCCESS) {
        printf("ATCA: Failed to get chip serial number\n");
        goto out;
    }

    status = atcab_is_locked(LOCK_ZONE_CONFIG, &config_is_locked);
    status = atcab_is_locked(LOCK_ZONE_DATA, &data_is_locked);
    if (status != ATCA_SUCCESS) {
        printf("ATCA: Failed to get chip zone lock status\n");
        goto out;
    }

    printf("ATECCx08 @ 0x%02x: rev 0x%04x S/N 0x%04x%04x%02x, zone "
        "lock status: %s, %s\n",
        cfg.atcai2c.slave_address >> 1, htonl(revision), htonl(serial[0]), htonl(serial[1]),
        *((uint8_t *) &serial[2]), (config_is_locked ? "yes" : "no"),
        (data_is_locked ? "yes" : "no"));

    edhoc_v_ctx.key.slot = 0;
    status = atcab_get_pubkey(1, id_v);
    memcpy(edhoc_v_ctx.peer_key.pubkey_raw, id_v, sizeof(id_v));
    status = atcab_write_pubkey(4, id_v);
    if (status != ATCA_SUCCESS) {
        printf("ATCA: Failed to write the public key to slot %i\n", 4);
        goto out;
    }
    edhoc_v_ctx.peer_key.slot = 4;
    edhoc_u_ctx.key.slot = 1;
    status = atcab_get_pubkey(0, id_u);
    memcpy(edhoc_u_ctx.peer_key.pubkey_raw, id_u, sizeof(id_u));
    status = atcab_write_pubkey(5, id_u);
    if (status != ATCA_SUCCESS) {
        printf("ATCA: Failed to write the public key to slot %i\n", 5);
        goto out;
    }
    edhoc_u_ctx.peer_key.slot = 5;
#elif defined(USE_WOLFSSL)
    RNG rng;
    wc_InitRng(&rng);

    wc_ecc_init(&(edhoc_v_ctx.key));
    wc_ecc_make_key(&rng, 32, &(edhoc_v_ctx.key));

    byte pub_key[65];
    word32 pub_key_len = sizeof(pub_key);
    wc_ecc_export_x963(&edhoc_v_ctx.key, pub_key, &pub_key_len);
    wc_ecc_import_x963(pub_key, pub_key_len, &edhoc_u_ctx.peer_key);

    wc_ecc_init(&(edhoc_u_ctx.key));
    wc_ecc_make_key(&rng, 32, &(edhoc_u_ctx.key));

    wc_ecc_export_x963(&edhoc_u_ctx.key, pub_key, &pub_key_len);
    wc_ecc_import_x963(pub_key, pub_key_len, &edhoc_v_ctx.peer_key);
#endif
    uint8_t message1_buf[512];
    uint8_t message2_buf[512];
    uint8_t message3_buf[512];
    size_t message1_len = initiate_edhoc(&edhoc_u_ctx, message1_buf, 512);
    size_t message2_len = edhoc_handler_message_1(&edhoc_v_ctx, message1_buf, message1_len, message2_buf, 512);
    size_t message3_len = edhoc_handler_message_2(&edhoc_u_ctx, message2_buf, message2_len, message3_buf, 512);
    edhoc_handler_message_3(&edhoc_v_ctx, message3_buf, message3_len);
    oscore_context_t oscore_ctx;
    compute_oscore_context(&edhoc_u_ctx, &oscore_ctx);
    uint8_t unprotected_h[] = {0xa2, 0x04, 0x41, 0x25, 0x06, 0x41, 0x05};
    uint8_t payload[9] = "PLAINTEXT";
    cose_encrypt0 encrypt0 = {
        .unprotected_header = unprotected_h,
        .unprotected_header_size = sizeof(unprotected_h),/*see OSCORE #5*/
        .plaintext = payload,
        .plaintext_size = sizeof(payload),
    };
    uint8_t cose[256];
    size_t cose_size = sizeof(cose);
    cose_encode_encrypted(&encrypt0, oscore_ctx.master_secret, oscore_ctx.master_salt, sizeof(oscore_ctx.master_salt), cose, cose_size, &cose_size);
    uint8_t plaintext[24];
    size_t plaintext_size = sizeof(plaintext);
    cose_decrypt_enc0(cose, cose_size, oscore_ctx.master_secret, oscore_ctx.master_salt, sizeof(oscore_ctx.master_salt), NULL, 0, plaintext, plaintext_size, &plaintext_size);
    fwrite(plaintext, sizeof(uint8_t), plaintext_size, stdout);
    fwrite("\n", 1, 1, stdout);

out:
#if defined(USE_CRYPTOAUTH)
    /*
    * We do not free atca_cfg in case of an error even if it was allocated
    * because it is referenced by ATCA basic object.
    */
    if (status != ATCA_SUCCESS) {
        printf("ATCA: Chip is not available");
        /* In most cases the device can still work, so we continue anyway. */
    }
#endif
    return strncmp((char *)plaintext, (char *)payload, plaintext_size);
}