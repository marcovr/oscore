#include <stdio.h>

#include "mongoose.h"
#include "cryptoauthlib.h"
#include "utils.h"
#include "cwt.h"
#include "edhoc.h"
#include "tinycbor/cbor.h"

#define AUDIENCE "tempSensor0"
#define SHA256_DIGEST_SIZE 32

static const char *s_listening_address = "tcp://:8000";

static edhoc_server_session_state edhoc_state;
static edhoc_client_session_state edhoc_c_state;
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

static size_t initiate_edhoc(uint8_t* out, size_t out_size) {
    // Generate random session id
    uint8_t session_id[32];
    atcab_random(session_id);
    edhoc_c_state.session_id = (bytes){ session_id, 2 };

    // Generate nonce
    uint8_t nonce[32];
    atcab_random(nonce);

    // Generate session key
    uint8_t session_key[64];
    atcab_genkey(2, session_key);

    // Encode session key
    uint8_t enc_sess_key[256];
    size_t n;
    cwt_encode_ecc_key(session_key, enc_sess_key, sizeof(enc_sess_key), &n);

    edhoc_msg_1 msg1 = {
            .tag = 1,
            .session_id = (bytes){ session_id, 2 },
            .nonce = {nonce, 8},
            .eph_key = {enc_sess_key, n},
    };

    size_t len = edhoc_serialize_msg_1(&msg1, out, out_size);

    edhoc_c_state.message1.len = len;
    edhoc_c_state.message1.buf = out;

    printf("Sending EDHOC MSG1: ");
    phex(out, len);

    // Cleanup
    //free(msg1.session_id.buf);
    //free(msg1.nonce.buf);
    //free(msg1.eph_key.buf);

    return len;
}

static size_t edhoc_handler_message_1(const uint8_t* buffer_in, size_t in_len, uint8_t* out, size_t out_size) {
    // Read msg1
    edhoc_msg_1 msg1;
    edhoc_deserialize_msg1(&msg1, (void*)buffer_in, in_len);

    // Save message1 for later
    edhoc_state.message1.len = in_len;
    memcpy(edhoc_state.message1.buf, buffer_in, in_len);

    // Generate random session id
    uint8_t session_id[32];
    atcab_random(session_id);
    edhoc_state.session_id = (bytes){ session_id, 2 };

    // Generate nonce
    uint8_t nonce[32];
    atcab_random(nonce);

    // Generate session key
    uint8_t session_key[64];
    atcab_genkey(3, session_key);

    // Compute shared secret
    cose_key cose_eph_key;
    cwt_parse_cose_key(&msg1.eph_key, &cose_eph_key);

    uint8_t eph_key[64];
    cwt_import_key(eph_key, &cose_eph_key);

    printf("Party U Ephemeral Key: {X:");
    for (int i = 0; i < 32; i++)
        printf("%02x", eph_key[i]);
    printf(", Y:");
    for (int i = 0; i < 32; i++)
        printf("%02x", eph_key[32 + i]);
    printf("}\n");

    uint8_t secret[32];
    atcab_ecdh(3, eph_key, secret);

    printf("Shared Secret: ");
    phex(secret, 32);

    // Save shared secret to state
    memcpy(edhoc_state.shared_secret.buf, secret, 32);

    // Encode session key
    uint8_t enc_sess_key[256];
    size_t n;
    cwt_encode_ecc_key(session_key, enc_sess_key, sizeof(enc_sess_key), &n);

    edhoc_msg_2 msg2 = {
            .tag = 2,
            .session_id = msg1.session_id,
            .peer_session_id = edhoc_state.session_id,
            .peer_nonce = {nonce, 8},
            .peer_key = {enc_sess_key, n},
    };

    msg_2_context ctx2 = {
            .shared_secret = (bytes) {secret, 32},
            .message1 = edhoc_state.message1
    };

    size_t len = edhoc_serialize_msg_2(&msg2, &ctx2, 0, out, out_size);

    edhoc_state.message2.len = len;
    edhoc_state.message2.buf = out;

    printf("Sending EDHOC MSG2: ");
    phex(out, len);

    // Cleanup
    free(msg1.session_id.buf);
    free(msg1.nonce.buf);
    free(msg1.eph_key.buf);

    return len;
}

static size_t edhoc_handler_message_2(const uint8_t* buffer_in, size_t in_len, uint8_t* out, size_t out_size) {
    // Read msg2
    edhoc_msg_2 msg2;
    edhoc_deserialize_msg2(&msg2, (void*)buffer_in, in_len);

    // Save message2 for later
    edhoc_c_state.message2.len = in_len;
    memcpy(edhoc_c_state.message2.buf, buffer_in, in_len);

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

    uint8_t secret[32];
    atcab_ecdh(2, eph_key, secret);

    printf("Shared Secret: ");
    phex(secret, 32);

    // Save shared secret to state
    memcpy(edhoc_c_state.shared_secret.buf, secret, 32);

    // Compute aad2
    uint8_t aad2[SHA256_DIGEST_SIZE];
    edhoc_aad2(&msg2, edhoc_c_state.message1, aad2);

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
    derive_key(&edhoc_c_state.shared_secret, &b_ci_k2, k2, sizeof(k2));

    uint8_t iv2[7];
    derive_key(&edhoc_c_state.shared_secret, &b_ci_iv2, iv2, sizeof(iv2));

    printf("K2: ");
    phex(k2, 16);
    printf("IV2: ");
    phex(iv2, 7);

    bytes b_aad2 = {aad2, SHA256_DIGEST_SIZE};

    uint8_t sig_v[256];
    size_t sig_v_len;
    cose_decrypt_enc0(&msg2.cose_enc_2, k2, iv2, &b_aad2, sig_v, sizeof(sig_v), &sig_v_len);

    bytes b_sig_v = {sig_v, sig_v_len};
    int verified = cose_verify_sign1(&b_sig_v, id_v/*edhoc_state.pop_key*/, &b_aad2);

    if (verified != 1) {
        return -1;
    }

    edhoc_msg_3 msg3 = {
            .tag = 3,
            .peer_session_id = edhoc_c_state.session_id
    };

    msg_3_context ctx3 = {
            .shared_secret = (bytes) {secret, 32},
            .message1 = edhoc_c_state.message1,
            .message2 = edhoc_c_state.message2
    };

    size_t len = edhoc_serialize_msg_3(&msg3, &ctx3, 1, out, out_size);

    edhoc_c_state.message3.len = len;
    edhoc_c_state.message3.buf = out;

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

static void edhoc_handler_message_3(const uint8_t* buffer_in, size_t in_len) {
    // Read msg3
    edhoc_msg_3 msg3;
    edhoc_deserialize_msg3(&msg3, (void*)buffer_in, in_len);

    // Save message3 for later
    edhoc_state.message3.len = in_len;
    memcpy(edhoc_state.message3.buf, buffer_in, in_len);

    // Compute aad3
    uint8_t aad3[SHA256_DIGEST_SIZE];
    edhoc_aad3(&msg3, edhoc_state.message1, edhoc_state.message2, aad3);

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
    derive_key(&edhoc_state.shared_secret, &b_ci_k3, k3, sizeof(k3));

    uint8_t iv3[7];
    derive_key(&edhoc_state.shared_secret, &b_ci_iv3, iv3, sizeof(iv3));

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
    int verified = cose_verify_sign1(&b_sig_u, id_u/*edhoc_state.pop_key*/, &b_aad3);

    if (verified != 1) {
        return -1;
    }

    // Cleanup
    free(msg3.peer_session_id.buf);
    free(msg3.cose_enc_3.buf);
}

int main(int argc, char *argv[]) {
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

    // Allocate space for stored messages
    edhoc_state.message1.buf = state_mem;
    edhoc_state.message2.buf = state_mem + 512;
    edhoc_state.message3.buf = state_mem + 1024; 
    edhoc_state.shared_secret.buf = malloc(32);
    edhoc_state.shared_secret.len = 32;

    edhoc_c_state.message1.buf = c_state_mem;
    edhoc_c_state.message2.buf = c_state_mem + 512;
    edhoc_c_state.message3.buf = c_state_mem + 1024; 
    edhoc_c_state.shared_secret.buf = malloc(32);
    edhoc_c_state.shared_secret.len = 32;

    atcab_get_pubkey(1, id_u);
    printf("U public ID: {X:");
    for (int i = 0; i < 32; i++)
        printf("%02x", id_u[i]);
    printf(", Y:");
    for (int i = 0; i < 32; i++)
        printf("%02x", id_u[32 + i]);
    printf("}\n");
    atcab_get_pubkey(0, id_v);
    printf("V public ID: {X:");
    for (int i = 0; i < 32; i++)
        printf("%02x", id_v[i]);
    printf(", Y:");
    for (int i = 0; i < 32; i++)
        printf("%02x", id_v[32 + i]);
    printf("}\n");

    uint8_t message1_buf[512];
    uint8_t message2_buf[512];
    uint8_t message3_buf[512];
    size_t message1_len = initiate_edhoc(message1_buf, 512);
    size_t message2_len = edhoc_handler_message_1(message1_buf, message1_len, message2_buf, 512);
    size_t message3_len = edhoc_handler_message_2(message2_buf, message2_len, message3_buf, 512);
    edhoc_handler_message_3(message3_buf, message3_len);

out:
    /*
    * We do not free atca_cfg in case of an error even if it was allocated
    * because it is referenced by ATCA basic object.
    */
    if (status != ATCA_SUCCESS) {
        printf("ATCA: Chip is not available");
        /* In most cases the device can still work, so we continue anyway. */
    }
    return 0;
}