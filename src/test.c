#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "cryptoauthlib.h"
#include "utils.h"
#include "cwt.h"
#include "edhoc.h"
#include "protocol.h"
#include "tinycbor/cbor.h"


static edhoc_server_session_state edhoc_state;
static edhoc_client_session_state edhoc_c_state;
uint8_t state_mem[512 * 3];
uint8_t c_state_mem[512 * 3];

uint8_t id_u[64];
uint8_t id_v[64];
uint8_t AS_ID[64] = {0x5a, 0xee, 0xc3, 0x1f, 0x9e, 0x64, 0xaa, 0xd4, 0x5a, 0xba, 0x2d, 0x36, 0x5e, 0x71, 0xe8, 0x4d, 0xee, 0x0d, 0xa3, 0x31, 0xba, 0xda, 0xb9, 0x11, 0x8a, 0x25, 0x31, 0x50, 0x1f, 0xd9, 0x86, 0x1d,
                     0x02, 0x7c, 0x99, 0x77, 0xca, 0x32, 0xd5, 0x44, 0xe6, 0x34, 0x26, 0x76, 0xef, 0x00, 0xfa, 0x43, 0x4b, 0x3a, 0xae, 0xd9, 0x9f, 0x48, 0x23, 0x75, 0x05, 0x17, 0xca, 0x33, 0x90, 0x37, 0x47, 0x53};


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
    memcpy(edhoc_state.pub_key, id_u, sizeof(id_u));
    memcpy(edhoc_c_state.pub_key, id_v, sizeof(id_v));

    uint8_t message1_buf[512];
    uint8_t message2_buf[512];
    uint8_t message3_buf[512];
    size_t message1_len = initiate_edhoc(&edhoc_c_state, message1_buf, 512);
    size_t message2_len = edhoc_handler_message_1(&edhoc_state, message1_buf, message1_len, message2_buf, 512);
    size_t message3_len = edhoc_handler_message_2(&edhoc_c_state, message2_buf, message2_len, message3_buf, 512);
    edhoc_handler_message_3(&edhoc_state, message3_buf, message3_len);

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