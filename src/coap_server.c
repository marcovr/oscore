#include <arpa/inet.h>

#include "cryptoauthlib.h"
#include "mongoose.h"
#include "tinycbor/cbor.h"
#include "edhoc.h"
#include "protocol.h"

static edhoc_server_session_state edhoc_ctx;
uint8_t id_u[64];

uint8_t message2_buf[512];

static char *s_default_address = "udp://:5683";
static int s_sig_received = 0;

static void signal_handler(int sig_num) {
  signal(sig_num, signal_handler);
  s_sig_received = sig_num;
}

static void coap_handler(struct mg_connection *nc, int ev, void *p) {
  switch (ev) {
    case MG_EV_COAP_CON: {
      uint32_t res;
      struct mg_coap_message *cm = (struct mg_coap_message *) p;
      printf("CON with msg_id = %d received\n", cm->msg_id);
      struct mg_coap_option *opt = cm->options;
      struct mg_str format;
      memset(&format, 0, sizeof(format));
      while (opt) {
        printf("\t%i: %.*s\n", opt->number, opt->value.len, opt->value.p);
        switch (opt->number) {
          case 12: {
            format = opt->value;
            break;
          }
        }
        opt = opt->next;
      }
      if (format.len==1 && format.p[0]=='\x3c' && cm->payload.len) {
        CborParser parser;
        CborValue value;
        cbor_parser_init(cm->payload.p, cm->payload.len, 0, &parser, &value);
        CborValue elem;
        cbor_value_enter_container(&value, &elem);
        uint64_t msg_type;
        cbor_value_get_uint64(&elem, &msg_type);
        printf("EDHOC MSG_TYPE: %i\n", msg_type);
        switch (msg_type) {
          case 1: {
            struct mg_coap_message cr;

            memset(&cr, 0, sizeof(cr));
            cr.msg_id = cm->msg_id;
            cr.msg_type = MG_COAP_MSG_ACK;
            cr.code_class = 2;
            cr.code_detail = 05;
            mg_coap_add_option(&cr, 12, "\x3c", 1); // application/edhoc not yet registered, fallback to application/cbor

            size_t message2_len = edhoc_handler_message_1(&edhoc_ctx, cm->payload.p, cm->payload.len, message2_buf, 512);
            cr.payload = (struct mg_str){message2_buf, message2_len};
            res = mg_coap_send_message(nc, &cr);
            break;
          }
          case 3: {
            edhoc_handler_message_3(&edhoc_ctx, cm->payload.p, cm->payload.len);
          }
          default: {
            res = mg_coap_send_ack(nc, cm->msg_id);
          }
        }
      }
      else {
        break;
        res = mg_coap_send_ack(nc, cm->msg_id);
      }
      if (res == 0) {
        printf("Successfully sent ACK for message with msg_id = %d\n",
               cm->msg_id);
      } else {
        printf("Error: %d\n", res);
      }
      break;
    }
    case MG_EV_COAP_NOC:
    case MG_EV_COAP_ACK:
    case MG_EV_COAP_RST: {
      struct mg_coap_message *cm = (struct mg_coap_message *) p;
      printf("ACK/RST/NOC with msg_id = %d received\n", cm->msg_id);
      break;
    }
  }
}

int main(void) {
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
  edhoc_ctx.message1.buf = malloc(512);
  edhoc_ctx.message2.buf = malloc(512);
  edhoc_ctx.message3.buf = malloc(512);
  edhoc_ctx.shared_secret.buf = malloc(32);
  edhoc_ctx.shared_secret.len = 32;

  atcab_get_pubkey(1, id_u);
  printf("U public ID: {X:");
  for (int i = 0; i < 32; i++)
    printf("%02x", id_u[i]);
  printf(", Y:");
  for (int i = 0; i < 32; i++)
    printf("%02x", id_u[32 + i]);
  printf("}\n");
  memcpy(edhoc_ctx.pub_key, id_u, sizeof(id_u));

  struct mg_mgr mgr;
  struct mg_connection *nc;

  signal(SIGTERM, signal_handler);
  signal(SIGINT, signal_handler);

  mg_mgr_init(&mgr, 0);

  nc = mg_bind(&mgr, s_default_address, coap_handler);
  if (nc == NULL) {
    printf("Unable to start listener at %s\n", s_default_address);
    return -1;
  }

  printf("Listening for CoAP messages at %s\n", s_default_address);

  mg_set_protocol_coap(nc);

  while (!s_sig_received) {
    mg_mgr_poll(&mgr, 1000000);
  }

  printf("Exiting on signal %d\n", s_sig_received);

  mg_mgr_free(&mgr);
  return 0;

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