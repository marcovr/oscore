#ifndef OSCORE_COAP_H
#define OSCORE_COAP_H

#include <coap2/coap.h>
#include <stdbool.h>

typedef struct option_desc_t {
    const int16_t code;
    const char *description;
} option_desc_t;

const char *coap_code_description(uint8_t code);
const char *coap_option_description(unsigned char code);
void coap_print_pdu(coap_pdu_t *pdu);
bool coap_parse_bytes(const uint8_t *data, size_t data_size, coap_pdu_t **pdu);
void dump_coap(const uint8_t *data, size_t data_size);
void coap_pdu_to_bytes(const coap_pdu_t *pdu, uint8_t **buffer, size_t *length);

#endif //OSCORE_COAP_H
