#include <stddef.h>
#include <stdio.h>
#include "utils.h"
#include "coap.h"

const option_desc_t coap_option_descs[] = {
    {1, "If-Match"},
    {3, "Uri-Host"},
    {4, "ETag"},
    {5, "If-None-Match"},
    {6, "Observe"},
    {7, "Uri-Port"},
    {8, "Location-Path"},
    {9, "OSCORE"},
    {11, "Uri-Path"},
    {12, "Content-Format"},
    {14, "Max-Age"},
    {15, "Uri-Query"},
    {17, "Accept"},
    {20, "Location-Query"},
    {23, "Block2"},
    {27, "Block1"},
    {28, "Size2"},
    {35, "Proxy-Uri"},
    {39, "Proxy-Scheme"},
    {60, "Size1"},
    {258, "No-Response"},
    {0, "UNKNOWN"}
};

const char *coap_method_code_desc[] = {"UNKNOWN", "GET", "POST", "PUT", "DELETE", "FETCH", "PATCH", "iPATCH"};

const char *coap_code_description(uint8_t code) {
    if (code < 8) {
        return coap_method_code_desc[code];
    }
    if (code < 32) {
        return coap_method_code_desc[0];
    }
    const char *desc = coap_response_phrase(code);
    return desc == NULL ? coap_method_code_desc[0] : desc;
}

const char *coap_option_description(unsigned char code) {
    int i = 0;
    for (; coap_option_descs[i].code; i++) {
        if (coap_option_descs[i].code == code) {
            break;
        }
    }
    return coap_option_descs[i].description;
}

void coap_print_pdu(coap_pdu_t *pdu) {
    printf("CoAP: %s\n", coap_code_description(pdu->code));

    coap_opt_iterator_t opt_iter;
    coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);

    coap_opt_t *option = NULL;
    while ((option = coap_option_next(&opt_iter))) {
        uint16_t length = coap_opt_length(option);
        printf("> %s[%d]: ", coap_option_description(opt_iter.type), length);
        print_diag(coap_opt_value(option), length);
    }

    size_t len;
    uint8_t *data;
    coap_get_data(pdu, &len, &data);
    if (len) {
        printf("> Data[%zu]: ", len);
        print_diag(data, len);
    }
}

bool coap_parse_bytes(const uint8_t *data, size_t data_size, coap_pdu_t **pdu) {
    *pdu = coap_pdu_init(0, 0, 0, COAP_DEFAULT_MTU);
    return coap_pdu_parse(COAP_PROTO_UDP, data, data_size, *pdu);
}

void dump_coap(const uint8_t *data, size_t data_size) {
    coap_pdu_t *pdu = NULL;
    coap_parse_bytes(data, data_size, &pdu);

    coap_print_pdu(pdu);
    //coap_set_log_level(LOG_DEBUG);
    //coap_show_pdu(LOG_DEBUG, pdu);

    coap_delete_pdu(pdu);
}

void coap_pdu_to_bytes(const coap_pdu_t *pdu, uint8_t **buffer, size_t *length) {
    *buffer = pdu->token - pdu->hdr_size;
    *length = pdu->used_size + pdu->hdr_size;
}
