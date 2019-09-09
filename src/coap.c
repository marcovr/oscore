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

void dump_coap(const uint8_t *data, size_t data_size) {
    coap_packet_t pdu;
    coap_parse(&pdu, data, data_size);
    coap_dumpPacket(&pdu);
}
