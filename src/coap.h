#ifndef OSCORE_COAP_H
#define OSCORE_COAP_H

#include "microcoap.h"

typedef struct option_desc_t {
    const int16_t code;
    const char *description;
} option_desc_t;

void dump_coap(const uint8_t *data, size_t data_size);

#endif //OSCORE_COAP_H
