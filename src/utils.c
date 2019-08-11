#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void phex(uint8_t* ary, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", ary[i]);
    }
    printf("\n");
}

// print hex string as C array initializer
void parr(char* txt) {
    size_t len = strlen(txt);
    uint8_t *buf;
    hexstring_to_buffer(&buf, txt, len);
    len /= 2;

    printf("{");
    for (size_t i = 0; i < len; i++) {
        printf("0x%02x", buf[i]);
        printf(i == len -1 ? "}\n" : ", ");
    }
}

size_t buffer_to_hexstring(char **string, uint8_t *buffer, size_t buf_len) {
    size_t out_len = 2*buf_len + 1;
    char* block = malloc(out_len);
    char* p = block;

    for (size_t i = 0; i < buf_len; i++) {
        p += sprintf(p, "%02x", buffer[i]);
    }
    block[out_len-1] = 0;

    *string = block;
    return out_len;
}

size_t hexstring_to_buffer(uint8_t **buffer, char *string, size_t string_len) {
    size_t out_length = string_len / 2;
    uint8_t* block = malloc(out_length);

    for (size_t i = 0; i < out_length; i++) {
        char buf[3] = {string[2*i], string[2*i+1], 0};
        block[i] = (uint8_t) strtol(buf, 0, 16);
    }

    *buffer = block;
    return out_length;
}