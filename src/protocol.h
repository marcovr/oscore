#ifndef PROTOCOL_EDHOC_H
#define PROTOCOL_EDHOC_H

#include "types.h"

#define CONN_IDENTIFIER_SIZE 2

size_t initiate_edhoc(edhoc_u_session_state* ctx, uint8_t* out, size_t out_size);
size_t edhoc_handler_message_1(edhoc_v_session_state* ctx, const uint8_t* buffer_in, size_t in_size, uint8_t* out, size_t out_size);
size_t edhoc_handler_message_2(edhoc_u_session_state* ctx, const uint8_t* buffer_in, size_t in_size, uint8_t* out, size_t out_size);
void edhoc_handler_message_3(edhoc_v_session_state* ctx, const uint8_t* buffer_in, size_t in_size);

#endif //PROTOCOL_EDHOC_H