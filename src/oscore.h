#ifndef OSCORE_OSCORE_H
#define OSCORE_OSCORE_H

void derive_context(const uint8_t *secret, size_t secret_size, const uint8_t *salt, size_t salt_size, const uint8_t *id,
        size_t id_size);

void encode_info(const uint8_t *id, size_t id_size, const uint8_t *id_context, size_t id_ctx_size, int alg_aead,
                 const char *tstr, uint32_t L, uint8_t *buffer, size_t buf_size, size_t *out_size);

void HKDF(const uint8_t *secret, size_t secret_size, const uint8_t *salt, size_t salt_size, const uint8_t *info,
          size_t info_size, uint8_t *buffer, size_t buf_size);

#endif //OSCORE_OSCORE_H
