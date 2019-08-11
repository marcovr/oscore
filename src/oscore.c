/**
 * @file oscore.c
 * @author Marco vR
 *
 * OSCORE methods
 */

#include <tinycbor/cbor.h>
#include "oscore.h"
#include "utils.h"

#if defined(USE_CRYPTOAUTH)
    #include "cryptoauthlib.h"
    #include "basic/atca_basic_aes_gcm.h"
    #include "crypto/atca_crypto_sw.h"
#elif defined(USE_WOLFSSL)
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/sha256.h>
    #include <wolfssl/wolfcrypt/hmac.h>
#endif

// Derives OSCORE context keys & common IV.
void derive_context(oscore_c_ctx_t *c_ctx, oscore_s_ctx_t *s_ctx, oscore_r_ctx_t *r_ctx) {
    uint8_t info[20]; // TODO: determine useful size. Min 6 for CBOR + space for ints & bytes
    size_t info_size;

    // Information to derive sender key
    info_t info_S = {
            .id = s_ctx->id,
            .id_size = s_ctx->id_size,
            .id_context = c_ctx->id_context,
            .id_ctx_size = c_ctx->id_ctx_size,
            .alg_aead = c_ctx->alg_aead,
            .tstr = "Key",
            .L = s_ctx->key_size
    };
    encode_info(&info_S, info, sizeof(info), &info_size);
    HKDF(c_ctx->master_secret, c_ctx->secret_size, c_ctx->master_salt, c_ctx->salt_size, info, info_size, s_ctx->key,
         s_ctx->key_size);

    // Information to derive recipient key
    info_t info_R = {
            .id = r_ctx->id,
            .id_size = r_ctx->id_size,
            .id_context = c_ctx->id_context,
            .id_ctx_size = c_ctx->id_ctx_size,
            .alg_aead = c_ctx->alg_aead,
            .tstr = "Key",
            .L = r_ctx->key_size
    };
    encode_info(&info_R, info, sizeof(info), &info_size);
    HKDF(c_ctx->master_secret, c_ctx->secret_size, c_ctx->master_salt, c_ctx->salt_size, info, info_size, r_ctx->key,
         r_ctx->key_size);

    // Information to derive common IV
    info_t info_IV = {
            .id_context = c_ctx->id_context,
            .id_ctx_size = c_ctx->id_ctx_size,
            .alg_aead = c_ctx->alg_aead,
            .tstr = "IV",
            .L = c_ctx->common_iv_size
    };
    encode_info(&info_IV, info, sizeof(info), &info_size);
    HKDF(c_ctx->master_secret, c_ctx->secret_size, c_ctx->master_salt, c_ctx->salt_size, info, info_size,
            c_ctx->common_iv, c_ctx->common_iv_size);
}

// Encodes the given info structure as a CBOR array.
void encode_info(const info_t *info, uint8_t *buffer, size_t buf_size, size_t *out_size) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 5);

    cbor_encode_byte_string(&ary, info->id, info->id_size);
    if (info->id_context == NULL) {
        cbor_encode_null(&ary);
    } else {
        cbor_encode_byte_string(&ary, info->id_context, info->id_ctx_size);
    }
    cbor_encode_int(&ary, info->alg_aead);
    cbor_encode_text_stringz(&ary, info->tstr);
    cbor_encode_uint(&ary, info->L);

    cbor_encoder_close_container(&enc, &ary);
    *out_size = cbor_encoder_get_buffer_size(&enc, buffer);
}

// HMAC-based key derivation function.
void HKDF(const uint8_t *secret, size_t secret_size, const uint8_t *salt, size_t salt_size, const uint8_t *info,
          size_t info_size, uint8_t *buffer, size_t buf_size) {
#if defined(USE_CRYPTOAUTH)
    assert(0); // TODO: write cryptoauth equivalent
#elif defined(USE_WOLFSSL)
    assert(!wc_HKDF(SHA256, secret, secret_size, salt, salt_size, info, info_size, buffer, buf_size));
#endif
}
