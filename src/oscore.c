#include <stdint-gcc.h>
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

void derive_context(const uint8_t *secret, size_t secret_size, const uint8_t *salt, size_t salt_size,
        const uint8_t *id, size_t id_size) {
    uint8_t RS_context[16];
    uint8_t common_IV[13];

    uint8_t info[20]; // TODO: determine useful size. Min 6 for CBOR + space for ints & bytes
    size_t out_size;
    int alg_aead = 10; // AES_CCM

    encode_info(id, id_size, NULL, 0, alg_aead, "Key", sizeof(RS_context), info, sizeof(info), &out_size);

    HKDF(secret, secret_size, salt, salt_size, info, out_size, RS_context, sizeof(RS_context));

    encode_info(NULL, 0, NULL, 0, alg_aead, "IV", sizeof(common_IV), info, sizeof(info), &out_size);

    HKDF(secret, secret_size, salt, salt_size, info, out_size, common_IV, sizeof(common_IV));
}

void encode_info(const uint8_t *id, size_t id_size, const uint8_t *id_context, size_t id_ctx_size, int alg_aead,
                 const char *tstr, uint32_t L, uint8_t *buffer, size_t buf_size, size_t *out_size) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 5);

    cbor_encode_byte_string(&ary, id, id_size);
    if (id_context == NULL) {
        cbor_encode_null(&ary);
    } else {
        cbor_encode_byte_string(&ary, id_context, id_ctx_size);
    }
    cbor_encode_int(&ary, alg_aead);
    cbor_encode_text_stringz(&ary, tstr);
    cbor_encode_uint(&ary, L);

    cbor_encoder_close_container(&enc, &ary);
    *out_size = cbor_encoder_get_buffer_size(&enc, buffer);
}

void HKDF(const uint8_t *secret, size_t secret_size, const uint8_t *salt, size_t salt_size, const uint8_t *info,
          size_t info_size, uint8_t *buffer, size_t buf_size) {
#if defined(USE_CRYPTOAUTH)
    assert(0); // TODO: write cryptoauth equivalent
#elif defined(USE_WOLFSSL)
    assert(!wc_HKDF(SHA256, secret, secret_size, salt, salt_size, info, info_size, buffer, buf_size));
#endif
}
