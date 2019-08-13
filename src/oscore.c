/**
 * @file oscore.c
 * @author Marco vR
 *
 * OSCORE methods
 */

#include <netinet/in.h>
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

/** Array of supported AEAD algorithms.*/
const int32_t OSCORE_AEAD_algs[1] = {AES_CCM_16_64_128};
const size_t OSCORE_AEAD_algs_size = sizeof(OSCORE_AEAD_algs) / sizeof(int32_t);

// Derives OSCORE context keys & common IV.
void derive_context(oscore_c_ctx_t *c_ctx, oscore_s_ctx_t *s_ctx, oscore_r_ctx_t *r_ctx) {
    uint8_t info[20]; // TODO: determine useful size. Min 6 for CBOR + space for ints & bytes
    size_t info_size;

    // Information to derive sender key
    oscore_hkdf_info_t info_S = {
            .id = s_ctx->id,
            .id_size = s_ctx->id_size,
            .id_context = c_ctx->id_context,
            .id_ctx_size = c_ctx->id_ctx_size,
            .alg_aead = c_ctx->alg_aead,
            .type = "Key",
            .L = s_ctx->key_size
    };
    encode_info(&info_S, info, sizeof(info), &info_size);
    HKDF(c_ctx->master_secret, c_ctx->secret_size, c_ctx->master_salt, c_ctx->salt_size, info, info_size, s_ctx->key,
         s_ctx->key_size);

    // Information to derive recipient key
    oscore_hkdf_info_t info_R = {
            .id = r_ctx->id,
            .id_size = r_ctx->id_size,
            .id_context = c_ctx->id_context,
            .id_ctx_size = c_ctx->id_ctx_size,
            .alg_aead = c_ctx->alg_aead,
            .type = "Key",
            .L = r_ctx->key_size
    };
    encode_info(&info_R, info, sizeof(info), &info_size);
    HKDF(c_ctx->master_secret, c_ctx->secret_size, c_ctx->master_salt, c_ctx->salt_size, info, info_size, r_ctx->key,
         r_ctx->key_size);

    // Information to derive common IV
    oscore_hkdf_info_t info_IV = {
            .id_context = c_ctx->id_context,
            .id_ctx_size = c_ctx->id_ctx_size,
            .alg_aead = c_ctx->alg_aead,
            .type = "IV",
            .L = c_ctx->common_iv_size
    };
    encode_info(&info_IV, info, sizeof(info), &info_size);
    HKDF(c_ctx->master_secret, c_ctx->secret_size, c_ctx->master_salt, c_ctx->salt_size, info, info_size,
            c_ctx->common_iv, c_ctx->common_iv_size);
}

// Encodes the given info structure as a CBOR array.
void encode_info(const oscore_hkdf_info_t *info, uint8_t *buffer, size_t buf_size, size_t *out_size) {
    /*
     *    info = [
     *        id : bstr,
     *        id_context : bstr / nil,
     *        alg_aead : int / tstr,
     *        type : tstr,
     *        L : uint,
     *    ]
     */
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
    cbor_encode_text_stringz(&ary, info->type);
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

// Derives the AEAD nonce from the OSCORE context.
void derive_nonce(const oscore_c_ctx_t *c_ctx, const oscore_s_ctx_t *s_ctx, uint8_t *nonce) {
    size_t nonce_length = c_ctx->common_iv_size;
    uint8_t partial_iv[OSCORE_PIV_MAX_SIZE];
    size_t partial_iv_size;
    uint64_to_partial_iv(s_ctx->sequence_number, partial_iv, &partial_iv_size);

    /*
     *         <- nonce length minus 6 B -> <-- 5 bytes -->
     *    +---+-------------------+--------+---------+-----+
     *    | S |      padding      | ID_PIV | padding | PIV |
     *    +---+-------------------+--------+---------+-----+
     */
    memset(nonce, 0, nonce_length);
    nonce[0] = s_ctx->id_size;
    memcpy(nonce + nonce_length - partial_iv_size, &partial_iv, partial_iv_size);
    memcpy(nonce + nonce_length - 5 - s_ctx->id_size, s_ctx->id, s_ctx->id_size);

    // XOR with common IV
    for (size_t i = 0; i < nonce_length; ++i) {
        nonce[i] = nonce[i] ^ c_ctx->common_iv[i];
    }
}

void encode_aad_array(const oscore_ext_aad_t *ext_aad, uint8_t *buffer, size_t buf_size, size_t *out_size) {
    /*
     *    aad_array = [
     *        oscore_version : uint,
     *        algorithms : [ alg_aead : int / tstr ],
     *        request_kid : bstr,
     *        request_piv : bstr,
     *        options : bstr,
     *    ]
     */
    CborEncoder enc;
    cbor_encoder_init(&enc, buffer, buf_size, 0);

    CborEncoder ary;
    cbor_encoder_create_array(&enc, &ary, 5);

    uint32_t oscore_version = ext_aad->oscore_version != 0 ? ext_aad->oscore_version : OSCORE_VERSION;
    cbor_encode_uint(&ary, oscore_version);

    // Array of supported AEAD algorithms
    const int32_t *aead_algs = ext_aad->algorithms != NULL ? ext_aad->algorithms : OSCORE_AEAD_algs;
    size_t aead_algs_size = ext_aad->algorithms_size != 0 ? ext_aad->algorithms_size : OSCORE_AEAD_algs_size;
    CborEncoder alg;
    cbor_encoder_create_array(&ary, &alg, aead_algs_size);
    for (size_t i = 0; i < aead_algs_size; ++i) {
        cbor_encode_int(&alg, aead_algs[i]);
    }
    cbor_encoder_close_container(&ary, &alg);

    cbor_encode_byte_string(&ary, ext_aad->request_kid, ext_aad->request_kid_size);
    cbor_encode_byte_string(&ary, ext_aad->request_piv, ext_aad->request_piv_size);
    cbor_encode_byte_string(&ary, ext_aad->options, ext_aad->options_size);

    cbor_encoder_close_container(&enc, &ary);
    *out_size = cbor_encoder_get_buffer_size(&enc, buffer);
}

void generate_oscore_option(const uint8_t *piv, size_t piv_size, const uint8_t *kid, size_t kid_size,
        const uint8_t *kid_context, size_t kid_ctx_size, uint8_t *buffer, size_t buf_size, size_t *out_size) {
    assert(piv_size < 6);
    assert(kid_ctx_size < 256);
    if (piv != NULL || kid_context != NULL || kid != NULL) {
        buffer[0] = 0;
    } else {
        *out_size = 0;
        return;
    }

    /*
     *     0 1 2 3 4 5 6 7 <------------- n bytes -------------->
     *    +-+-+-+-+-+-+-+-+--------------------------------------
     *    |0 0 0|h|k|  n  |       Partial IV (if any) ...
     *    +-+-+-+-+-+-+-+-+--------------------------------------
     *
     *     <- 1 byte -> <----- s bytes ------>
     *    +------------+----------------------+------------------+
     *    | s (if any) | kid context (if any) | kid (if any) ... |
     *    +------------+----------------------+------------------+
     *
     */
    if (piv != NULL) {
        *out_size = 1 + piv_size;
        assert(buf_size >= *out_size);
        buffer[0] = piv_size;
        memcpy(buffer + 1, piv, piv_size);
    }
    if (kid_context != NULL) {
        *out_size += 1 + kid_ctx_size;
        assert(buf_size >= *out_size);
        buffer[0] |= 1u << 4u;
        buffer[piv_size + 1] = kid_ctx_size;
        memcpy(buffer + 2 + piv_size, kid_context, kid_ctx_size);
    }
    if (kid != NULL) {
        *out_size += kid_size;
        assert(buf_size >= *out_size);
        buffer[0] |= 1u << 3u;
        memcpy(buffer + 2 + piv_size + kid_ctx_size, kid, kid_size);
    }
}

void uint64_to_partial_iv(uint64_t source, uint8_t *piv, size_t *out_size) {
    size_t size = 0;
    int max_offset = 1u << OSCORE_PIV_MAX_SIZE;

    // PIV is required to be in Network Byte Order (Big Endian).
    // Since the source is most likely stored as Little Endian, memcpy would produce a wrong result.
    // Also, the partial IV can be up to (currently) 5 bytes long, thus htonl() doesn't work.
    for (uint64_t i = max_offset; i >= 8; i -= 8) {
        if (source >= (1ul << i)) {
            piv[size++] = source >> i;
        }
    }
    piv[size++] = source;
    *out_size = size;
}
