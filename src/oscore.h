/**
 * @file oscore.h
 * @author Marco vR
 *
 * OSCORE method headers
 */

#ifndef OSCORE_OSCORE_H
#define OSCORE_OSCORE_H

/** See rfc8152 Table 10 for the definition.*/
#define AES_CCM_16_64_128 10
/** OSCORE version must be 1. See rfc8613#section-5.4 */
#define OSCORE_VERSION 1
/** Sender Sequence Number is used as PIV and has to be smaller than 2^40 (5 bytes). See rfc8613#section-7.2.1 */
#define OSCORE_PIV_MAX_SIZE 5u

/**
 * Information structure used for the HKDF to derive OSCORE context data.
 */
typedef struct oscore_hkdf_info_t {
    const uint8_t *id;
    const size_t id_size;
    const uint8_t *id_context;
    const size_t id_ctx_size;
    const int alg_aead;
    const char *type;
    const uint32_t L;
} oscore_hkdf_info_t;

/**
 * Common OSCORE context. Contains shared information.
 */
typedef struct oscore_c_ctx_t {
    const int alg_aead;
    const int alg_hkdf;
    const uint8_t *master_secret;
    const size_t secret_size;
    const uint8_t *master_salt;
    const size_t salt_size;
    const uint8_t *id_context;
    const size_t id_ctx_size;
    uint8_t *common_iv;
    const size_t common_iv_size;
} oscore_c_ctx_t;

/**
 * Sender OSCORE context. Contains information about the local node.
 */
typedef struct oscore_s_ctx_t {
    const uint8_t *id;
    const size_t id_size;
    uint8_t *key;
    const size_t key_size;
    uint64_t sequence_number;
} oscore_s_ctx_t;

/**
 * Recipient OSCORE context. Contains information about the remote node.
 */
typedef struct oscore_r_ctx_t {
    const uint8_t *id;
    const size_t id_size;
    uint8_t *key;
    const size_t key_size;
    void *replay_window; /**< Not correctly implemented yet*/
} oscore_r_ctx_t;

/**
 * Derives OSCORE context keys & common IV. The Master Secret & Salt need to be given, as well as information about
 * the AEAD algorithm, key sizes, IDs etc.
 *
 * @param[in,out] c_ctx Common OSCORE context
 * @param[in,out] s_ctx Sender OSCORE context
 * @param[in,out] r_ctx Recipient OSCORE context
 */
void derive_context(oscore_c_ctx_t *c_ctx, oscore_s_ctx_t *s_ctx, oscore_r_ctx_t *r_ctx);

/**
 * Encodes the given information structure as CBOR array so it can be fed into the HKDF.
 *
 * @param[in] info Information structure to encode
 * @param[out] buffer Output buffer where the encoded value is written to
 * @param[in] buf_size Buffer capacity
 * @param[out] out_size Written output size
 */
void encode_info(const oscore_hkdf_info_t *info, uint8_t *buffer, size_t buf_size, size_t *out_size);

/**
 * HMAC-based key derivation function. Derive key based on secret and optional salt and info.
 *
 * @param[in] secret
 * @param[in] secret_size
 * @param[in] salt
 * @param[in] salt_size
 * @param[in] info
 * @param[in] info_size
 * @param[out] buffer Output buffer where the key is written to.
 * @param[in] buf_size Buffer capacity. Output will be truncated to fit.
 */
void HKDF(const uint8_t *secret, size_t secret_size, const uint8_t *salt, size_t salt_size, const uint8_t *info,
          size_t info_size, uint8_t *buffer, size_t buf_size);

/**
 * Derives the AEAD nonce from the OSCORE context. Nonce length is equal to common IV length.
 *
 * @param[in] c_ctx Common OSCORE context
 * @param[in] s_ctx Sender OSCORE context
 * @param[out] nonce Output buffer, where nonce is written to
 */
void derive_nonce(const oscore_c_ctx_t *c_ctx, const oscore_s_ctx_t *s_ctx, uint8_t *nonce);

void encode_aad_array(const uint8_t *r_kid, size_t r_kid_size, const uint8_t *r_piv, size_t r_piv_size,
                      const uint8_t *options, size_t options_size, uint8_t *buffer, size_t buf_size, size_t *out_size);

void generate_oscore_option(const uint8_t *piv, size_t piv_size, const uint8_t *kid, size_t kid_size,
                            const uint8_t *kid_context, size_t kid_ctx_size, uint8_t *buffer, size_t buf_size,
                            size_t *out_size);

void uint64_to_partial_iv(uint64_t source, uint8_t *piv, size_t *out_size);

#endif //OSCORE_OSCORE_H
