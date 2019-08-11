#ifndef OSCORE_OSCORE_H
#define OSCORE_OSCORE_H

typedef struct info_t {
    const uint8_t *id;
    const size_t id_size;
    const uint8_t *id_context;
    const size_t id_ctx_size;
    const int alg_aead;
    const char *tstr;
    const uint32_t L;
} info_t;

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
    uint32_t sequence_number;
} oscore_s_ctx_t;

/**
 * Recipient OSCORE context. Contains information about the remote node.
 */
typedef struct oscore_r_ctx_t {
    const uint8_t *id;
    const size_t id_size;
    uint8_t *key;
    const size_t key_size;
    //TODO: add replay_window
} oscore_r_ctx_t;

/**
 * Derives OSCORE context keys & common IV. The Master Secret & Salt need to be given, as well as information about
 * the AEAD algorithm, key sizes, IDs etc.
 *
 * @param c_ctx Common OSCORE context
 * @param s_ctx Sender OSCORE context
 * @param r_ctx Recipient OSCORE context
 */
void derive_context(oscore_c_ctx_t *c_ctx, oscore_s_ctx_t *s_ctx, oscore_r_ctx_t *r_ctx);

void encode_info(const info_t *info, uint8_t *buffer, size_t buf_size, size_t *out_size);

void HKDF(const uint8_t *secret, size_t secret_size, const uint8_t *salt, size_t salt_size, const uint8_t *info,
          size_t info_size, uint8_t *buffer, size_t buf_size);

#endif //OSCORE_OSCORE_H
