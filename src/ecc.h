#ifndef OSCORE_ECC_H_
#define OSCORE_ECC_H_

#ifdef USE_WOLFSSL
    #include <wolfssl/options.h>    
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/ecc.h>
#else
    #define SHA256_DIGEST_SIZE 32
#endif
#ifndef WC_ECCKEY_TYPE_DEFINED
    struct ecc_key {
    #ifdef USE_CRYPTOAUTH
        unsigned char pubkey_raw[64];
        int slot; /* Key Slot Number (-1 unknown) */
    #endif
    };
    typedef struct ecc_key ecc_key;
    #define WC_ECCKEY_TYPE_DEFINED
#endif

#endif