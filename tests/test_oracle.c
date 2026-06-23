#include "mdh.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(MDH_HAVE_OPENSSL) && MDH_HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>

typedef struct {
    uint32_t state;
} oracle_rng_t;

static uint32_t oracle_next(oracle_rng_t *rng) {
    rng->state = rng->state * 1664525U + 1013904223U;
    return rng->state;
}

static void oracle_fill(oracle_rng_t *rng, uint8_t *buf, size_t len) {
    size_t i;

    for (i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(oracle_next(rng) >> 24);
    }
}

static void print_hex_line(const char *label, const uint8_t *buf, size_t len) {
    size_t i;

    fprintf(stderr, "%s", label);
    for (i = 0; i < len; ++i) {
        fprintf(stderr, "%02x", buf[i]);
    }
    fprintf(stderr, "\n");
}

static void print_openssl_errors(void) {
    unsigned long err;

    while ((err = ERR_get_error()) != 0UL) {
        char message[256];

        ERR_error_string_n(err, message, sizeof(message));
        fprintf(stderr, "OpenSSL error: %s\n", message);
    }
}

static int oracle_x25519(uint8_t out[32],
                         const uint8_t scalar[32],
                         const uint8_t peer[32]) {
    uint8_t scalar_copy[32];
    uint8_t peer_copy[32];
    EVP_PKEY *priv = NULL;
    EVP_PKEY *pub = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t out_len = 32;
    int ok = 0;

    memcpy(scalar_copy, scalar, sizeof(scalar_copy));
    memcpy(peer_copy, peer, sizeof(peer_copy));

    scalar_copy[0] &= 248U;
    scalar_copy[31] &= 127U;
    scalar_copy[31] |= 64U;
    peer_copy[31] &= 0x7fU;

    priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, scalar_copy, 32);
    if (priv == NULL) {
        print_openssl_errors();
        goto done;
    }

    pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_copy, 32);
    if (pub == NULL) {
        print_openssl_errors();
        goto done;
    }

    ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (ctx == NULL) {
        print_openssl_errors();
        goto done;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        print_openssl_errors();
        goto done;
    }
    if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0) {
        print_openssl_errors();
        goto done;
    }
    if (EVP_PKEY_derive(ctx, out, &out_len) <= 0 || out_len != 32U) {
        print_openssl_errors();
        goto done;
    }

    ok = 1;

done:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(priv);
    return ok;
}

static int oracle_probe(void) {
    static const uint8_t probe_scalar[32] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    };
    static const uint8_t probe_peer[32] = { 9 };
    uint8_t out[32];

    return oracle_x25519(out, probe_scalar, probe_peer);
}

static int run_oracle_compare(void) {
    oracle_rng_t rng = { 0xC0FFEE01U };
    uint8_t scalar[32];
    uint8_t peer[32];
    uint8_t actual[32];
    uint8_t expected[32];
    size_t i;
    const size_t case_count = 10000U;

    for (i = 0; i < case_count; ++i) {
        uint32_t case_seed;

        case_seed = rng.state;
        oracle_fill(&rng, scalar, sizeof(scalar));
        oracle_fill(&rng, peer, sizeof(peer));

        if (i == 0U) {
            scalar[0] = 1U;
            peer[0] = 9U;
        } else if (i == 1U) {
            memset(scalar, 0xff, sizeof(scalar));
            memset(peer, 0xff, sizeof(peer));
        }

        if ((i & 3U) == 1U) {
            scalar[0] = 1U;
            peer[31] ^= 0x80U;
        } else if ((i & 3U) == 2U) {
            peer[0] = 0xed;
            peer[31] = 0x7f;
        } else if ((i & 3U) == 3U) {
            peer[0] = 0xee;
            peer[31] = 0x7f;
        }

        if (!oracle_x25519(expected, scalar, peer)) {
            fprintf(stderr,
                    "NOT VERIFIED: OpenSSL X25519 oracle became unusable at case %zu (seed=0x%08x)\n",
                    i,
                    (unsigned)case_seed);
            return 77;
        }

        if (mdh_x25519(actual, scalar, peer) != MDH_OK) {
            fprintf(stderr,
                    "microdh X25519 failed unexpectedly at case %zu (seed=0x%08x)\n",
                    i,
                    (unsigned)case_seed);
            return 1;
        }

        if (memcmp(actual, expected, sizeof(actual)) != 0) {
            fprintf(stderr,
                    "oracle mismatch at case %zu seed=0x%08x\n",
                    i,
                    (unsigned)case_seed);
            print_hex_line("scalar=", scalar, sizeof(scalar));
            print_hex_line("u=", peer, sizeof(peer));
            print_hex_line("expected=", expected, sizeof(expected));
            print_hex_line("actual=", actual, sizeof(actual));
            return 1;
        }
    }

    return 0;
}

int main(void) {
    if (!oracle_probe()) {
        fprintf(stderr, "NOT VERIFIED: OpenSSL X25519 oracle unavailable or unusable\n");
        return 77;
    }

    return run_oracle_compare();
}

#else

int main(void) {
    fprintf(stderr, "NOT VERIFIED: OpenSSL X25519 oracle unavailable\n");
    return 77;
}

#endif
