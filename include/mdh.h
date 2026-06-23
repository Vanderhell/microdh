#ifndef MDH_H
#define MDH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MDH_VERSION_MAJOR 2
#define MDH_VERSION_MINOR 0
#define MDH_VERSION_PATCH 0
#define MDH_VERSION_STRING "2.0.0"

typedef enum {
    MDH_OK = 0,
    MDH_ERR_INVALID_ARGUMENT = -1,
    MDH_ERR_RNG = -2,
    MDH_ERR_WEAK_PEER_KEY = -3,
    MDH_ERR_INTERNAL = -4
} mdh_err_t;

#define MDH_ERR_INVALID_KEY MDH_ERR_INVALID_ARGUMENT
#define MDH_ERR_WEAK_KEY MDH_ERR_WEAK_PEER_KEY

typedef struct {
    // cppcheck-suppress unusedStructMember
    uint8_t privkey[32];
    // cppcheck-suppress unusedStructMember
    uint8_t pubkey[32];
} mdh_keypair_t;

typedef mdh_err_t (*mdh_rng_fn)(void *user, uint8_t *buffer, size_t length);

void mdh_secure_clear(void *ptr, size_t len);
void mdh_keypair_clear(mdh_keypair_t *keypair);
void mdh_secret_clear(uint8_t secret[32]);

/*
 * Generate an X25519 keypair using a caller-provided CSPRNG.
 * The RNG callback must write exactly 32 bytes when it succeeds.
 * Output is cleared on failure. Exact full-buffer aliasing is supported.
 */
mdh_err_t mdh_generate_keypair(mdh_keypair_t *keypair,
                               mdh_rng_fn rng,
                               void *rng_user);

/*
 * Raw RFC 7748 X25519 primitive.
 * Accepts any 32-byte scalar, clamps a local copy, masks the input u-coordinate
 * high bit, and writes the raw 32-byte X25519 result.
 * Exact full-buffer aliasing is supported because inputs are copied before use.
 */
mdh_err_t mdh_x25519(uint8_t out[32],
                     const uint8_t scalar[32],
                     const uint8_t u_coordinate[32]);

/*
 * Derive a public key from a private key using X25519 and the canonical base
 * point. Output is cleared on failure.
 */
mdh_err_t mdh_public_key(uint8_t out_public[32], const uint8_t private_key[32]);

/*
 * Checked shared-secret API.
 * Rejects an all-zero shared result after X25519 and clears the output on
 * failure.
 */
mdh_err_t mdh_shared_secret_checked(uint8_t out_secret[32],
                                    const uint8_t private_key[32],
                                    const uint8_t peer_public_key[32]);

/*
 * Compatibility wrapper that preserves the legacy name while using checked
 * shared-secret semantics.
 */
mdh_err_t mdh_shared_secret(const uint8_t private_key[32],
                            const uint8_t peer_public_key[32],
                            uint8_t out_secret[32]);

#ifdef MDH_TESTING
typedef enum {
    MDH_TEST_WIPE_SCALAR = 0,
    MDH_TEST_WIPE_X1,
    MDH_TEST_WIPE_A,
    MDH_TEST_WIPE_B,
    MDH_TEST_WIPE_C,
    MDH_TEST_WIPE_D,
    MDH_TEST_WIPE_E,
    MDH_TEST_WIPE_F,
    MDH_TEST_WIPE_SHARED_SECRET,
    MDH_TEST_WIPE_COUNT
} mdh_test_wipe_slot_t;

void mdh_test_reset_wipes(void);
int mdh_test_wipe_was_zeroed(mdh_test_wipe_slot_t slot, size_t expected_len);
size_t mdh_test_weak_peer_case_count(void);
const uint8_t *mdh_test_weak_peer_case(size_t index);
void mdh_test_gf_select(int64_t p[16], int64_t q[16], uint32_t bit);
#endif

#ifdef __cplusplus
}
#endif

#endif
