#include "mdh.h"
#include "mtest.h"

#include <string.h>

static void hex_to_bytes(uint8_t out[32], const char *hex) {
    static const char digits[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < 32U; ++i) {
        const char *hi = strchr(digits, hex[i * 2]);
        const char *lo = strchr(digits, hex[i * 2 + 1]);
        out[i] = (uint8_t)(((unsigned)(hi - digits) << 4) | (unsigned)(lo - digits));
    }
}

static mdh_err_t deterministic_rng_a(uint8_t *buf, size_t len) {
    static uint8_t state = 0x10;
    size_t i;

    for (i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(state + (uint8_t)(i * 13U));
    }

    state = (uint8_t)(state + 0x31U);
    return MDH_OK;
}

static mdh_err_t deterministic_rng_b(uint8_t *buf, size_t len) {
    static uint8_t state = 0x80;
    size_t i;

    for (i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(state ^ (uint8_t)(0xA5U + i * 7U));
    }

    state = (uint8_t)(state + 0x19U);
    return MDH_OK;
}

static mdh_err_t failing_rng(uint8_t *buf, size_t len) {
    memset(buf, 0xA5, len);
    return MDH_ERR_RNG;
}

static int is_all_zero(const uint8_t *buf, size_t len) {
    size_t i;
    uint8_t acc = 0;

    for (i = 0; i < len; ++i) {
        acc |= buf[i];
    }

    return acc == 0;
}

static void test_01_rfc7748_vectors(void) {
    uint8_t alice_priv[32];
    uint8_t bob_priv[32];
    uint8_t alice_pub[32];
    uint8_t bob_pub[32];
    uint8_t expected_alice_pub[32];
    uint8_t expected_bob_pub[32];
    uint8_t expected_shared[32];
    uint8_t basepoint[32] = { 9 };
    uint8_t out[32];

    hex_to_bytes(alice_priv, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    hex_to_bytes(expected_alice_pub, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    hex_to_bytes(bob_priv, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    hex_to_bytes(expected_bob_pub, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    hex_to_bytes(expected_shared, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    MTEST_ASSERT_EQ_INT(mdh_shared_secret(alice_priv, basepoint, alice_pub), MDH_OK);
    MTEST_ASSERT_MEMEQ(alice_pub, expected_alice_pub, 32U);

    MTEST_ASSERT_EQ_INT(mdh_shared_secret(bob_priv, basepoint, bob_pub), MDH_OK);
    MTEST_ASSERT_MEMEQ(bob_pub, expected_bob_pub, 32U);

    MTEST_ASSERT_EQ_INT(mdh_shared_secret(alice_priv, bob_pub, out), MDH_OK);
    MTEST_ASSERT_MEMEQ(out, expected_shared, 32U);

    MTEST_ASSERT_EQ_INT(mdh_shared_secret(bob_priv, alice_pub, out), MDH_OK);
    MTEST_ASSERT_MEMEQ(out, expected_shared, 32U);
}

static void test_02_generate_keypair(void) {
    mdh_keypair_t a;
    mdh_keypair_t b;

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&a, deterministic_rng_a), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&b, deterministic_rng_b), MDH_OK);
    MTEST_ASSERT(memcmp(a.privkey, b.privkey, 32U) != 0);
    MTEST_ASSERT(memcmp(a.pubkey, b.pubkey, 32U) != 0);
    MTEST_ASSERT(!is_all_zero(a.pubkey, 32U));
    MTEST_ASSERT(!is_all_zero(b.pubkey, 32U));
}

static void test_03_shared_secret_symmetry(void) {
    mdh_keypair_t a;
    mdh_keypair_t b;
    uint8_t shared_ab[32];
    uint8_t shared_ba[32];

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&a, deterministic_rng_a), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&b, deterministic_rng_b), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_shared_secret(a.privkey, b.pubkey, shared_ab), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_shared_secret(b.privkey, a.pubkey, shared_ba), MDH_OK);
    MTEST_ASSERT_MEMEQ(shared_ab, shared_ba, 32U);
    MTEST_ASSERT(!is_all_zero(shared_ab, 32U));
}

static void test_04_weak_key(void) {
    mdh_keypair_t kp;
    uint8_t weak_remote[32] = { 1 };
    uint8_t shared[32];

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, deterministic_rng_a), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_shared_secret(kp.privkey, weak_remote, shared), MDH_ERR_WEAK_KEY);
}

static void test_05_zero_key(void) {
    mdh_keypair_t kp;
    uint8_t zero[32] = { 0 };
    uint8_t out[32];

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, deterministic_rng_b), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_shared_secret(zero, kp.pubkey, out), MDH_ERR_INVALID_KEY);
    MTEST_ASSERT_EQ_INT(mdh_shared_secret(kp.privkey, zero, out), MDH_ERR_INVALID_KEY);
}

static void test_06_clamp(void) {
    mdh_keypair_t kp;

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, deterministic_rng_a), MDH_OK);
    MTEST_ASSERT((kp.privkey[0] & 0x07U) == 0U);
    MTEST_ASSERT((kp.privkey[31] & 0x80U) == 0U);
    MTEST_ASSERT((kp.privkey[31] & 0x40U) == 0x40U);
}

static void test_07_rng_failure_propagation(void) {
    mdh_keypair_t kp;

    memset(&kp, 0x5A, sizeof(kp));
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, failing_rng), MDH_ERR_RNG);
    MTEST_ASSERT(is_all_zero(kp.privkey, 32U));
    MTEST_ASSERT(is_all_zero(kp.pubkey, 32U));
}

static void test_08_reject_small_subgroup_points(void) {
    mdh_keypair_t kp;
    uint8_t shared[32];
    static const uint8_t weak_remote_1[32] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t weak_remote_2[32] = {
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
        0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
        0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
        0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00
    };

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, deterministic_rng_a), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_shared_secret(kp.privkey, weak_remote_1, shared), MDH_ERR_WEAK_KEY);
    MTEST_ASSERT_EQ_INT(mdh_shared_secret(kp.privkey, weak_remote_2, shared), MDH_ERR_WEAK_KEY);
}

static void test_09_zeroization(void) {
    mdh_keypair_t a;
    mdh_keypair_t b;
    uint8_t shared[32];

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&a, deterministic_rng_a), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&b, deterministic_rng_b), MDH_OK);

    mdh_test_reset_wipes();
    MTEST_ASSERT_EQ_INT(mdh_shared_secret(a.privkey, b.pubkey, shared), MDH_OK);

    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_SCALAR, 32U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_X1, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_A, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_B, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_C, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_D, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_E, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_F, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_SHARED_SECRET, 32U));
    MTEST_ASSERT(!is_all_zero(shared, 32U));
}

int main(void) {
    MTEST_RUN(test_01_rfc7748_vectors);
    MTEST_RUN(test_02_generate_keypair);
    MTEST_RUN(test_03_shared_secret_symmetry);
    MTEST_RUN(test_04_weak_key);
    MTEST_RUN(test_05_zero_key);
    MTEST_RUN(test_06_clamp);
    MTEST_RUN(test_07_rng_failure_propagation);
    MTEST_RUN(test_08_reject_small_subgroup_points);
    MTEST_RUN(test_09_zeroization);
    return mtest_finish();
}
