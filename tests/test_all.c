#include "mdh.h"
#include "mtest.h"

#include <string.h>

typedef struct {
    uint8_t seed;
    uint8_t step;
} rng_stream_t;

typedef struct {
    uint8_t fill;
} rng_fail_after_partial_t;

typedef struct {
    uint32_t state;
} fuzz_state_t;

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

static int hex_to_bytes(uint8_t *out, size_t out_len, const char *hex) {
    size_t i;
    size_t hex_len;

    if (out == NULL || hex == NULL) {
        return 0;
    }

    hex_len = strlen(hex);
    if (hex_len != out_len * 2U) {
        return 0;
    }

    for (i = 0; i < out_len; ++i) {
        int hi = hex_nibble((unsigned char)hex[i * 2U]);
        int lo = hex_nibble((unsigned char)hex[i * 2U + 1U]);

        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }

    return 1;
}

static int bytes_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    return memcmp(a, b, len) == 0;
}

static int is_all_zero(const uint8_t *buf, size_t len) {
    size_t i;
    uint8_t acc = 0;

    for (i = 0; i < len; ++i) {
        acc |= buf[i];
    }

    return acc == 0;
}

static mdh_err_t rng_stream(void *user, uint8_t *buffer, size_t length) {
    rng_stream_t *state = (rng_stream_t *)user;
    size_t i;

    if (state == NULL) {
        return MDH_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < length; ++i) {
        buffer[i] = (uint8_t)(state->seed + (uint8_t)(i * state->step));
    }

    state->seed = (uint8_t)(state->seed + 0x31U);
    return MDH_OK;
}

static mdh_err_t rng_stream_alt(void *user, uint8_t *buffer, size_t length) {
    rng_stream_t *state = (rng_stream_t *)user;
    size_t i;

    if (state == NULL) {
        return MDH_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < length; ++i) {
        buffer[i] = (uint8_t)(state->seed ^ (uint8_t)(0xA5U + i * state->step));
    }

    state->seed = (uint8_t)(state->seed + 0x19U);
    return MDH_OK;
}

static mdh_err_t rng_fail_before_write(void *user, uint8_t *buffer, size_t length) {
    (void)user;
    memset(buffer, 0xA5, length);
    return MDH_ERR_RNG;
}

// cppcheck-suppress constParameterCallback
// cppcheck-suppress constParameterCallback
static mdh_err_t rng_fail_after_partial(void *user, uint8_t *buffer, size_t length) {
    const rng_fail_after_partial_t *state = (const rng_fail_after_partial_t *)user;
    size_t i;
    size_t half = length / 2U;

    if (state == NULL) {
        return MDH_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < half; ++i) {
        buffer[i] = (uint8_t)(state->fill + (uint8_t)(i * 3U));
    }
    for (i = half; i < length; ++i) {
        buffer[i] = 0xCC;
    }

    return MDH_ERR_RNG;
}

static mdh_err_t rng_all_zero(void *user, uint8_t *buffer, size_t length) {
    (void)user;
    memset(buffer, 0, length);
    return MDH_OK;
}

static void expect_x25519_hex(const char *scalar_hex,
                              const char *u_hex,
                              const char *expected_hex) {
    uint8_t scalar[32];
    uint8_t u[32];
    uint8_t out[32];
    uint8_t expected[32];

    MTEST_ASSERT(hex_to_bytes(scalar, sizeof(scalar), scalar_hex));
    MTEST_ASSERT(hex_to_bytes(u, sizeof(u), u_hex));
    MTEST_ASSERT(hex_to_bytes(expected, sizeof(expected), expected_hex));
    memset(out, 0xAA, sizeof(out));
    MTEST_ASSERT_EQ_INT(mdh_x25519(out, scalar, u), MDH_OK);
    MTEST_ASSERT_MEMEQ(out, expected, sizeof(out));
}

static void test_01_hex_parser(void) {
    uint8_t out[4];

    MTEST_ASSERT(hex_to_bytes(out, sizeof(out), "00112233"));
    MTEST_ASSERT(!hex_to_bytes(out, sizeof(out), "0011223"));
    MTEST_ASSERT(!hex_to_bytes(out, sizeof(out), "0011223344"));
    MTEST_ASSERT(!hex_to_bytes(out, sizeof(out), "0011223g"));
    MTEST_ASSERT(!hex_to_bytes(out, sizeof(out), "0011223A"));
}

static void test_02_rfc_5_2_vectors(void) {
    expect_x25519_hex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    expect_x25519_hex(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
}

static void test_03_rfc_6_1_vectors(void) {
    static const uint8_t alice_scalar[32] = {
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    };
    static const uint8_t bob_scalar[32] = {
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
    };
    static const uint8_t alice_pub_expected[32] = {
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
        0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
        0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
        0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
    };
    static const uint8_t bob_pub_expected[32] = {
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
        0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
        0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
        0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
    };
    static const uint8_t shared_expected[32] = {
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
        0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
        0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
        0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
    };
    uint8_t alice_pub[32];
    uint8_t bob_pub[32];
    uint8_t shared_ab[32];
    uint8_t shared_ba[32];
    static const uint8_t basepoint[32] = { 9 };

    MTEST_ASSERT_EQ_INT(mdh_x25519(alice_pub, alice_scalar, basepoint), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(bob_pub, bob_scalar, basepoint), MDH_OK);
    MTEST_ASSERT_MEMEQ(alice_pub, alice_pub_expected, sizeof(alice_pub));
    MTEST_ASSERT_MEMEQ(bob_pub, bob_pub_expected, sizeof(bob_pub));

    MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(shared_ab, alice_scalar, bob_pub), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(shared_ba, bob_scalar, alice_pub), MDH_OK);
    MTEST_ASSERT_MEMEQ(shared_ab, shared_expected, sizeof(shared_ab));
    MTEST_ASSERT_MEMEQ(shared_ba, shared_expected, sizeof(shared_ba));
    MTEST_ASSERT_MEMEQ(shared_ab, shared_ba, sizeof(shared_ab));
}

static void test_04_rfc_iteration_vectors(void) {
    uint8_t k[32];
    uint8_t u[32];
    uint8_t next[32];
    static const uint8_t basepoint[32] = { 9 };
    static const uint8_t one_iter_expected[32] = {
        0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc,
        0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
        0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78,
        0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79
    };
    static const uint8_t thousand_iter_expected[32] = {
        0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
        0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
        0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
        0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51
    };
    size_t i;

    memset(k, 0, sizeof(k));
    k[0] = 9;
    memcpy(u, basepoint, sizeof(u));

    MTEST_ASSERT_EQ_INT(mdh_x25519(next, k, u), MDH_OK);
    MTEST_ASSERT_MEMEQ(next, one_iter_expected, sizeof(next));

    memcpy(k, basepoint, sizeof(k));
    memcpy(u, basepoint, sizeof(u));
    for (i = 0; i < 1000U; ++i) {
        MTEST_ASSERT_EQ_INT(mdh_x25519(next, k, u), MDH_OK);
        memcpy(u, k, sizeof(u));
        memcpy(k, next, sizeof(k));
    }
    MTEST_ASSERT_MEMEQ(k, thousand_iter_expected, sizeof(k));
}

static void test_05_high_bit_and_noncanonical_inputs(void) {
    uint8_t scalar[32];
    uint8_t basepoint[32] = { 9 };
    uint8_t high_bit_variant[32];
    uint8_t zero_u[32] = { 0 };
    uint8_t one_u[32] = { 1 };
    uint8_t p_minus_one[32];
    uint8_t p_value[32];
    uint8_t p_plus_one[32];
    uint8_t out_a[32];
    uint8_t out_b[32];
    uint8_t out_zero[32];
    uint8_t out_one[32];

    MTEST_ASSERT(hex_to_bytes(scalar, sizeof(scalar),
                              "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"));
    memcpy(high_bit_variant, basepoint, sizeof(high_bit_variant));
    high_bit_variant[31] |= 0x80U;
    MTEST_ASSERT_EQ_INT(mdh_x25519(out_a, scalar, basepoint), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(out_b, scalar, high_bit_variant), MDH_OK);
    MTEST_ASSERT_MEMEQ(out_a, out_b, sizeof(out_a));

    memset(p_minus_one, 0xff, sizeof(p_minus_one));
    p_minus_one[31] = 0x7f;
    p_minus_one[0] = 0xec;
    memset(p_value, 0xff, sizeof(p_value));
    p_value[31] = 0x7f;
    p_value[0] = 0xed;
    memset(p_plus_one, 0xff, sizeof(p_plus_one));
    p_plus_one[31] = 0x7f;
    p_plus_one[0] = 0xee;

    MTEST_ASSERT_EQ_INT(mdh_x25519(out_a, scalar, p_minus_one), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(out_zero, scalar, zero_u), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(out_b, scalar, p_value), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(out_one, scalar, one_u), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(high_bit_variant, scalar, p_plus_one), MDH_OK);
    MTEST_ASSERT_MEMEQ(out_b, out_zero, sizeof(out_b));
    MTEST_ASSERT_MEMEQ(high_bit_variant, out_one, sizeof(high_bit_variant));
}

static void test_06_scalar_edge_inputs(void) {
    uint8_t zero_scalar[32] = { 0 };
    uint8_t one_scalar[32] = { 1 };
    uint8_t low_bits_scalar[32] = { 0 };
    uint8_t high_bits_scalar[32];
    uint8_t unclamped_scalar[32];
    uint8_t clamped_scalar[32];
    uint8_t u[32] = { 9 };
    uint8_t out_a[32];
    uint8_t out_b[32];

    memset(high_bits_scalar, 0xff, sizeof(high_bits_scalar));
    memset(unclamped_scalar, 0xaa, sizeof(unclamped_scalar));
    memcpy(clamped_scalar, unclamped_scalar, sizeof(clamped_scalar));
    clamped_scalar[0] &= 248U;
    clamped_scalar[31] &= 127U;
    clamped_scalar[31] |= 64U;

    MTEST_ASSERT_EQ_INT(mdh_x25519(out_a, zero_scalar, u), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(out_b, one_scalar, u), MDH_OK);
    MTEST_ASSERT_MEMEQ(out_a, out_b, sizeof(out_a));

    MTEST_ASSERT_EQ_INT(mdh_x25519(out_a, low_bits_scalar, u), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(out_b, high_bits_scalar, u), MDH_OK);

    MTEST_ASSERT_EQ_INT(mdh_x25519(out_a, unclamped_scalar, u), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(out_b, clamped_scalar, u), MDH_OK);
    MTEST_ASSERT_MEMEQ(out_a, out_b, sizeof(out_a));
}

static void test_07_public_key_and_checked_aliasing(void) {
    mdh_keypair_t kp;
    uint8_t shared[32];
    uint8_t alias_buf[32];
    uint8_t other_pub[32];
    uint8_t expected_shared[32];
    rng_stream_t rng = { 0x10U, 13U };

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, rng_stream, &rng), MDH_OK);
    memcpy(alias_buf, kp.privkey, sizeof(alias_buf));
    MTEST_ASSERT_EQ_INT(mdh_public_key(alias_buf, alias_buf), MDH_OK);

    MTEST_ASSERT_EQ_INT(mdh_public_key(other_pub, kp.privkey), MDH_OK);
    MTEST_ASSERT_MEMEQ(alias_buf, other_pub, sizeof(other_pub));

    memcpy(alias_buf, kp.pubkey, sizeof(alias_buf));
    MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(alias_buf, kp.privkey, kp.pubkey), MDH_OK);
    memcpy(expected_shared, alias_buf, sizeof(expected_shared));

    memcpy(shared, kp.pubkey, sizeof(shared));
    MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(shared, kp.privkey, shared), MDH_OK);
    MTEST_ASSERT_MEMEQ(shared, expected_shared, sizeof(shared));

    memcpy(shared, kp.pubkey, sizeof(shared));
    MTEST_ASSERT_EQ_INT(mdh_shared_secret(kp.privkey, kp.pubkey, shared), MDH_OK);
    MTEST_ASSERT_MEMEQ(shared, expected_shared, sizeof(shared));
}

static void test_08_aliasing_support(void) {
    uint8_t scalar[64];
    uint8_t u[64];
    uint8_t expected[32];
    uint8_t alias_out[32];
    uint8_t alias_expected[32];
    uint8_t shared_expected[32];
    uint8_t shared_alias[32];
    uint8_t basepoint[32] = { 9 };
    uint8_t overlap[64];
    uint8_t overlap_expected[32];
    uint8_t overlap_scalar[32];
    uint8_t overlap_u[32];
    size_t i;

    for (i = 0; i < sizeof(scalar); ++i) {
        scalar[i] = (uint8_t)(0x10U + i);
        u[i] = (uint8_t)(0x80U + i);
    }

    MTEST_ASSERT_EQ_INT(mdh_x25519(expected, scalar + 8, u + 16), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(alias_out, scalar + 8, u + 16), MDH_OK);
    MTEST_ASSERT_MEMEQ(alias_out, expected, sizeof(expected));

    memcpy(alias_out, scalar + 8, sizeof(alias_out));
    MTEST_ASSERT_EQ_INT(mdh_x25519(alias_expected, scalar + 8, basepoint), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(alias_out, alias_out, basepoint), MDH_OK);
    MTEST_ASSERT_MEMEQ(alias_out, alias_expected, sizeof(alias_expected));

    memcpy(alias_out, u + 16, sizeof(alias_out));
    MTEST_ASSERT_EQ_INT(mdh_x25519(alias_expected, scalar + 8, u + 16), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(alias_out, scalar + 8, alias_out), MDH_OK);
    MTEST_ASSERT_MEMEQ(alias_out, alias_expected, sizeof(alias_expected));

    memmove(overlap, scalar + 8U, 32U);
    memmove(overlap + 16U, u + 16U, 32U);
    memcpy(overlap_scalar, overlap, sizeof(overlap_scalar));
    memcpy(overlap_u, overlap + 16U, sizeof(overlap_u));
    MTEST_ASSERT_EQ_INT(mdh_x25519(overlap_expected, overlap_scalar, overlap_u), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_x25519(overlap + 8U, overlap, overlap + 16U), MDH_OK);
    MTEST_ASSERT_MEMEQ(overlap + 8U, overlap_expected, sizeof(overlap_expected));

    MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(shared_expected, scalar + 8, u + 16), MDH_OK);
    memcpy(shared_alias, u + 16, sizeof(shared_alias));
    MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(shared_alias, scalar + 8, shared_alias), MDH_OK);
    MTEST_ASSERT_MEMEQ(shared_alias, shared_expected, sizeof(shared_expected));
}

static void test_09_weak_peer_rejection(void) {
    static const uint8_t zero_pub[32] = { 0 };
    static const uint8_t one_pub[32] = { 1 };
    static const uint8_t weak_variants[][32] = {
        { 0x00 },
        { 0x01 },
        { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
          0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
          0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
          0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x80 }
    };
    mdh_keypair_t kp;
    uint8_t shared[32];
    rng_stream_t rng = { 0x10U, 13U };
    size_t i;

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, rng_stream, &rng), MDH_OK);
    memset(shared, 0xA5, sizeof(shared));
    MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(shared, kp.privkey, zero_pub), MDH_ERR_WEAK_PEER_KEY);
    MTEST_ASSERT(is_all_zero(shared, sizeof(shared)));
    memset(shared, 0xA5, sizeof(shared));
    MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(shared, kp.privkey, one_pub), MDH_ERR_WEAK_PEER_KEY);
    MTEST_ASSERT(is_all_zero(shared, sizeof(shared)));

    for (i = 0; i < sizeof(weak_variants) / sizeof(weak_variants[0]); ++i) {
        uint8_t peer[32];

        memcpy(peer, weak_variants[i], sizeof(peer));
        memset(shared, 0xA5, sizeof(shared));
        MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(shared, kp.privkey, peer), MDH_ERR_WEAK_PEER_KEY);
        MTEST_ASSERT(is_all_zero(shared, sizeof(shared)));
        peer[31] ^= 0x80U;
        memset(shared, 0xA5, sizeof(shared));
        MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(shared, kp.privkey, peer), MDH_ERR_WEAK_PEER_KEY);
        MTEST_ASSERT(is_all_zero(shared, sizeof(shared)));
    }
}

static void test_10_rng_and_keypair_failure_zeroization(void) {
    mdh_keypair_t kp;
    rng_stream_t rng_a = { 0x10U, 13U };
    rng_stream_t rng_b = { 0x80U, 7U };
    rng_fail_after_partial_t partial = { 0x44U };
    mdh_keypair_t snapshot;

    memset(&kp, 0x5A, sizeof(kp));
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, NULL, NULL), MDH_ERR_INVALID_ARGUMENT);
    MTEST_ASSERT(is_all_zero(kp.privkey, sizeof(kp.privkey)));
    MTEST_ASSERT(is_all_zero(kp.pubkey, sizeof(kp.pubkey)));

    memset(&kp, 0x5A, sizeof(kp));
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, rng_fail_before_write, NULL), MDH_ERR_RNG);
    MTEST_ASSERT(is_all_zero(kp.privkey, sizeof(kp.privkey)));
    MTEST_ASSERT(is_all_zero(kp.pubkey, sizeof(kp.pubkey)));

    memset(&kp, 0x5A, sizeof(kp));
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, rng_fail_after_partial, &partial), MDH_ERR_RNG);
    MTEST_ASSERT(is_all_zero(kp.privkey, sizeof(kp.privkey)));
    MTEST_ASSERT(is_all_zero(kp.pubkey, sizeof(kp.pubkey)));

    memset(&kp, 0x5A, sizeof(kp));
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, rng_all_zero, NULL), MDH_OK);
    memcpy(snapshot.privkey, kp.privkey, sizeof(snapshot.privkey));
    memcpy(snapshot.pubkey, kp.pubkey, sizeof(snapshot.pubkey));
    MTEST_ASSERT(!is_all_zero(snapshot.privkey, sizeof(snapshot.privkey)));
    MTEST_ASSERT(!is_all_zero(snapshot.pubkey, sizeof(snapshot.pubkey)));

    mdh_keypair_clear(&kp);
    MTEST_ASSERT(is_all_zero(kp.privkey, sizeof(kp.privkey)));
    MTEST_ASSERT(is_all_zero(kp.pubkey, sizeof(kp.pubkey)));

    memset(&kp, 0x5A, sizeof(kp));
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, rng_stream, &rng_a), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&snapshot, rng_stream_alt, &rng_b), MDH_OK);
    MTEST_ASSERT(!bytes_equal(kp.privkey, snapshot.privkey, sizeof(kp.privkey)));
    MTEST_ASSERT(!bytes_equal(kp.pubkey, snapshot.pubkey, sizeof(kp.pubkey)));
}

static void test_11_deterministic_rng_and_clears(void) {
    mdh_keypair_t a;
    mdh_keypair_t b;
    mdh_keypair_t c;
    rng_stream_t rng = { 0x10U, 13U };
    rng_stream_t rng_reset = { 0x10U, 13U };

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&a, rng_stream, &rng), MDH_OK);
    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&b, rng_stream, &rng), MDH_OK);
    MTEST_ASSERT(!bytes_equal(a.privkey, b.privkey, sizeof(a.privkey)));

    MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&c, rng_stream, &rng_reset), MDH_OK);
    MTEST_ASSERT_MEMEQ(a.privkey, c.privkey, sizeof(a.privkey));
    MTEST_ASSERT_MEMEQ(a.pubkey, c.pubkey, sizeof(a.pubkey));

    mdh_keypair_clear(&a);
    MTEST_ASSERT(is_all_zero(a.privkey, sizeof(a.privkey)));
    MTEST_ASSERT(is_all_zero(a.pubkey, sizeof(a.pubkey)));

    mdh_secret_clear(b.privkey);
    MTEST_ASSERT(is_all_zero(b.privkey, sizeof(b.privkey)));
    mdh_secure_clear(NULL, 0);
}

static void test_12_bounded_fuzz_smoke(void) {
    fuzz_state_t state = { 0x12345678U };
    uint8_t scalar[32];
    uint8_t peer[32];
    uint8_t out_a[32];
    uint8_t out_b[32];
    mdh_keypair_t kp;
    rng_stream_t rng;
    size_t i;

    for (i = 0; i < 256U; ++i) {
        size_t j;
        mdh_err_t expected_err;

        state.state = state.state * 1664525U + 1013904223U;
        for (j = 0; j < sizeof(scalar); ++j) {
            state.state = state.state * 1664525U + 1013904223U;
            scalar[j] = (uint8_t)(state.state >> 24);
        }
        for (j = 0; j < sizeof(peer); ++j) {
            state.state = state.state * 1664525U + 1013904223U;
            peer[j] = (uint8_t)(state.state >> 24);
        }

        MTEST_ASSERT_EQ_INT(mdh_x25519(out_a, scalar, peer), MDH_OK);
        MTEST_ASSERT_EQ_INT(mdh_x25519(out_b, scalar, peer), MDH_OK);
        MTEST_ASSERT_MEMEQ(out_a, out_b, sizeof(out_a));

        memset(out_b, 0xA5, sizeof(out_b));
        expected_err = is_all_zero(out_a, sizeof(out_a)) ? MDH_ERR_WEAK_PEER_KEY : MDH_OK;
        MTEST_ASSERT_EQ_INT(mdh_shared_secret_checked(out_b, scalar, peer), expected_err);
        if (expected_err == MDH_OK) {
            MTEST_ASSERT_MEMEQ(out_a, out_b, sizeof(out_a));
        } else {
            MTEST_ASSERT(is_all_zero(out_b, sizeof(out_b)));
        }

        rng.seed = (uint8_t)(state.state >> 24);
        rng.step = (uint8_t)(1U + ((state.state >> 16) & 0x0FU));
        MTEST_ASSERT_EQ_INT(mdh_generate_keypair(&kp, rng_stream, &rng), MDH_OK);
        MTEST_ASSERT(!is_all_zero(kp.privkey, sizeof(kp.privkey)));
        MTEST_ASSERT(!is_all_zero(kp.pubkey, sizeof(kp.pubkey)));
        mdh_keypair_clear(&kp);
    }
}

int main(void) {
    MTEST_RUN(test_01_hex_parser);
    MTEST_RUN(test_02_rfc_5_2_vectors);
    MTEST_RUN(test_03_rfc_6_1_vectors);
    MTEST_RUN(test_04_rfc_iteration_vectors);
    MTEST_RUN(test_05_high_bit_and_noncanonical_inputs);
    MTEST_RUN(test_06_scalar_edge_inputs);
    MTEST_RUN(test_07_public_key_and_checked_aliasing);
    MTEST_RUN(test_08_aliasing_support);
    MTEST_RUN(test_09_weak_peer_rejection);
    MTEST_RUN(test_10_rng_and_keypair_failure_zeroization);
    MTEST_RUN(test_11_deterministic_rng_and_clears);
    MTEST_RUN(test_12_bounded_fuzz_smoke);
    return mtest_finish();
}
