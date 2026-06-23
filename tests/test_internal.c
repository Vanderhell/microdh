#include "mdh.h"
#include "mtest.h"

#include <string.h>

static void test_01_gf_select_masks(void) {
    int64_t p0[16] = {
        1, -2, 3, -4, 5, -6, 7, -8,
        9, -10, 11, -12, 13, -14, 15, -16
    };
    int64_t q0[16] = {
        -101, 102, -103, 104, -105, 106, -107, 108,
        -109, 110, -111, 112, -113, 114, -115, 116
    };
    int64_t p[16];
    int64_t q[16];

    memcpy(p, p0, sizeof(p));
    memcpy(q, q0, sizeof(q));
    mdh_test_gf_select(p, q, 0U);
    MTEST_ASSERT_MEMEQ(p, p0, sizeof(p));
    MTEST_ASSERT_MEMEQ(q, q0, sizeof(q));

    memcpy(p, p0, sizeof(p));
    memcpy(q, q0, sizeof(q));
    mdh_test_gf_select(p, q, 1U);
    MTEST_ASSERT_MEMEQ(p, q0, sizeof(p));
    MTEST_ASSERT_MEMEQ(q, p0, sizeof(q));

    memcpy(p, p0, sizeof(p));
    memcpy(q, q0, sizeof(q));
    mdh_test_gf_select(p, q, 2U);
    MTEST_ASSERT_MEMEQ(p, p0, sizeof(p));
    MTEST_ASSERT_MEMEQ(q, q0, sizeof(q));

    memcpy(p, p0, sizeof(p));
    memcpy(q, q0, sizeof(q));
    mdh_test_gf_select(p, q, 3U);
    MTEST_ASSERT_MEMEQ(p, q0, sizeof(p));
    MTEST_ASSERT_MEMEQ(q, p0, sizeof(q));

    memcpy(p, p0, sizeof(p));
    memcpy(q, q0, sizeof(q));
    mdh_test_gf_select(p, q, 1U);
    mdh_test_gf_select(p, q, 1U);
    MTEST_ASSERT_MEMEQ(p, p0, sizeof(p));
    MTEST_ASSERT_MEMEQ(q, q0, sizeof(q));
}

static void test_02_weak_peer_table(void) {
    static const uint8_t zero_case[32] = { 0 };
    static const uint8_t one_case[32] = { 1 };
    size_t count = mdh_test_weak_peer_case_count();
    size_t i;
    size_t j;

    MTEST_ASSERT_EQ_INT((int)count, 12);
    for (i = 0; i < count; ++i) {
        const uint8_t *entry = mdh_test_weak_peer_case(i);

        MTEST_ASSERT(entry != NULL);
        for (j = i + 1; j < count; ++j) {
            const uint8_t *other = mdh_test_weak_peer_case(j);

            if (other == NULL) {
                MTEST_ASSERT(other != NULL);
            } else {
                MTEST_ASSERT(memcmp(entry, other, 32U) != 0);
            }
        }
    }
    MTEST_ASSERT_MEMEQ(mdh_test_weak_peer_case(0), zero_case, 32U);
    MTEST_ASSERT_MEMEQ(mdh_test_weak_peer_case(1), one_case, 32U);
}

static void test_03_wipe_instrumentation(void) {
    uint8_t scalar[32] = { 0 };
    uint8_t u[32] = { 9 };
    uint8_t out[32];

    scalar[0] = 0x77U;
    scalar[1] = 0x07U;
    scalar[2] = 0x6dU;
    scalar[3] = 0x0aU;
    scalar[4] = 0x73U;
    scalar[5] = 0x18U;
    scalar[6] = 0xa5U;
    scalar[7] = 0x7dU;

    mdh_test_reset_wipes();
    MTEST_ASSERT_EQ_INT(mdh_x25519(out, scalar, u), MDH_OK);
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_SCALAR, 32U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_X1, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_A, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_B, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_C, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_D, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_E, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_F, sizeof(int64_t) * 16U));
    MTEST_ASSERT(mdh_test_wipe_was_zeroed(MDH_TEST_WIPE_SHARED_SECRET, 32U));
}

int main(void) {
    MTEST_RUN(test_01_gf_select_masks);
    MTEST_RUN(test_02_weak_peer_table);
    MTEST_RUN(test_03_wipe_instrumentation);
    return mtest_finish();
}
