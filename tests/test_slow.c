#include "mdh.h"
#include "mtest.h"

#include <string.h>

static void test_01_one_million_iterations(void) {
    uint8_t k[32];
    uint8_t u[32];
    uint8_t next[32];
    static const uint8_t million_iter_expected[32] = {
        0x7c, 0x39, 0x11, 0xe0, 0xab, 0x25, 0x86, 0xfd,
        0x86, 0x44, 0x97, 0x29, 0x7e, 0x57, 0x5e, 0x6f,
        0x3b, 0xc6, 0x01, 0xc0, 0x88, 0x3c, 0x30, 0xdf,
        0x5f, 0x4d, 0xd2, 0xd2, 0x4f, 0x66, 0x54, 0x24
    };
    size_t i;

    memset(k, 0, sizeof(k));
    k[0] = 9;
    memset(u, 0, sizeof(u));
    u[0] = 9;

    for (i = 0; i < 1000000U; ++i) {
        uint8_t old_k[32];

        memcpy(old_k, k, sizeof(old_k));
        MTEST_ASSERT_EQ_INT(mdh_x25519(next, k, u), MDH_OK);
        memcpy(u, old_k, sizeof(u));
        memcpy(k, next, sizeof(k));
    }

    MTEST_ASSERT_MEMEQ(k, million_iter_expected, sizeof(k));
}

int main(void) {
    MTEST_RUN(test_01_one_million_iterations);
    return mtest_finish();
}
