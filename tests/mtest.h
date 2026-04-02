#ifndef MTEST_H
#define MTEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void mtest_print_hex(const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t i;

    for (i = 0; i < len; ++i) {
        fprintf(stderr, "%02x", p[i]);
    }
}

static int mtest_failures = 0;
static int mtest_checks = 0;

#define MTEST_ASSERT(expr)                                                      \
    do {                                                                        \
        ++mtest_checks;                                                         \
        if (!(expr)) {                                                          \
            ++mtest_failures;                                                   \
            fprintf(stderr, "ASSERT FAILED: %s (%s:%d)\n", #expr, __FILE__,     \
                    __LINE__);                                                  \
        }                                                                       \
    } while (0)

#define MTEST_ASSERT_EQ_INT(actual, expected)                                   \
    do {                                                                        \
        int mtest_actual__ = (int)(actual);                                     \
        int mtest_expected__ = (int)(expected);                                 \
        ++mtest_checks;                                                         \
        if (mtest_actual__ != mtest_expected__) {                               \
            ++mtest_failures;                                                   \
            fprintf(stderr,                                                     \
                    "ASSERT FAILED: %s == %s (actual=%d expected=%d) "          \
                    "(%s:%d)\n",                                                \
                    #actual, #expected, mtest_actual__, mtest_expected__,       \
                    __FILE__, __LINE__);                                        \
        }                                                                       \
    } while (0)

#define MTEST_ASSERT_MEMEQ(actual, expected, len)                               \
    do {                                                                        \
        ++mtest_checks;                                                         \
        if (memcmp((actual), (expected), (len)) != 0) {                         \
            ++mtest_failures;                                                   \
            fprintf(stderr, "ASSERT FAILED: %s == %s (%s:%d)\n", #actual,       \
                    #expected, __FILE__, __LINE__);                             \
            fprintf(stderr, "  actual:   ");                                    \
            mtest_print_hex((actual), (len));                                   \
            fprintf(stderr, "\n  expected: ");                                  \
            mtest_print_hex((expected), (len));                                 \
            fprintf(stderr, "\n");                                              \
        }                                                                       \
    } while (0)

#define MTEST_RUN(fn)                                                           \
    do {                                                                        \
        fprintf(stdout, "[test] %s\n", #fn);                                    \
        fn();                                                                   \
    } while (0)

static int mtest_finish(void) {
    if (mtest_failures != 0) {
        fprintf(stderr, "%d of %d checks failed\n", mtest_failures,
                mtest_checks);
        return EXIT_FAILURE;
    }
    fprintf(stdout, "All %d checks passed\n", mtest_checks);
    return EXIT_SUCCESS;
}

#endif
