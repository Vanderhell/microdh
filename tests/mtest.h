#ifndef MTEST_H
#define MTEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int mtest_failures = 0;
static int mtest_checks = 0;
static int mtest_cases = 0;

static void mtest_print_hex(const void *buf, size_t len) {
    const unsigned char *p;
    size_t i;

    if (buf == NULL && len == 0) {
        return;
    }
    p = (const unsigned char *)buf;
    for (i = 0; i < len; ++i) {
        fprintf(stderr, "%02x", p[i]);
    }
}

static void mtest_begin_case(const char *name) {
    ++mtest_cases;
    fprintf(stdout, "[case %d] %s\n", mtest_cases, name);
}

static void mtest_record_failure(const char *expr,
                                 const char *file,
                                 int line) {
    ++mtest_failures;
    fprintf(stderr, "ASSERT FAILED: %s (%s:%d)\n", expr, file, line);
}

static void mtest_assert_int_eq_impl(int actual,
                                    int expected,
                                    const char *actual_expr,
                                    const char *expected_expr,
                                    const char *file,
                                    int line) {
    ++mtest_checks;
    if (actual != expected) {
        ++mtest_failures;
        fprintf(stderr,
                "ASSERT FAILED: %s == %s (actual=%d expected=%d) (%s:%d)\n",
                actual_expr,
                expected_expr,
                actual,
                expected,
                file,
                line);
    }
}

static void mtest_assert_mem_eq_impl(const void *actual,
                                     const void *expected,
                                     size_t len,
                                     const char *actual_expr,
                                     const char *expected_expr,
                                     const char *file,
                                     int line) {
    ++mtest_checks;
    if ((actual == NULL || expected == NULL) && len != 0) {
        ++mtest_failures;
        fprintf(stderr,
                "ASSERT FAILED: %s == %s (null pointer) (%s:%d)\n",
                actual_expr,
                expected_expr,
                file,
                line);
        return;
    }
    if (memcmp(actual, expected, len) != 0) {
        ++mtest_failures;
        fprintf(stderr, "ASSERT FAILED: %s == %s (%s:%d)\n", actual_expr,
                expected_expr, file, line);
        fprintf(stderr, "  actual:   ");
        mtest_print_hex(actual, len);
        fprintf(stderr, "\n  expected: ");
        mtest_print_hex(expected, len);
        fprintf(stderr, "\n");
    }
}

#define MTEST_ASSERT(expr)                                                      \
    do {                                                                        \
        ++mtest_checks;                                                         \
        if (!(expr)) {                                                          \
            mtest_record_failure(#expr, __FILE__, __LINE__);                   \
        }                                                                       \
    } while (0)

#define MTEST_ASSERT_EQ_INT(actual, expected)                                   \
    do {                                                                        \
        int mtest_actual__ = (int)(actual);                                     \
        int mtest_expected__ = (int)(expected);                                 \
        mtest_assert_int_eq_impl(mtest_actual__, mtest_expected__,             \
                                 #actual, #expected, __FILE__, __LINE__);      \
    } while (0)

#define MTEST_ASSERT_MEMEQ(actual, expected, len)                               \
    do {                                                                        \
        const void *mtest_actual_ptr__ = (const void *)(actual);                \
        const void *mtest_expected_ptr__ = (const void *)(expected);            \
        size_t mtest_len__ = (size_t)(len);                                     \
        mtest_assert_mem_eq_impl(mtest_actual_ptr__, mtest_expected_ptr__,      \
                                 mtest_len__, #actual, #expected, __FILE__,    \
                                 __LINE__);                                     \
    } while (0)

#define MTEST_RUN(fn)                                                           \
    do {                                                                        \
        mtest_begin_case(#fn);                                                  \
        fn();                                                                   \
    } while (0)

static int mtest_finish(void) {
    if (mtest_failures != 0) {
        fprintf(stderr, "%d of %d checks failed across %d cases\n",
                mtest_failures, mtest_checks, mtest_cases);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "All %d checks passed across %d cases\n",
            mtest_checks, mtest_cases);
    return EXIT_SUCCESS;
}

#endif
