#include "mdh.h"

#include <stdint.h>
#include <string.h>

typedef int64_t gf[16];

static const gf MDH_121665 = { 0xdb41, 1 };

static void gf_0(gf out) {
    memset(out, 0, sizeof(gf));
}

static void gf_1(gf out) {
    gf_0(out);
    out[0] = 1;
}

static void gf_copy(gf out, const gf in) {
    memcpy(out, in, sizeof(gf));
}

static void gf_add(gf out, const gf a, const gf b) {
    int i;

    for (i = 0; i < 16; ++i) {
        out[i] = a[i] + b[i];
    }
}

static void gf_sub(gf out, const gf a, const gf b) {
    int i;

    for (i = 0; i < 16; ++i) {
        out[i] = a[i] - b[i];
    }
}

static void gf_carry(gf out) {
    int i;
    int64_t carry;

    for (i = 0; i < 16; ++i) {
        out[i] += (int64_t)1 << 16;
        carry = out[i] >> 16;
        if (i < 15) {
            out[i + 1] += carry - 1;
        } else {
            out[0] += (carry - 1) * 38;
        }
        out[i] -= carry << 16;
    }
}

static void gf_mul(gf out, const gf a, const gf b) {
    int i;
    int j;
    int64_t t[31] = { 0 };

    for (i = 0; i < 16; ++i) {
        for (j = 0; j < 16; ++j) {
            t[i + j] += a[i] * b[j];
        }
    }

    for (i = 0; i < 15; ++i) {
        t[i] += 38 * t[i + 16];
    }

    for (i = 0; i < 16; ++i) {
        out[i] = t[i];
    }

    gf_carry(out);
    gf_carry(out);
}

static void gf_sq(gf out, const gf in) {
    gf_mul(out, in, in);
}

static void gf_select(gf p, gf q, uint32_t bit) {
    int i;
    int64_t mask = ~(int64_t)(bit - 1U);

    for (i = 0; i < 16; ++i) {
        int64_t t = mask & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void gf_pack(uint8_t out[32], const gf in) {
    gf m;
    gf t;
    int i;
    int j;

    gf_copy(t, in);
    gf_carry(t);
    gf_carry(t);
    gf_carry(t);

    for (j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        m[14] &= 0xffff;
        gf_select(t, m, (uint32_t)(1 - ((m[15] >> 16) & 1)));
    }

    for (i = 0; i < 16; ++i) {
        out[2 * i] = (uint8_t)(t[i] & 0xff);
        out[2 * i + 1] = (uint8_t)((t[i] >> 8) & 0xff);
    }
}

static void gf_unpack(gf out, const uint8_t in[32]) {
    int i;

    for (i = 0; i < 16; ++i) {
        out[i] = in[2 * i] + ((int64_t)in[2 * i + 1] << 8);
    }
    out[15] &= 0x7fff;
}

static void gf_invert(gf out, const gf in) {
    gf c;
    int i;
    int a;

    gf_copy(c, in);
    for (a = 253; a >= 0; --a) {
        gf_sq(c, c);
        if (a != 2 && a != 4) {
            gf_mul(c, c, in);
        }
    }
    for (i = 0; i < 16; ++i) {
        out[i] = c[i];
    }
}

static void mdh_clamp_scalar(uint8_t scalar[32]) {
    scalar[0] &= 248U;
    scalar[31] &= 127U;
    scalar[31] |= 64U;
}

static int mdh_is_all_zero(const uint8_t *buf, size_t len) {
    uint8_t acc = 0;
    size_t i;

    for (i = 0; i < len; ++i) {
        acc |= buf[i];
    }

    return acc == 0;
}

static void mdh_x25519(uint8_t out[32],
                       const uint8_t scalar_in[32],
                       const uint8_t point[32]) {
    uint8_t scalar[32];
    gf x1;
    gf a;
    gf b;
    gf c;
    gf d;
    gf e;
    gf f;
    int i;

    memcpy(scalar, scalar_in, sizeof(scalar));
    mdh_clamp_scalar(scalar);
    gf_unpack(x1, point);

    gf_1(a);
    gf_0(b);
    gf_0(c);
    gf_1(d);
    gf_copy(b, x1);

    for (i = 254; i >= 0; --i) {
        uint32_t bit = (uint32_t)((scalar[i >> 3] >> (i & 7)) & 1U);

        gf_select(a, b, bit);
        gf_select(c, d, bit);

        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_add(c, b, d);
        gf_sub(b, b, d);
        gf_sq(d, e);
        gf_sq(f, a);
        gf_mul(a, c, a);
        gf_mul(c, b, e);
        gf_add(e, a, c);
        gf_sub(a, a, c);
        gf_sq(b, a);
        gf_sub(c, d, f);
        gf_mul(a, c, MDH_121665);
        gf_add(a, a, d);
        gf_mul(c, c, a);
        gf_mul(a, d, f);
        gf_mul(d, b, x1);
        gf_sq(b, e);

        gf_select(a, b, bit);
        gf_select(c, d, bit);
    }

    gf_invert(c, c);
    gf_mul(a, a, c);
    gf_pack(out, a);
}

mdh_err_t mdh_generate_keypair(mdh_keypair_t *kp, mdh_rng_fn rng) {
    static const uint8_t basepoint[32] = { 9 };

    if (kp == NULL || rng == NULL) {
        return MDH_ERR_RNG;
    }

    rng(kp->privkey, sizeof(kp->privkey));
    if (mdh_is_all_zero(kp->privkey, sizeof(kp->privkey))) {
        return MDH_ERR_RNG;
    }

    mdh_clamp_scalar(kp->privkey);
    mdh_x25519(kp->pubkey, kp->privkey, basepoint);
    if (mdh_is_all_zero(kp->pubkey, sizeof(kp->pubkey))) {
        return MDH_ERR_RNG;
    }

    return MDH_OK;
}

mdh_err_t mdh_shared_secret(const uint8_t privkey[32],
                            const uint8_t remote_pub[32],
                            uint8_t out_secret[32]) {
    if (privkey == NULL || remote_pub == NULL || out_secret == NULL) {
        return MDH_ERR_INVALID_KEY;
    }

    if (mdh_is_all_zero(privkey, 32U) || mdh_is_all_zero(remote_pub, 32U)) {
        return MDH_ERR_INVALID_KEY;
    }

    mdh_x25519(out_secret, privkey, remote_pub);
    if (mdh_is_all_zero(out_secret, 32U)) {
        return MDH_ERR_WEAK_KEY;
    }

    return MDH_OK;
}
