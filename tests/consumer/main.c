#include "mdh.h"

#include <string.h>

typedef struct {
    uint8_t seed;
    uint8_t step;
} consumer_rng_t;

static mdh_err_t consumer_rng(void *user, uint8_t *buffer, size_t length) {
    consumer_rng_t *state = (consumer_rng_t *)user;
    size_t i;

    if (state == NULL) {
        return MDH_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < length; ++i) {
        buffer[i] = (uint8_t)(state->seed + (uint8_t)(i * state->step));
    }
    state->seed = (uint8_t)(state->seed + 0x21U);
    return MDH_OK;
}

static int is_all_zero(const uint8_t *buf, size_t len) {
    size_t i;
    uint8_t acc = 0;

    for (i = 0; i < len; ++i) {
        acc |= buf[i];
    }
    return acc == 0;
}

int main(void) {
    mdh_keypair_t a;
    mdh_keypair_t b;
    uint8_t shared_ab[32];
    uint8_t shared_ba[32];
    consumer_rng_t rng_a = { 0x10U, 13U };
    consumer_rng_t rng_b = { 0x80U, 7U };

    if (mdh_generate_keypair(&a, consumer_rng, &rng_a) != MDH_OK) {
        return 1;
    }
    if (mdh_generate_keypair(&b, consumer_rng, &rng_b) != MDH_OK) {
        mdh_keypair_clear(&a);
        return 1;
    }
    if (mdh_shared_secret_checked(shared_ab, a.privkey, b.pubkey) != MDH_OK) {
        mdh_keypair_clear(&a);
        mdh_keypair_clear(&b);
        return 1;
    }
    if (mdh_shared_secret_checked(shared_ba, b.privkey, a.pubkey) != MDH_OK) {
        mdh_keypair_clear(&a);
        mdh_keypair_clear(&b);
        mdh_secret_clear(shared_ab);
        return 1;
    }
    if (memcmp(shared_ab, shared_ba, sizeof(shared_ab)) != 0 || is_all_zero(shared_ab, sizeof(shared_ab))) {
        mdh_keypair_clear(&a);
        mdh_keypair_clear(&b);
        mdh_secret_clear(shared_ab);
        mdh_secret_clear(shared_ba);
        return 1;
    }

    mdh_keypair_clear(&a);
    mdh_keypair_clear(&b);
    mdh_secret_clear(shared_ab);
    mdh_secret_clear(shared_ba);
    return 0;
}
