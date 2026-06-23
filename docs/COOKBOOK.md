# Cookbook

This guide uses only public API names from `include/mdh.h` and keeps the examples C99-compatible.

## 1. Generate a keypair with caller-context RNG

Use a platform CSPRNG in real code. The callback below shows the shape of the integration; replace the body with your OS RNG and check its return value.

```c
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "mdh.h"

typedef struct {
    /* Platform-specific RNG state goes here. */
    int unused;
} app_rng_t;

static mdh_err_t app_rng_fill(void *user, uint8_t *buffer, size_t length) {
    app_rng_t *rng = (app_rng_t *)user;
    (void)rng;

    /* Fill buffer with exactly length bytes from a CSPRNG.
       If the platform call fails, return MDH_ERR_RNG. */
    (void)buffer;
    (void)length;
    return MDH_ERR_RNG; /* replace with real platform RNG integration */
}

static mdh_err_t generate_pair(mdh_keypair_t *pair, app_rng_t *rng) {
    mdh_err_t rc = mdh_generate_keypair(pair, app_rng_fill, rng);
    if (rc != MDH_OK) {
        mdh_keypair_clear(pair);
    }
    return rc;
}
```

For tests only, a deterministic callback can be used to supply fixed bytes:

```c
static mdh_err_t test_rng_fill(void *user, uint8_t *buffer, size_t length) {
    static const uint8_t fixed[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    (void)user;
    if (length != sizeof(fixed)) {
        return MDH_ERR_RNG;
    }
    memcpy(buffer, fixed, sizeof(fixed));
    return MDH_OK;
}
```

## 2. Derive a public key from a private key

```c
uint8_t public_key[32];
mdh_err_t rc = mdh_public_key(public_key, keypair.privkey);
if (rc != MDH_OK) {
    mdh_secure_clear(public_key, sizeof(public_key));
}
```

## 3. Use raw X25519

`mdh_x25519()` returns the raw 32-byte RFC 7748 X25519 result.

```c
uint8_t shared_raw[32];
mdh_err_t rc = mdh_x25519(shared_raw, alice.privkey, bob.pubkey);
if (rc != MDH_OK) {
    mdh_secure_clear(shared_raw, sizeof(shared_raw));
}
```

## 4. Use the checked shared-secret path

`mdh_shared_secret_checked()` rejects an all-zero shared result.

```c
uint8_t shared[32];
mdh_err_t rc = mdh_shared_secret_checked(shared, alice.privkey, bob.pubkey);
if (rc == MDH_ERR_WEAK_PEER_KEY) {
    /* Reject the peer public key. */
    mdh_secret_clear(shared);
} else if (rc != MDH_OK) {
    mdh_secret_clear(shared);
}
```

## 5. Clear secrets and keypairs

Use the dedicated clear helpers when you are done with sensitive data.

```c
mdh_secret_clear(shared);
mdh_keypair_clear(&alice);
mdh_keypair_clear(&bob);
```

`mdh_secure_clear()` is the generic helper for other secret buffers.

```c
uint8_t other_secret[32];
mdh_secure_clear(other_secret, sizeof(other_secret));
```

## 6. Handle common error codes

`MDH_ERR_RNG` is returned when the RNG callback fails during key generation.
`MDH_ERR_INVALID_ARGUMENT` means the caller passed a bad pointer or length.
`MDH_ERR_WEAK_PEER_KEY` means the checked shared-secret path rejected an all-zero shared result.

```c
mdh_err_t rc = mdh_generate_keypair(&alice, app_rng_fill, &rng);
if (rc == MDH_ERR_RNG) {
    /* The platform RNG failed. */
} else if (rc == MDH_ERR_INVALID_ARGUMENT) {
    /* The caller passed an invalid argument. */
}

rc = mdh_shared_secret_checked(shared, alice.privkey, bob.pubkey);
if (rc == MDH_ERR_WEAK_PEER_KEY) {
    /* Treat the peer key as invalid for this protocol. */
} else if (rc == MDH_ERR_INVALID_ARGUMENT) {
    /* The caller passed an invalid argument. */
}
```

## 7. Combine X25519 with a KDF conceptually

`microdh` does not provide a KDF API. A safe protocol normally feeds the raw shared secret into a KDF together with transcript or context data, role labels, and identity authentication data.

Conceptually:

1. Compute a raw shared secret with `mdh_shared_secret_checked()` or `mdh_x25519()`.
2. Bind the result to the protocol transcript, negotiated parameters, and identities.
3. Expand or extract application keys with your protocol's KDF.
4. Authenticate the peers separately.

Do not use the raw X25519 output as a standalone session key unless your protocol design explicitly accounts for the missing context binding and authentication steps.
