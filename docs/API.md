# API

## Public surface

- `mdh_x25519(out, scalar, u_coordinate)` is the raw RFC 7748 primitive.
- `mdh_shared_secret_checked(out_secret, private_key, peer_public_key)` calls raw X25519 and rejects an all-zero shared result.
- `mdh_shared_secret()` is a compatibility wrapper that preserves the legacy name.
- `mdh_public_key(out_public, private_key)` derives the X25519 public key for a private key.
- `mdh_generate_keypair(keypair, rng, rng_user)` requests 32 RNG bytes from the caller-provided callback.
- `mdh_secure_clear()`, `mdh_keypair_clear()`, and `mdh_secret_clear()` clear sensitive buffers.

## Semantics

- Raw X25519 accepts any 32-byte scalar and clamps a local copy.
- Raw X25519 masks the high bit of the u-coordinate input.
- Checked shared-secret derivation zeroes the output on failure when an output buffer is provided.
- Key generation zeroes the full keypair on failure.
- Null inputs are treated as invalid arguments.
- The RNG callback must be a CSPRNG.

## Aliasing

- Exact full-buffer aliasing is supported by copying inputs before output writes.
- Partial overlap is exercised in tests and should not be relied on as an API guarantee.
