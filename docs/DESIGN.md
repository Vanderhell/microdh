# Design

`microdh` implements X25519 over the Montgomery form of Curve25519 as a small,
portable C99 library intended for embedded targets.

## Goals

- No dynamic allocation
- No external dependencies
- Small public API
- Portable across ESP32, Linux, and Windows

## Implementation notes

- Scalar multiplication uses the Montgomery ladder from RFC 7748.
- Field arithmetic uses a 5x51-bit limb representation over GF(2^255 - 19).
- Private scalars are clamped exactly once before use.
- Weak peer keys are rejected by treating an all-zero shared secret as a
  small-subgroup failure.

## RNG integration

The library does not ship a platform RNG abstraction beyond the callback-based
`mdh_rng_fn`. Embedded targets can wire this to a HAL-backed entropy source.
