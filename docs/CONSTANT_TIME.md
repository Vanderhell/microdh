# Constant Time

## Verified scope

- The Montgomery ladder runs a fixed number of iterations for X25519.
- Scalar-bit swaps are implemented with bit masks.
- Secret scalar processing does not use secret-dependent array indexing in the ladder.
- Peer public-key checks happen on public input encodings in the checked wrapper.

## Not verified

- Compiler output is not formally proven constant time.
- Formal verification is `NOT VERIFIED`.
- Side-channel resistance for every target compiler, optimizer, MCU, or accelerator is `NOT VERIFIED`.
- Fault-injection resistance, DPA/SPA/EM resistance, and cache behavior are `NOT VERIFIED`.

## Assumptions

- The code assumes 8-bit bytes and two's-complement signed integers.
- The implementation currently uses signed 64-bit limb arithmetic with explicit compile-time checks.
- Platform-specific accelerators are outside the verified scope unless separately tested.
