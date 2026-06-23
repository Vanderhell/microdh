# microdh

`microdh` is a small portable C99 library for X25519/Curve25519 only.

## What it does

- Raw RFC 7748 X25519 primitive: `mdh_x25519()`
- Checked shared-secret API: `mdh_shared_secret_checked()`
- Public-key derivation: `mdh_public_key()`
- Caller-context key generation: `mdh_generate_keypair()`
- Explicit secure-clear helpers: `mdh_secure_clear()`, `mdh_keypair_clear()`, `mdh_secret_clear()`

## What it does not do

- It is not authenticated key exchange.
- It does not prevent man-in-the-middle attacks.
- Raw X25519 output is not a session key by itself.
- Applications still need a KDF, transcript or context binding, and separate identity authentication.
- This library does not implement full protocols.

## Security and scope

- RNG input must be a CSPRNG.
- Checked shared-secret derivation rejects an all-zero shared result.
- Public secret-writing APIs clear output on failure when an output buffer is provided.
- Side-channel resistance is not formally verified.
- No independent audit, formal proof, hardware execution, or certification is claimed here.

## Verified platforms and evidence

Local verification evidence is recorded in [docs/VERIFICATION.md](docs/VERIFICATION.md).

- Windows / Visual Studio 17 2022 / MSVC 19.42.34444.0 / Debug fast verification
- MSYS2 UCRT64 GCC 16.1.0 / Debug and Release fast verification
- MSYS2 UCRT64 Clang 22.1.7 / Debug and Release fast verification
- MSYS2 CLANG64 Clang 22.1.7 / ASan+UBSan sanitizer verification
- ARM Cortex-M0 and Cortex-M4 compile/link smoke
- RFC 7748 1,000,000-iteration slow test completion

## Further reading

- [API reference](docs/API.md)
- [RNG guidance](docs/RNG.md)
- [Protocol integration](docs/PROTOCOL_INTEGRATION.md)
- [Constant-time notes](docs/CONSTANT_TIME.md)
- [Footprint data](docs/FOOTPRINT.md)
- [Verification evidence](docs/VERIFICATION.md)
- [Cookbook](docs/COOKBOOK.md)
- [Security policy](SECURITY.md)
- [Contributing guide](CONTRIBUTING.md)
- [Support](SUPPORT.md)

## Build

See [docs/VERIFICATION.md](docs/VERIFICATION.md) for the exact local commands used for verification.

## License

See `LICENSE`.
