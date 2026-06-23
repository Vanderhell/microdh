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
- Raw X25519 output is not an application session key by itself.
- Applications still need a KDF and protocol context binding.
- Identity authentication is a separate layer.

## Security notes

- RNG input must be a CSPRNG.
- Checked shared-secret derivation rejects an all-zero shared result.
- Public secret-writing APIs clear output on failure when an output buffer is provided.
- Zero external dependencies means no third-party runtime dependencies; the C standard library is still used.
- Side-channel resistance is not formally verified.
- Hardware verification, certification, and independent audit are `NOT VERIFIED`.

## Verified platform

- Verified in this task: Windows, Visual Studio 17 2022, MSVC 19.42.34444.0, Debug generator.
- Other compilers, sanitizers, MCUs, and hardware targets are `NOT VERIFIED`.

## Build

```powershell
cmake -S . -B build -DMDH_BUILD_TESTS=ON -DMDH_BUILD_INTERNAL_TESTS=ON
cmake --build build --parallel
ctest --test-dir build -C Debug --output-on-failure
```

Install the package and run the consumer smoke test from the build tree:

```powershell
cmake --install build --prefix build/_install
cmake -S tests/consumer -B build/consumer -DCMAKE_PREFIX_PATH=build/_install
cmake --build build/consumer --config Debug
```

## License

See `LICENSE`.
