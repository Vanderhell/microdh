# microdh

[![CI](https://github.com/Vanderhell/microdh/actions/workflows/ci.yml/badge.svg)](https://github.com/Vanderhell/microdh/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![C99](https://img.shields.io/badge/C-C99-blue.svg)](https://en.wikipedia.org/wiki/C99)

Minimal X25519 (Curve25519) key exchange for embedded systems in pure C99.
Zero dependencies. Zero allocations. Designed to pair with
[microcrypt](https://github.com/Vanderhell/microcrypt).

## Features

- X25519 key exchange (RFC 7748)
- Keypair generation with pluggable RNG
- Shared secret computation
- Weak key detection
- RFC 7748 test vectors

## Security notice

This is a portable reference implementation. It has not been audited for
side-channel resistance. For high-security production systems, use audited
libraries or hardware accelerators.

## Usage

```c
#include "mdh.h"

mdh_keypair_t kp;
mdh_generate_keypair(&kp, my_rng);

uint8_t shared[32];
mdh_shared_secret(kp.privkey, remote_pubkey, shared);
```

## Build and test

```bash
cmake -B build -DMDH_BUILD_TESTS=ON
cmake --build build
cd build && ctest --output-on-failure
```

## License

MIT - see [LICENSE](LICENSE).
