# Changelog

## [2.0.0] - 2026-06-23

### Changed
- Split the raw RFC 7748 X25519 primitive from the checked shared-secret wrapper
- Changed key-generation RNG callbacks to accept caller context and request exactly 32 bytes
- Added explicit secure-clear helpers for keys, secrets, and arbitrary buffers
- Added installable package targets and consumer smoke coverage

### Fixed
- Conditional-swap mask construction now normalizes the selector bit to a full-width mask
- Public secret-writing APIs now clear outputs on failure
- Checked shared-secret derivation now rejects all-zero results consistently
- Test harness and internal instrumentation now avoid hidden mutable RNG state

## [1.0.1] - 2026-04-02

### Fixed
- RNG callback failures now propagate as `MDH_ERR_RNG` during key generation
- Sensitive X25519 temporaries are explicitly zeroized with a volatile wipe
- Peer key validation now rejects all-zero inputs and known small-subgroup points
- Constant-time expectations are documented in the X25519 implementation
- Test coverage now includes RNG failure propagation and zeroization checks

## [1.0.0] - 2026-04-02

### Added
- X25519 key exchange (RFC 7748)
- Keypair generation with pluggable RNG
- Shared secret computation
- Weak key detection
- RFC 7748 test vectors
- CMakeLists.txt
- ESP32 HAL-ready RNG hook
