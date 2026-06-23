# RNG

`mdh_generate_keypair()` takes a caller-context RNG callback:

```c
typedef mdh_err_t (*mdh_rng_fn)(void *user, uint8_t *buffer, size_t length);
```

## Requirements

- The callback must write exactly 32 bytes on success.
- The callback must return `MDH_OK` on success and `MDH_ERR_RNG` on failure.
- The RNG source must be a CSPRNG.
- The library does not fall back to `rand()`, timestamps, MAC addresses, device IDs, or an unseeded PRNG.
- No global RNG state is used by the library.

## Failure handling

- A callback failure clears the keypair before returning `MDH_ERR_RNG`.
- Null RNG inputs are treated as invalid arguments.
- Deterministic test RNGs are for tests only and are not a security substitute.
