# Contributing to microdh

## Reporting issues

Use GitHub Issues. Include:
- Platform (ESP32 / Linux / Windows)
- Compiler and version
- Minimal reproducer

## Pull requests

- Fork the repo and create a branch: `git checkout -b fix/your-fix`
- Follow the existing code style (C99, no heap, no dependencies)
- Add or update tests for any change
- All tests must pass: `cmake --build build && ctest`
- Submit a PR with a clear description

## Code style

- C99 strictly
- No dynamic allocation
- No external dependencies
- snake_case for functions and variables
- UPPER_CASE for macros and constants
- Every public function documented in the header

## Versioning

Semantic versioning: MAJOR.MINOR.PATCH
See CHANGELOG.md for history.
