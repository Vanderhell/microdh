# Security

## Scope

`microdh` implements X25519 only. It does not provide authenticated key exchange or man-in-the-middle protection.

## Reporting

Report suspected security issues privately to the repository maintainers through the repository issue or security contact path used for this project.

Include:

- the affected version or commit
- a minimal reproducer
- the observed impact
- whether the issue affects raw X25519, checked shared secret handling, zeroization, or packaging

## Disclosure

- The maintainers will acknowledge receipt when practical.
- Fixes should be coordinated before public disclosure when the report is actionable.
- This repository does not claim an independent audit.

## Non-claims

- No claim of certification
- No claim of formal verification
- No claim of hardware verification
- No claim of side-channel immunity
