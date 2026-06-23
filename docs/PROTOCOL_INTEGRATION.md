# Protocol Integration

`microdh` provides X25519 building blocks. It does not define a full protocol.

## Required protocol behavior

- Bind both public keys into the protocol transcript.
- Use a KDF before treating shared material as a session key.
- Separate identity authentication from key agreement.
- Use role and context labels to prevent key reuse across protocols.
- Preserve replay, session, and channel-binding responsibility in the protocol layer.
- Treat ephemeral/static key use according to the protocol design.
- Validate or policy-check peer keys at the protocol layer when needed.
- Clear secrets after use.
- Abort cleanly on `MDH_ERR_WEAK_PEER_KEY`, `MDH_ERR_RNG`, `MDH_ERR_INVALID_ARGUMENT`, or `MDH_ERR_INTERNAL`.

## Limitations

- Raw X25519 output is not authenticated.
- The library does not prevent MITM attacks.
- The repository does not claim compatibility with any specific higher-level protocol.
