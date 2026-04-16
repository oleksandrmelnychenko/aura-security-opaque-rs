# Wire Protocol Versioning

## Overview

Every wire message in the Aura OPAQUE protocol begins with a **1-byte version prefix**.
The current (and only) version is `0x01`. Both client and server reject messages with
an unknown version byte, returning error code `-10` (`UnsupportedVersion`).

## Wire Format

```
┌──────────┬─────────────────────────────────────┐
│ byte [0] │ bytes [1..N]                        │
│ version  │ payload                             │
├──────────┼─────────────────────────────────────┤
│   0x01   │ message-specific fields             │
└──────────┴─────────────────────────────────────┘
```

All six message types share this layout:

| Message | Total bytes | Payload bytes | Description |
|---------|------------:|:-------------:|-------------|
| Registration Request | 33 | 32 | OPRF-blinded element |
| Registration Response | 65 | 64 | Evaluated element + server public key |
| Registration Record | 169 | 168 | Encrypted envelope + client public key |
| KE1 | 1273 | 1272 | Credential request + ephemeral keys + nonce + ML-KEM PK |
| KE2 | 1377 | 1376 | Nonce + ephemeral PK + credential response + MAC + KEM CT |
| KE3 | 65 | 64 | Client MAC |

## Version Validation

Version is checked by `protocol::check_version()` before any field parsing:

```rust
fn check_version(data: &[u8]) -> OpaqueResult<()> {
    if data.is_empty() {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    match data[0] {
        PROTOCOL_VERSION_1 => Ok(()),
        _ => Err(OpaqueError::UnsupportedVersion),
    }
}
```

Every `parse_*` function calls `check_version()` as its first validation step, before
reading any payload bytes. This means:

- `0x00` → rejected (reserved/invalid)
- `0x01` → accepted (current version)
- `0x02..0xFF` → rejected (future/unknown)

## FFI Error Code

When a version mismatch is detected, the FFI layer returns **`-10`**:

```c
// Return codes
//  -10  Unsupported protocol version
```

Both agent and relay FFI functions propagate this error transparently. The caller
should handle `-10` by logging the mismatch and rejecting the message.

## Version Negotiation

The protocol does **not** perform version negotiation. Both sides must use
the same version. If a client sends version `0x02` to a server that only knows
`0x01`, the server rejects the message immediately.

This is a deliberate design choice:
- **No downgrade attacks** — there is no mechanism to fall back to an older version
- **Simple implementation** — no negotiation round-trip
- **Fail-fast** — mismatched versions are detected at the first message

## Future Version Upgrades

When a new protocol version is introduced:

1. Define `PROTOCOL_VERSION_2: u8 = 0x02` in `types.rs`
2. Add `PROTOCOL_VERSION_2` to the `check_version()` match arm
3. Add parsing logic for the new payload format (if changed)
4. Update `PROTOCOL_VERSION` to the new default for writing
5. Both client and server must be updated before the new version is used

Since there is no negotiation, rolling upgrades require a transition period
where both sides accept `[0x01, 0x02]` but write `0x01`, then switch to
writing `0x02` once all peers are updated.

## Constants

Defined in `opaque-core/src/types.rs`:

```rust
pub const PROTOCOL_VERSION_1: u8 = 0x01;
pub const PROTOCOL_VERSION: u8 = PROTOCOL_VERSION_1;
pub const VERSION_PREFIX_LENGTH: usize = 1;
```

## Test Coverage

6 tests in `opaque-core/tests/protocol_tests.rs` verify that every message type
rejects unknown version bytes (`0x00`, `0x02`, `0xFF`):

- `version_mismatch_registration_request_rejected`
- `version_mismatch_registration_response_rejected`
- `version_mismatch_registration_record_rejected`
- `version_mismatch_ke1_rejected`
- `version_mismatch_ke2_rejected`
- `version_mismatch_ke3_rejected`
