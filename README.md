# Ecliptix OPAQUE

[![CI](https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/actions/workflows/ci.yml)
[![Benchmarks](https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/oleksandrmelnychenko/ecliptix-opaque-rs/actions/workflows/benchmarks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Hybrid post-quantum **OPAQUE** implementation in Rust combining **4DH Ristretto255** with **ML-KEM-768** for password-authenticated key exchange.

## Security Posture

This repository ships:

- Production Rust implementations of the agent, relay, and FFI layers.
- Regression tests for known security classes, including identity-point rejection, terminal-state reuse rejection, and the `oprf_seed` compromise boundary.
- Symbolic models in `formal/` that support the protocol narrative, but do **not** constitute an exact proof of the shipping implementation.

Security claims are intentionally scoped to the implemented trust boundary:

| Property | Status | Scope |
|----------|--------|-------|
| Session key secrecy | Supported by symbolic models + Rust tests | Honest endpoints, uncompromised ephemeral secrets |
| Password secrecy on the wire | Supported by symbolic models + Rust tests | Password never appears directly in protocol messages |
| Hybrid combiner / PQ contribution | Supported by Rust tests + surrogate symbolic models | Depends on the implemented 4DH + ML-KEM transcript combiner |
| Mutual authentication | Supported by symbolic models + Rust tests | Assumes correct relay public key pinning and trusted transport |
| Offline dictionary resistance | **Scoped** | Holds for DB compromise **without** `oprf_seed` compromise |

## Attack Coverage

The test suite exercises multiple failure classes directly in code. Important boundary conditions:

| Attack | Protection | Tests |
|--------|-----------|-------|
| **Offline dictionary after DB-only compromise** | Argon2id hardness + server-side OPRF key separation | regression + property tests |
| **Offline dictionary after `oprf_seed` compromise** | Not prevented by design; documented operator boundary | regression test |
| **Server impersonation (MITM)** | KE2 MAC verification, 4DH mutual auth | 4 |
| **Client impersonation** | KE3 MAC verification | 2 |
| **Replay attack** | Fresh ephemeral keys + nonce binding per session | 2 |
| **Transcript tampering** | HMAC-SHA512 on all KE messages, detected at every byte position | deterministic + fuzz |
| **Forward secrecy (classical)** | Ephemeral 4DH — past sessions safe after LTK compromise | 3 |
| **Forward secrecy (post-quantum)** | ML-KEM-768 ephemeral encapsulation | 3 |
| **Quantum key recovery** | ML-KEM-768 protects if DH is broken | 3 |
| **AND-model violation** | HKDF-SHA512 combiner — both DH and KEM must break | 4 |
| **Password leakage** | OPRF blinding, password absent from all wire messages | 7 |
| **Version downgrade** | 1-byte version prefix, no negotiation, unknown versions rejected | 6 |

**Property-based tests** (proptest) verify with randomized inputs that:
- Any wrong password always fails authentication
- Any single-byte tampering of KE2 (at every offset) is always detected
- Any single-byte tampering of KE3 (at every offset) is always detected
- Different sessions always produce different session keys

## Cryptographic Primitives

| Primitive | Algorithm | Crate |
|-----------|-----------|-------|
| Elliptic Curve DH | Ristretto255 (4DH) | curve25519-dalek |
| Key Encapsulation | ML-KEM-768 | ml-kem (FIPS 203) |
| Key Stretching | Argon2id | argon2 |
| MAC | HMAC-SHA512 | hmac + sha2 |
| AEAD | XSalsa20-Poly1305 | crypto_secretbox |
| OPRF | Ristretto255 | curve25519-dalek |
| PQ Combiner | HKDF-SHA512 (AND-model) | hmac + sha2 |
| Constant-time comparison | subtle | subtle |

## Architecture

```
rust/crates/
  opaque-core/     Cryptographic primitives, OPRF, KEM, envelope
  opaque-agent/    Agent (initiator) — registration & authentication
  opaque-relay/    Relay (responder) — registration & authentication
  opaque-ffi/      C FFI bindings (cdylib + staticlib)
```

## Build

```bash
cd rust
cargo build --release
```

Pure Rust — no system dependencies, no C compiler required.

### FFI Build Profiles

For Swift clients, build **portable** artifacts only:

```bash
./rust/scripts/build-client-portable.sh
```

```powershell
.\rust\scripts\build-client-portable.ps1
```

For server-side relay deployments on controlled hardware, you can use
native CPU tuning (`-C target-cpu=native`) for better throughput:

```bash
./rust/scripts/build-server-native.sh
```

```powershell
.\rust\scripts\build-server-native.ps1
```

Optional target triple can be passed as an argument in all scripts.

## Test

```bash
cd rust
cargo test --workspace
```

Focused security regressions for the agent/relay boundary live in:

```bash
cd rust
cargo test -p opaque-agent --test security_regressions
```

That suite covers known failure classes such as identity-point rejection, registration-response MITM rejection, fake-credential fail-closed behavior for unknown users, and rejection of corrupted registered credentials.

## Benchmarks

```bash
cd rust
cargo bench --workspace
```

Three Criterion benchmark suites:
- **Micro** — Ristretto255 keygen/DH, ML-KEM-768, OPRF, Argon2id, HMAC, HKDF, AEAD
- **Protocol** — registration and authentication phases end-to-end
- **Throughput** — relay KE2 generation and finish operations per second

## FFI

The canonical public C contract lives in `rust/include/`:

- `opaque_common.h`
- `opaque_agent.h`
- `opaque_relay.h`
- `opaque_api.h`

The Apple packaging path now stages those curated headers and `module.modulemap` directly into the XCFramework. The current Swift wrapper still uses a temporary ABI shim while the republished XCFramework/module path is rolled out, but the canonical ABI source is the curated header set above.

| Platform | Package |
|----------|---------|
| iOS/macOS | `EcliptixOPAQUE.xcframework` (Swift Package Manager) |

## Formal Verification

Models and proof logs live in `formal/`, but they should be read as **protocol evidence**, not as a line-by-line proof of the shipped Rust implementation:

- `hybrid_pq_opaque.spthy` and `hybrid_pq_opaque_verified.spthy` model surrogate/abstract DH behaviour.
- `hybrid_pq_opaque.pv` and `hybrid_pq_opaque_auth.pv` split secrecy and authentication into separate ProVerif models.
- `formal/logs/FULL_VERIFICATION_REPORT.md` documents the exact boundary between symbolic claims and implementation evidence.

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
