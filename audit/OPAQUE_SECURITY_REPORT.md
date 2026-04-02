# OPAQUE Protocol Security Audit

> **Historical status.** This report preserves an earlier audit snapshot for
> traceability. It is not the canonical statement of the current repository
> security posture. For the current branch, read
> `audit/SECURITY_AUDIT_2026-03-03.md`, `SECURITY.md`, and the curated public
> headers in `rust/include/`.

## Protocol Configuration
- OPAQUE variant: custom hybrid construction (not RFC 9497 OPAQUE-3DH), using 4 DH terms + ML-KEM-768 combiner
- OPRF suite: custom Ristretto255 OPRF (`hash_to_group` + scalar multiplication)
- KSF: Argon2id(`m=262144 KiB`, `t=3`, `p=1`, output 64 bytes)
- AEAD: XSalsa20-Poly1305 (`crypto_secretbox`)
- Hash: SHA-512
- Implementation: custom (`opaque-core`), not `opaque-ke`

## Remediation Delta (Current Branch)
- Removed broken FFI OPRF-seed export endpoint (`opaque_relay_keypair_get_oprf_seed`).
- Migrated deprecated `xsalsa20poly1305` crate to maintained `crypto_secretbox`.
- Added broad scalar/point zeroization hardening in `opaque-core::crypto` and `oprf`.
- Added `/// # Safety` contracts to all unsafe FFI exports.
- Reduced in-memory lifetime of password/blind material in agent state transitions.

## Threat Model Coverage
| Threat                          | Protected? | Notes |
|---------------------------------|------------|-------|
| Passive network eavesdropper    | Yes        | Session/master keys are derived from authenticated transcript and not sent on wire. |
| Active MITM                     | Partial    | Transcript MACs protect KE2/KE3; still depends on custom non-RFC design assumptions. |
| Server DB compromise            | Partial    | DB-only compromise is harder, but DB + OPRF seed still enables offline dictionary (Critical). |
| Server impersonation            | No         | With server long-term key + OPRF seed compromise, attacker can impersonate server. |
| Offline dictionary attack       | Partial    | Not practical from DB alone, but feasible when `oprf_seed` is compromised with records. |
| Online brute force              | Partial    | No protocol-native throttling/lockout (must be enforced at service layer). |
| Client device compromise        | Partial    | Key material zeroization improved, but runtime compromise still reveals active secrets. |
| Replay attack                   | Yes        | Nonces, ephemeral keys, transcript MACs prevent simple replay. |
| Pre-computation attack          | Partial    | OPRF prevents naive precomputation; compromise of OPRF seed removes this protection. |
| Key compromise impersonation    | Partial    | Compromised client static key allows impersonation; server key compromise is also catastrophic. |

## Flow Verification
- Registration flow present end-to-end:
  - Client blinds password (`create_registration_request` -> `oprf::blind`)
  - Server evaluates OPRF (`create_registration_response` -> `oprf::evaluate`)
  - Client finalizes OPRF, derives randomized password, seals envelope (`finalize_registration`)
  - Server stores registration record (`build_credentials`)
- Login/AKE flow present end-to-end:
  - Client sends credential request + KE1 (`generate_ke1`)
  - Server returns evaluated OPRF element + envelope + KE2 (`generate_ke2`)
  - Client finalizes OPRF, opens envelope, sends KE3 (`generate_ke3`)
  - Server verifies KE3 and finishes (`responder_finish`)
- Deviation note:
  - This is not RFC 9497 OPAQUE-3DH; it is a custom hybrid with 4 DH terms plus PQ-KEM combiner.

## Findings

### [CRITICAL-001] Offline Dictionary Attack If OPRF Seed Is Compromised With DB (OPEN)
- **File**: `rust/crates/opaque-core/src/crypto.rs:232`, `rust/crates/opaque-relay/src/authentication.rs:100`, `rust/crates/opaque-relay/src/registration.rs:28`
- **Attack**:
  - Per-account OPRF keys are derived from `oprf_seed` + `account_id`.
  - If attacker gets `oprf_seed` and stored registration records, they can test password guesses offline:
    1. Compute OPRF output for guessed password.
    2. Derive `randomized_pwd` with Argon2id.
    3. Try opening stored envelope.
  - Success validates the guessed password and recovers client static key.
- **Impact**: Full password recovery at scale and user impersonation without rate limits.
- **PoC**: `./audit/poc/critical_001_offline_dictionary_after_server_compromise.rs`
- **Fix**:
  - Treat `oprf_seed` as HSM/KMS-protected secret, never exportable.
  - Keep seed export interfaces disabled.
  - Rotate server secret material and re-enroll credentials after suspected exposure.

### [HIGH-001] Custom Non-RFC OPAQUE Variant (OPEN ARCHITECTURAL RISK)
- **File**: `rust/crates/opaque-agent/src/authentication.rs:130`, `rust/crates/opaque-relay/src/authentication.rs:119`, `rust/crates/opaque-core/src/types.rs:104`
- **Attack**:
  - The implementation is a custom 4DH + ML-KEM combiner, not RFC 9497 OPAQUE-3DH and not built on `opaque-ke`.
  - Security claims rely on local reasoning/tests, not a published proof for this exact construction.
- **Impact**: Higher residual risk of subtle design flaws versus standardized, analyzed OPAQUE profiles.
- **PoC**: N/A (architectural risk).
- **Fix**:
  - Prefer migration to RFC 9497-compatible `opaque-ke` profile and add PQ as a formally reviewed extension.
  - If custom design remains, produce formal model/proof and third-party cryptographic review.

### [RESOLVED-MEDIUM-001] Unmaintained Cryptographic Dependency in Core Path (FIXED)
- **File**: `rust/Cargo.toml:24`
- **Attack (pre-fix)**: `cargo audit` flagged `xsalsa20poly1305` (`RUSTSEC-2023-0037`) as unmaintained.
- **Impact**: Increased supply-chain and maintenance risk for a core cryptographic primitive.
- **PoC**: N/A
- **Fix applied**:
  - Migrated to maintained replacement (`crypto_secretbox`) in workspace dependencies and `opaque-core`.

### [RESOLVED-CRITICAL-002] Identity Point Injection in OPRF/DH Inputs (FIXED)
- **File**: `rust/crates/opaque-core/src/crypto.rs:28`, `rust/crates/opaque-core/src/crypto.rs:98`, `rust/crates/opaque-core/src/crypto.rs:106`
- **Attack (pre-fix)**:
  - Identity Ristretto points were accepted as valid OPRF and DH inputs.
  - Active MITM could inject identity elements during registration OPRF flow, degrading OPRF contribution.
- **Impact**: Protocol downgrade risk and weakened password-hardening assumptions under active manipulation.
- **PoC**: `./audit/poc/critical_002_identity_point_injection.rs`
- **Fix applied**:
  - Added central `decode_non_identity_point` validation.
  - `validate_ristretto_point`, `validate_public_key`, and `scalar_mult` now reject identity points.
  - Added regression tests in `crypto_tests.rs` and `oprf_tests.rs`.

### [RESOLVED-HIGH-002] Account Enumeration Oracle in KE2 Path (FIXED)
- **File**: `rust/crates/opaque-relay/src/authentication.rs:69`, `rust/crates/opaque-ffi/src/relay_ffi.rs:269`
- **Attack (pre-fix)**: Missing accounts triggered distinct immediate failures.
- **Fix applied**: Added fake credential path, aligned KE2 path work for missing/existing accounts, and tolerant FFI KE2 handling for absent credentials.

### [RESOLVED-HIGH-003] Client Static Key Lifetime in Initiator State (FIXED)
- **File**: `rust/crates/opaque-agent/src/authentication.rs:224`, `rust/crates/opaque-agent/src/authentication.rs:281`, `rust/crates/opaque-agent/src/state.rs:168`
- **Attack (pre-fix)**: Static private key remained in memory longer than required.
- **Fix applied**: Added explicit zeroization in success/error paths and `ZeroizeOnDrop` for initiator wrapper.

### [RESOLVED-HIGH-004] KE3 Retry on Same Responder State After Failure (FIXED)
- **File**: `rust/crates/opaque-relay/src/authentication.rs:227`, `rust/crates/opaque-agent/tests/integration.rs:294`
- **Attack (pre-fix)**:
  - After failed `responder_finish`, state stayed in `Ke2Generated` with zeroized-but-nonempty key buffers.
  - A second `responder_finish` call on the same state could be abused as a retry oracle and state-machine bypass vector.
- **Impact**: Authentication-state confusion and potential bypass under state reuse.
- **PoC**: `./audit/poc/high_003_ke3_retry_state_reuse.rs`
- **Fix applied**:
  - Mark responder state terminal (`Finished`) on KE3 authentication failure.
  - Clear key buffers after zeroization to prevent nonempty-zero key material reuse.
  - Added integration regression test `responder_finish_rejects_replay_after_failed_ke3`.

## Recommendations
1. Priority fixes (with effort estimates)
   - P0 (2-4 days): isolate `oprf_seed` in HSM/KMS or process boundary; plan rotation/re-enrollment workflow.
   - P1 (1-2 days): complete remaining memory hardening (`secure_key` as `SecureBytes`, finalize scalar zeroization edge case).
   - P1 (2-3 days): harden FFI lifecycle (`destroy` APIs against double-free, panic poisoning).
   - P2 (1-2 days): add service-layer brute-force defenses (rate limiting, lockout, abuse telemetry).
2. Missing security properties
   - RFC 9497 compatibility/security proof is absent for the custom 4DH+PQ design.
   - OPRF-seed compromise resilience depends on external secret-management controls.
3. Fuzzing targets
   - OPRF input handling (`credential_request`, `evaluated_element`).
   - Envelope parsing/open path and malformed `ENVELOPE_LENGTH` layouts.
   - KE1/KE2/KE3 parsing and transcript assembly logic.
   - FFI boundary functions using raw pointers and length arguments.
4. Formal verification candidates
   - Handshake state machine (`InitiatorPhase`/`ResponderPhase`) and key-confirmation invariants.
   - Key schedule and transcript binding equivalence between initiator/responder.
   - Authentication guarantees under key compromise scenarios.

## Recon/Validation Notes
- Full Rust workspace pass completed across all source, tests, and benches.
- `cargo test`: all tests passed.
- `cargo audit`: no hard CVE breakage in core protocol crates, but unmaintained crypto crate warning in active dependency path.
- `unsafe` usage appears confined to FFI boundary crates.
