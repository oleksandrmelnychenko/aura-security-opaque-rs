# Aura Hybrid PQ-OPAQUE — Security Audit Report

**Date:** 2026-03-03
**Scope:** Full Rust workspace (`opaque-core`, `opaque-agent`, `opaque-relay`, `opaque-ffi`)
**Methodology:** Manual source code review + static analysis + dependency audit
**Lines of code audited:** ~2729 production + ~2700 test
**Auditor:** Claude Opus 4.6 (automated multi-agent security review)

---

## Executive Summary

The Aura Hybrid PQ-OPAQUE implementation demonstrates **strong security engineering**. The protocol is correctly implemented with proper 4DH computation, sound hybrid PQ combiner (AND-model), complete transcript binding including ML-KEM material, and consistent use of constant-time operations. No CRITICAL or HIGH-severity vulnerabilities were found in the cryptographic protocol itself.  

Post-audit remediation is now in progress: the previously reported broken OPRF-seed FFI endpoint was removed, deprecated AEAD dependency was migrated, and most scalar/KEM zeroization hardening was implemented. Remaining work is mostly defense-in-depth.

### Initial Finding Statistics (Pre-Fix Baseline)

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 8 |
| LOW | 14 |
| INFO | 5 |
| POSITIVE | 18 |
| **Total** | **46** |

---

## Remediation Status (Current Branch)

| ID | Status | Notes |
|----|--------|-------|
| H-01 | **Fixed** | `opaque_relay_keypair_get_oprf_seed` endpoint removed from the curated public FFI surface. |
| M-01 | **Fixed** | All reviewed `Scalar` temporaries in `opaque-core/src/crypto.rs` are explicitly zeroized after use. |
| M-02 | **Fixed** | `ml-kem` built with `zeroize` feature, `dk_array` zeroized, `DK` lifetime narrowed and dropped immediately after decapsulation. |
| M-03 | **Partially fixed** | Password/blind lifetime reduced and explicit zeroization added earlier; `secure_key` remains `Vec<u8>` in initiator state. |
| M-05 | **Fixed** | `/// # Safety` docs added for all unsafe FFI exports in `agent_ffi.rs` and `relay_ffi.rs`. |
| M-08 | **Fixed** | Migrated from deprecated `xsalsa20poly1305` to `crypto_secretbox`. |

---

## Historical Findings (Pre-Fix Snapshot)

The items below preserve the original audit narrative for traceability.  
Current status should be taken from the `Remediation Status (Current Branch)` table above.
### H-01 — FFI `opaque_relay_keypair_get_oprf_seed` is broken (always fails)

**File:** `rust/crates/opaque-ffi/src/relay_ffi.rs:70-85`
**OWASP:** A04:2021 — Insecure Design

The function ignores its `_handle` parameter (prefixed with underscore), writes **zeros** to the caller's buffer, and unconditionally returns `ValidationError`. No caller can ever retrieve the OPRF seed through FFI.

**Risk:** Downstream consumers (C/C#) that don't check the return code will receive an all-zero OPRF seed, completely breaking OPRF derivation and producing predictable outputs. Consumers that check the return code will be unable to persist/restore the OPRF seed, losing all registration data on server restart.

**Fix:** Implemented by removal of the endpoint from FFI API surface in current branch.

---

## MEDIUM Severity

### M-01 — Stack-resident `Scalar` not zeroized in crypto primitives

**Files:** `rust/crates/opaque-core/src/crypto.rs:53-77, 80-96, 114-125, 360-368, 383-395`

Functions `derive_key_pair`, `scalar_mult`, `scalarmult_base`, `hash_to_scalar`, `random_nonzero_scalar`, and `scalar_invert` create intermediate `Scalar` values on the stack that are never zeroized. `curve25519_dalek::Scalar` implements `Zeroize`, so explicit zeroization is straightforward.

**Risk:** The private key/blind scalar material lingers on the stack until the frame is reused. Exploitable via physical memory access or a memory disclosure vulnerability elsewhere.

**Fix:** Use `let mut scalar = ...; /* use */ scalar.zeroize();` pattern.

### M-02 — ML-KEM `DecapsulationKey` not zeroized after use

**File:** `rust/crates/opaque-core/src/pq_kem.rs:64-91`

The decoded `DK` (2400 bytes) and `dk_array` remain on the stack after `decapsulate` returns. Similarly, `keypair_generate` (line 18-32) does not zeroize `dk` after extracting bytes.

**Fix:** Wrap in `Zeroizing<>` or add explicit `.zeroize()` calls.

### M-03 — Password (`secure_key`) retained as `Vec<u8>` across network round-trip

**Files:** `rust/crates/opaque-agent/src/state.rs:26`, `rust/crates/opaque-agent/src/authentication.rs:27,88`

The plaintext password is stored at `generate_ke1` time and not consumed until `generate_ke3` (OPRF finalize). This creates a window (potentially hundreds of ms) where the password sits in heap memory during client-server communication.

**Risk:** Cold-boot attacks, memory dumps, swap-file exposure. Additionally, `Vec<u8>` reallocations may leave copies in freed-but-not-wiped allocator memory.

**Fix:** Consider using `SecureBytes` (already defined in `types.rs`) instead of `Vec<u8>` for the `secure_key` field.

### M-04 — FFI: Double-free not prevented on destroy functions

**Files:** `agent_ffi.rs:62-68,86-92`, `relay_ffi.rs:61-67,126-132,150-156`

All five `_destroy` functions check for null but cannot prevent a caller from passing the same handle twice. The second `Box::from_raw` on freed memory causes undefined behavior.

**Fix:** Change signature to `*mut *mut c_void` to null out caller's copy after free, or at minimum document the contract clearly.

### M-05 — FFI: No `// SAFETY:` documentation on 17 unsafe functions

**Files:** `agent_ffi.rs`, `relay_ffi.rs` (all `unsafe extern "C" fn`)

None of the 17 unsafe FFI entry points document their safety invariants. For a security-critical crypto library, this is an audit and maintenance hazard.

**Fix:** Add `/// # Safety` doc comments to every `pub unsafe extern "C" fn`.

### M-06 — FFI: `AssertUnwindSafe` without state-poisoning mechanism

**Files:** Both FFI files, all `catch_unwind` sites

If a panic occurs mid-mutation of a handle's internal state, `catch_unwind` returns `FFI_PANIC` but the handle is left in a partially mutated, possibly inconsistent state. Subsequent use could produce incorrect cryptographic results.

**Fix:** Add a "poisoned" flag to state handles, set on panic recovery, checked at operation start.

### M-07 — FFI: `agent_handle` parameter unused in `create_registration_request`

**File:** `rust/crates/opaque-ffi/src/agent_ffi.rs:95-129`

The parameter is null-checked but never dereferenced. Misleading API contract.

### M-08 — `xsalsa20poly1305` is deprecated (RUSTSEC-2023-0037)

**File:** `rust/Cargo.toml`

The crate has been renamed to `crypto_secretbox` since 2023. It will receive no security patches.

**Fix:** Migrate to `crypto_secretbox = "0.1"` (API-compatible).

---

## LOW Severity

| ID | Finding | File(s) |
|----|---------|---------|
| L-01 | No state expiration/timeout mechanism | `agent/state.rs`, `relay/state.rs` |
| L-02 | State struct fields are `pub` (should be `pub(crate)`) | `agent/state.rs`, `relay/state.rs` |
| L-03 | Minor timing difference in fake credential path (conditional `validate_public_key`) | `relay/authentication.rs:73-81` |
| L-04 | No OPRF seed rotation mechanism | `relay/state.rs:188-222` |
| L-05 | No ML-KEM public key validation before encapsulation | `pq_kem.rs:34-61` |
| L-06 | `constant_time_eq` length check is not CT (benign — lengths always match) | `types.rs:260-266` |
| L-07 | Registration flow has no state machine enforcement | `agent/registration.rs` |
| L-08 | `oprf_seed` stack copy not zeroized on error paths in `create_with_keys` | `relay_ffi.rs:352-390` |
| L-09 | No FFI-specific test suite | `opaque-ffi/` crate |
| L-10 | `curve25519-dalek` version range too broad (`"4"` instead of `"=4.1.3"`) | `Cargo.toml` |
| L-11 | `zeroize` version range too broad (`"1"` instead of `"1.8"`) | `Cargo.toml` |
| L-12 | Yanked dev-dependencies (`js-sys`, `wasm-bindgen`) | `Cargo.lock` |
| L-13 | Missing `aarch64-unknown-linux-gnu` target crypto flags | `.cargo/config.toml` |
| L-14 | `cbindgen` outdated (0.27 vs 0.29) | `Cargo.toml` |

---

## Positive Findings (Security Strengths)

| ID | Strength | Location |
|----|----------|----------|
| P-01 | OPRF blind/evaluate/finalize flow correct with domain separation | `oprf.rs` |
| P-02 | Envelope seal/open: authenticated encryption with key consistency check | `envelope.rs` |
| P-03 | HMAC verification uses `subtle::ConstantTimeEq` | `crypto.rs:153-165` |
| P-04 | `constant_time_eq` and `is_all_zero` use constant-time operations | `types.rs:259-276` |
| P-05 | Error types are generic — no information leakage for oracle attacks | `types.rs:119-147` |
| P-06 | Consistent `OsRng` usage — no weak/deterministic RNG anywhere | Multiple files |
| P-07 | `SecureBytes`/`Envelope` implement `Zeroize + ZeroizeOnDrop`, `Debug` is `[REDACTED]` | `types.rs:167-257` |
| P-08 | All state structs derive `Zeroize + ZeroizeOnDrop` | Both state files |
| P-09 | Identity point and zero scalar rejected in all DH operations | `crypto.rs` |
| P-10 | 4DH computation correct and symmetric between initiator/responder | Agent/Relay `authentication.rs` |
| P-11 | Hybrid combiner: HKDF-Extract(transcript_salt, dh1‖dh2‖dh3‖dh4‖ss_kem) — sound AND-model | `pq_kem.rs:93-121` |
| P-12 | Transcript includes `pq_eph_pk` (1184 B) and `kem_ciphertext` (1088 B) — downgrade protection | Agent/Relay `authentication.rs` |
| P-13 | Fake credentials prevent user enumeration attacks | `relay/authentication.rs:18-42` |
| P-14 | Strict exact-length message parsing | `protocol.rs` |
| P-15 | Compile-time assertions verify structural constants | `types.rs:61-71` |
| P-16 | Panic-safe FFI boundary with `catch_unwind` + `FFI_PANIC = -99` | Both FFI files |
| P-17 | Release profile: LTO + codegen-units=1 + overflow-checks + strip symbols | `Cargo.toml` |
| P-18 | All crypto deps from trusted RustCrypto/dalek-cryptography, zero known vulns | `Cargo.lock` |

---

## Recommended Fix Priority

### Immediate (before any production/external deployment)
1. **M-03** — Replace `InitiatorState.secure_key: Vec<u8>` with `SecureBytes`
2. **M-04** — Harden FFI destroy API against double-free misuse
3. **M-06** — Add panic-poisoning for mutable FFI state handles

### Short-term (before v1.0)
4. **M-07** — Remove/actually use unused `agent_handle` parameter in FFI
5. **L-01** — Add state expiration/timeout
6. **L-02** — Change state fields to `pub(crate)`
7. **L-09** — Add FFI integration test suite

### Maintenance
8. **L-10, L-11** — Tighten crypto dependency version pinning
9. **L-13** — Add ARM Linux target crypto flags
10. **L-03** — Equalize timing in fake credential path

---

## Overall Assessment

**Rating: STRONG** — This implementation is of high quality for a security-critical cryptographic library. The protocol design is sound (4DH + ML-KEM-768 AND-composition with full transcript binding), the code demonstrates consistent defensive programming (constant-time ops, input validation, zeroization on error paths, identity point rejection), and the build configuration is well-hardened.

The identified issues are primarily defense-in-depth concerns (stack zeroization, version pinning) rather than protocol-breaking vulnerabilities. The single HIGH finding (H-01) is an FFI API bug, not a cryptographic flaw.

No path was identified that would allow an attacker to:
- Bypass authentication without knowing the password
- Recover the password from observed protocol messages
- Perform user enumeration
- Downgrade from hybrid PQ to classical-only
- Exploit timing side-channels in MAC verification or key comparison
