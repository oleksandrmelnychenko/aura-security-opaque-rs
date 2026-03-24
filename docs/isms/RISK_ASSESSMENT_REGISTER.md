# Risk Assessment Register

**Document ID:** ISMS-RISK-001
**Version:** 1.0
**Last Reviewed:** 2026-03-04
**Classification:** Public

## Risk Scoring

**Likelihood:** 1 (Rare) — 5 (Almost Certain)
**Impact:** 1 (Negligible) — 5 (Critical)
**Risk = Likelihood x Impact**

| Level | Score | Action |
|-------|-------|--------|
| Low | 1–6 | Accept and monitor |
| Medium | 7–12 | Mitigate within release cycle |
| High | 13–19 | Mitigate before next release |
| Critical | 20–25 | Immediate action required |

## Risk Register

### R-001: Quantum Threat to Classical DH

| Field | Value |
|-------|-------|
| **Category** | Cryptographic |
| **Description** | A cryptographically relevant quantum computer breaks Ristretto255 ECDH, compromising session keys. |
| **Likelihood** | 2 |
| **Impact** | 5 |
| **Risk Score** | 10 (Medium) |
| **Mitigation** | Hybrid 4DH + ML-KEM-768 key exchange with AND-model combiner. Classical key material alone is insufficient to derive session keys; both KEM and DH must be broken simultaneously. |
| **Residual Risk** | Low |
| **Owner** | Maintainer |

### R-002: Side-Channel Timing Attack

| Field | Value |
|-------|-------|
| **Category** | Implementation |
| **Description** | Variable-time operations on secrets leak key material via timing measurements. |
| **Likelihood** | 3 |
| **Impact** | 5 |
| **Risk Score** | 15 (High) |
| **Mitigation** | All secret-dependent operations use `subtle` crate for constant-time comparisons. Credential records are strictly validated and rejected on parse/format errors. Scalar validation rejects non-canonical encodings in constant time. |
| **Residual Risk** | Low |
| **Owner** | Maintainer |

### R-003: Offline Dictionary Attack on Passwords

| Field | Value |
|-------|-------|
| **Category** | Cryptographic |
| **Description** | Attacker obtains server records and attempts offline brute-force of user passwords. |
| **Likelihood** | 3 |
| **Impact** | 5 |
| **Risk Score** | 15 (High) |
| **Mitigation** | Registration records are not password-equivalent by themselves, and Argon2id raises per-guess cost. Offline resistance holds for database compromise **without** `oprf_seed` compromise. |
| **Residual Risk** | Medium. Compromise of `oprf_seed` turns stolen registration records into an offline-verifiable target. |
| **Owner** | Maintainer |

### R-004: Dependency Supply-Chain Compromise

| Field | Value |
|-------|-------|
| **Category** | Supply Chain |
| **Description** | A compromised upstream crate introduces a vulnerability or backdoor. |
| **Likelihood** | 2 |
| **Impact** | 5 |
| **Risk Score** | 10 (Medium) |
| **Mitigation** | Pure Rust with no C dependencies. `Cargo.lock` pins exact versions. Blocking `cargo audit`, blocking `cargo-deny`, pinned Rust toolchain, and Dependabot coverage for Cargo + GitHub Actions. |
| **Residual Risk** | Low |
| **Owner** | Maintainer |

### R-005: Memory Disclosure of Key Material

| Field | Value |
|-------|-------|
| **Category** | Implementation |
| **Description** | Sensitive key material remains in memory after use, accessible via core dumps or memory forensics. |
| **Likelihood** | 2 |
| **Impact** | 4 |
| **Risk Score** | 8 (Medium) |
| **Mitigation** | All secret types implement `Zeroize` and `ZeroizeOnDrop`. Ephemeral keys are destroyed immediately after protocol completion. The FFI layer catches panics and zeroizes owned handles on drop. |
| **Residual Risk** | Low |
| **Owner** | Maintainer |

### R-006: Protocol State Confusion

| Field | Value |
|-------|-------|
| **Category** | Protocol |
| **Description** | Attacker replays or reorders protocol messages to cause state machine confusion. |
| **Likelihood** | 2 |
| **Impact** | 4 |
| **Risk Score** | 8 (Medium) |
| **Mitigation** | Strict state machine with phase tracking (`InitiatorPhase`, `ResponderPhase`). State expiry after `STATE_MAX_LIFETIME_SECS`. Wire protocol versioning rejects mismatched versions. Regression tests cover failed-KE3 terminal state reuse. |
| **Residual Risk** | Low |
| **Owner** | Maintainer |

### R-007: FFI Misuse by Integrators

| Field | Value |
|-------|-------|
| **Category** | Integration |
| **Description** | Callers of the C FFI pass invalid pointers, wrong buffer sizes, or call functions out of order. |
| **Likelihood** | 3 |
| **Impact** | 3 |
| **Risk Score** | 9 (Medium) |
| **Mitigation** | All FFI functions validate inputs (null checks, length checks). `panic::catch_unwind` wraps every FFI entry point. Busy guards prevent concurrent access. Documented API contracts in `FFI_AGENT_API.md` and `FFI_RELAY_API.md`. |
| **Residual Risk** | Low |
| **Owner** | Maintainer |

### R-008: CI/CD Pipeline Compromise

| Field | Value |
|-------|-------|
| **Category** | Infrastructure |
| **Description** | Attacker gains access to GitHub Actions and tampers with builds or releases. |
| **Likelihood** | 2 |
| **Impact** | 4 |
| **Risk Score** | 8 (Medium) |
| **Mitigation** | Minimal CI permissions. No secrets in workflow logs. Branch protection rules on `main`. Artifact checksum generation and build attestation are part of the release pipeline. |
| **Residual Risk** | Low |
| **Owner** | Maintainer |

## Review Schedule

This register is reviewed:

- At least annually
- After any security incident
- When new features or dependencies are added
- When the threat landscape changes materially (e.g., quantum computing milestones)
