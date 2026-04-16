# Threat Model

**Document ID:** SEC-TM-001
**Version:** 1.0
**Last Reviewed:** 2026-03-04
**Classification:** Public

## 1. System Overview

Aura OPAQUE is a hybrid post-quantum password-authenticated key exchange (PAKE) library combining 4DH Ristretto255 with ML-KEM-768. The system has two roles:

- **Agent (Initiator)**: The client that holds the user's password.
- **Relay (Responder)**: The server that holds registration records and a long-term keypair.

Communication is assumed to occur over an authenticated and encrypted transport (TLS).

```
Agent                         Relay
  |                             |
  |--- Registration Request --->|
  |<-- Registration Response ---|
  |--- Registration Record ---->|  (stored)
  |                             |
  |--- KE1 (credential req) -->|
  |<-- KE2 (credential resp) --|
  |--- KE3 (confirmation) ---->|
  |                             |
  [session key + master key]    [session key + master key]
```

## 2. Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Agent ↔ Network | Untrusted channel; assumed protected by TLS |
| Network ↔ Relay | Untrusted channel; assumed protected by TLS |
| Relay ↔ Storage | Registration records at rest; integrator's responsibility |
| Relay secret material | `oprf_seed` and relay long-term private key are production-critical secrets; compromise changes the security story materially |
| FFI ↔ Host Application | C ABI boundary; validated by input checks and panic guards |

## 3. Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| **Passive Network Adversary** | Observe all traffic | Recover passwords or session keys |
| **Active Network Adversary (MITM)** | Intercept, modify, replay messages | Impersonate agent or relay, recover secrets |
| **Compromised Relay** | Access to records, long-term keys, or `oprf_seed` | Recover user passwords from registration records or impersonate the relay |
| **Quantum Adversary** | Future CRQC with Shor's algorithm | Break classical DH, recover recorded session keys |
| **Local Attacker** | Access to process memory or core dumps | Extract key material from RAM |

## 4. Threats and Mitigations

### T-001: Password Recovery from Network Traffic

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **Actor** | Passive/Active Network Adversary |
| **Attack** | Capture protocol messages and attempt to extract the password. |
| **Mitigation** | OPAQUE ensures the password never leaves the agent in any form. The OPRF blinds the password with a random scalar before transmission. |
| **Verification** | Password secrecy verified by Tamarin and ProVerif. |

### T-002: Offline Dictionary Attack

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **Actor** | Database attacker or relay attacker |
| **Attack** | Extract registration records and brute-force passwords offline. |
| **Mitigation** | If an attacker steals only the registration database, guesses still require the per-account OPRF key derived from `oprf_seed`, and Argon2id adds substantial per-guess cost. |
| **Residual Risk** | If `oprf_seed` is compromised, offline dictionary attacks become feasible against stolen registration records. This is an explicit trust-boundary limitation and is covered by a regression test. |
| **Verification** | Symbolic models support the DB-only compromise story. Rust regression tests cover both the protected case and the `oprf_seed` compromise boundary. |

### T-003: Session Key Compromise via Classical Cryptanalysis

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **Actor** | Quantum Adversary (future) |
| **Attack** | Use Shor's algorithm to break Ristretto255 DH and derive session keys from recorded transcripts. |
| **Mitigation** | Hybrid 4DH + ML-KEM-768 with AND-model combiner. Session key derivation requires breaking both the classical DH and the post-quantum KEM. ML-KEM-768 provides NIST Level 3 security against quantum attacks. |
| **Verification** | Supported by surrogate symbolic models plus Rust regression tests for the implemented combiner. |

### T-004: Man-in-the-Middle Impersonation

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing |
| **Actor** | Active Network Adversary |
| **Attack** | Intercept KE1/KE2 and substitute own ephemeral keys to establish separate sessions with agent and relay. |
| **Mitigation** | 4DH protocol binds all four DH computations (static-static, static-ephemeral, ephemeral-static, ephemeral-ephemeral) into the session key. The relay's long-term key is authenticated via the registration record. KE3 MAC confirms mutual authentication. |
| **Verification** | Supported by symbolic models and Rust tests; also depends on correct relay public-key distribution and transport authentication. |

### T-005: Replay Attack

| Field | Value |
|-------|-------|
| **STRIDE** | Spoofing |
| **Actor** | Active Network Adversary |
| **Attack** | Replay a previously captured KE1 or KE2 message. |
| **Mitigation** | Fresh ephemeral keys per session. State machine rejects reuse. State objects expire after `STATE_MAX_LIFETIME_SECS`. Wire protocol version field rejects mismatched versions. |
| **Verification** | Rust regression tests cover terminal-state behaviour; symbolic models include freshness constraints. |

### T-006: Memory Forensics / Core Dump Extraction

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **Actor** | Local Attacker |
| **Attack** | Read process memory or core dump to extract private keys or session keys. |
| **Mitigation** | `Zeroize` + `ZeroizeOnDrop` on secret types. Ephemeral keys destroyed after use. The FFI layer catches panics and zeroizes owned handles on drop. |
| **Residual Risk** | Compiler optimizations may reorder or copy memory. OS swap/hibernation may persist pages. Integrators should use `mlock` where available. |

### T-007: FFI Boundary Exploitation

| Field | Value |
|-------|-------|
| **STRIDE** | Tampering, Denial of Service |
| **Actor** | Malicious or Buggy Host Application |
| **Attack** | Pass null pointers, wrong buffer sizes, or call functions concurrently or out of order. |
| **Mitigation** | All FFI entry points: null-check all pointers, validate buffer lengths, wrap in `panic::catch_unwind`, use `AtomicBool` busy guards to prevent concurrent access. Defined error codes for all failure modes. |
| **Verification** | FFI contracts documented in `FFI_AGENT_API.md` and `FFI_RELAY_API.md`, with smoke tests for C consumers and dedicated Rust FFI regression tests. |

### T-008: Timing Side-Channel on Credential Lookup

| Field | Value |
|-------|-------|
| **STRIDE** | Information Disclosure |
| **Actor** | Active Network Adversary |
| **Attack** | Measure response time differences between valid and invalid usernames to enumerate accounts. |
| **Mitigation** | On unknown user, relay generates a fake credential using a deterministic seed and proceeds with the protocol using constant-time byte selection (`ct_select_bytes`). Response time is independent of whether the user exists. |
| **Verification** | Constant-time credential selection implemented and reviewed in security audit (18/18 findings resolved). |

## 5. Assets

| Asset | Sensitivity | Protection |
|-------|------------|------------|
| User password | Critical | Never leaves agent; OPRF-blinded before transmission |
| Session key | Critical | Derived from hybrid KEM+DH; zeroized after use |
| Master key | Critical | Derived during authentication; zeroized after extraction |
| Relay private key | Critical | Integrator-managed storage; zeroized in memory |
| Registration record | High | Server-side storage; not password-equivalent on its own, but no longer protective if `oprf_seed` is also compromised |
| Ephemeral keys | High | Per-session; zeroized immediately after protocol step |
| `oprf_seed` | Critical | Must be stored like a master secret; compromise enables offline verification of stolen records |

## 6. Assumptions

1. The transport layer (TLS) provides confidentiality and integrity for protocol messages.
2. The agent's platform provides a secure random number generator (`OsRng`).
3. The relay's long-term private key **and** `oprf_seed` are stored securely by the integrator.
4. Argon2id parameters are configured appropriately for the deployment environment.
5. The host application correctly follows the FFI API contract and state machine ordering.

## 7. Formal Verification Coverage

| Property | Threats Addressed | Tamarin | ProVerif |
|----------|------------------|---------|----------|
| Session key secrecy | T-001, T-003 | surrogate model | secrecy/auth models |
| Password secrecy on the wire | T-001 | surrogate model | secrecy model |
| Classical forward secrecy | T-003 | verified | — |
| Post-quantum forward secrecy | T-003 | verified | — |
| Mutual authentication | T-004, T-005 | surrogate model | auth-only model |
| AND-model hybrid security | T-003 | surrogate model | — |
| Offline dictionary resistance | T-002 | DB-only compromise model | not exact implementation model |

## 8. Review

This threat model is reviewed:

- At least annually
- After any security incident or protocol change
- When new features or attack vectors are identified
