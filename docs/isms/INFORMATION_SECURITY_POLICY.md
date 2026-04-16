# Information Security Policy

**Document ID:** ISMS-POL-001
**Version:** 1.0
**Last Reviewed:** 2026-03-04
**Classification:** Public

## 1. Purpose

This policy establishes the information security framework for the Aura OPAQUE cryptographic library. It defines controls to protect the confidentiality, integrity, and availability of the library and systems that depend on it.

## 2. Scope

This policy applies to:

- All source code in this repository (`opaque-core`, `opaque-agent`, `opaque-relay`, `opaque-ffi`)
- Cryptographic key material processed by the library at runtime
- Build, test, and release infrastructure (GitHub Actions CI/CD)
- Contributors, maintainers, and integrators

## 3. Roles and Responsibilities

| Role | Responsibility |
|------|---------------|
| Project Maintainer | Enforce policy, triage vulnerabilities, approve releases |
| Contributor | Follow secure coding guidelines, sign commits |
| Integrator | Deploy per production guidelines, manage key storage |
| Security Contact | Receive and respond to vulnerability reports (security@aura.com) |

## 4. Cryptographic Controls

### 4.1 Algorithm Selection

All algorithms are selected from IETF/NIST standards:

| Function | Algorithm | Standard |
|----------|-----------|----------|
| OPRF / DH | Ristretto255 (4DH) | RFC 9807 baseline OPAQUE + implementation-specific 4DH extension |
| KEM | ML-KEM-768 | FIPS 203 |
| Key Stretching | Argon2id | RFC 9106 |
| MAC | HMAC-SHA512 | RFC 2104 |
| AEAD | XSalsa20-Poly1305 | NaCl |
| Hybrid Combiner | HKDF-SHA512 (AND-model) | RFC 5869 |

### 4.2 Key Management

- Private keys are never serialized to persistent storage by the library.
- All sensitive material is zeroized on drop via the `zeroize` crate.
- Ephemeral keys are destroyed immediately after protocol completion.
- Relay long-term keys must be stored in a hardware security module (HSM) or encrypted-at-rest keystore in production.

### 4.3 Constant-Time Operations

- All secret-dependent comparisons use the `subtle` crate.
- Credential lookups use constant-time selection to prevent timing side-channels.
- Scalar and point validation rejects non-canonical encodings.

## 5. Secure Development

### 5.1 Code Quality Gates

All changes must pass before merge:

- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt --all -- --check`
- `cargo test --workspace`
- `cargo audit` (no known vulnerabilities)

### 5.2 Dependency Management

- Pure Rust — no C dependencies.
- Dependencies are pinned via `Cargo.lock`.
- `cargo audit` runs in CI on every push.
- New dependencies require maintainer review for supply-chain risk.

### 5.3 Build Hardening

Release profile settings:

- LTO: enabled (fat)
- Codegen units: 1
- Symbols: stripped
- Panic: abort

## 6. Vulnerability Management

- Vulnerabilities are reported via security@aura.com (see `SECURITY.md`).
- Initial response within 48 hours; confirmation within 7 days.
- Critical vulnerabilities are patched and released within 72 hours of confirmation.
- Security advisories are published with each fix release.

## 7. Access Control

- Repository write access requires two-factor authentication.
- Releases are tagged and signed by authorized maintainers.
- CI secrets are scoped to the minimum required permissions.

## 8. Formal Verification

Seven security properties are verified by two independent tools:

- **Tamarin Prover**: 8/8 lemmas verified
- **ProVerif**: 5/5 queries verified

Properties: session key secrecy, password secrecy, classical forward secrecy, post-quantum forward secrecy, mutual authentication, AND-model hybrid security, offline dictionary resistance.

## 9. Incident Response

1. **Detect** — CI alerts, audit reports, external disclosures
2. **Contain** — Revert or disable affected releases
3. **Eradicate** — Develop and test patch
4. **Recover** — Publish fixed release and security advisory
5. **Lessons Learned** — Update risk register and controls

## 10. Review

This policy is reviewed at least annually or after any security incident.
