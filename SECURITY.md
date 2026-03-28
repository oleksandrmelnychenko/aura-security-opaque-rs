# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues.**

Report them via email to: **security@ecliptix.com**

You should receive a response within 48 hours.

### What to Include

- Type of issue (cryptographic weakness, authentication bypass, information disclosure)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Vulnerability Confirmation**: Within 7 days
- **Patch Development**: Varies based on complexity
- **Security Advisory**: Published with fix release

### Disclosure Policy

- Coordinated disclosure
- Credit to reporters in security advisories (unless you prefer to remain anonymous)
- Reasonable time to address the issue before public disclosure

## Security Measures

### Cryptographic Implementation (pure Rust, no C dependencies)

- **Ristretto255** elliptic curve operations via `curve25519-dalek`
- **ML-KEM-768** post-quantum key encapsulation (FIPS 203) via `ml-kem`
- **Argon2id** key stretching via `argon2`
- **HMAC-SHA512** message authentication via `hmac` + `sha2`
- **XSalsa20-Poly1305** authenticated encryption via `crypto_secretbox`
- **Constant-time comparison** via `subtle`

### Memory Security

- Zeroization of sensitive data via `zeroize` crate
- No heap allocation of raw secrets
- Ephemeral keys destroyed immediately after use
- Focused regression coverage for protocol edge cases in `rust/crates/opaque-agent/tests/security_regressions.rs`

### Build Security

- Release profile: LTO enabled, single codegen unit, symbols stripped
- `cargo audit` in CI for known vulnerabilities
- `cargo clippy` with `-D warnings` enforced

## Production Deployment

1. **Always use TLS** for transport layer security
2. **Implement rate limiting** at the application layer
3. **Secure storage** for relay private keys and registration records
4. **Protect `oprf_seed` like a master secret**; DB-only compromise and `oprf_seed` compromise have different consequences
5. **Regular updates** via `cargo audit`

## Formal Verification

Symbolic models in `formal/` provide protocol evidence, but they are not an exact proof of the shipping Rust/FFI implementation. See `formal/logs/` and `docs/security-review/THREAT_MODEL.md` for the exact boundary.

## References

- [OPAQUE Draft Specification](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/)
- [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
