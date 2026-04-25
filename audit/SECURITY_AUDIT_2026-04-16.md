# Aura Hybrid PQ-OPAQUE — Security Audit (2026-04-16)

**Scope:** Full Rust workspace (`opaque-core`, `opaque-agent`, `opaque-relay`,
`opaque-ffi`), Swift wrapper (`AuraOPAQUE`), CI workflows, supply chain.
**Methodology:** Manual source review + `cargo audit` + `cargo deny` +
`cargo clippy -D warnings` + workflow review. No runtime/dynamic analysis run.
**Prior reports:** `audit/SECURITY_AUDIT_2026-03-03.md`,
`audit/OPAQUE_SECURITY_REPORT.md`.

---

## Executive Summary

The workspace continues to demonstrate strong security engineering and builds
cleanly under `cargo clippy --all-targets -- -D warnings` against the pinned
Rust 1.93.1 toolchain. The cryptographic core (`opaque-core`, `opaque-agent`,
`opaque-relay`) enforces `#![forbid(unsafe_code)]`; all `unsafe` is confined to
`opaque-ffi`. State machines invalidate on failure, MACs use constant-time
comparison, scalars/points are zeroized, and the unknown-user fake-credential
path is constant-time-selected against registered credentials. The formal model
claims (in `formal/`) and the protocol narrative in `SECURITY.md` are
consistent with what the code actually does, modulo the documented operator
boundary on the OPRF seed.

Nothing in this audit elevates any finding above **Medium**. The findings
below are a mix of defense-in-depth and supply-chain hygiene issues. No new
**Critical** or **High** cryptographic defects were identified beyond what is
already documented in prior reports and `SECURITY.md`.

| Severity  | New | Confirmed pre-existing | Total |
|-----------|-----|------------------------|-------|
| Critical  | 0   | 0                      | 0     |
| High      | 0   | 1 (architectural)      | 1     |
| Medium    | 3   | 0                      | 3     |
| Low       | 5   | 1                      | 6     |
| Info      | 4   | —                      | 4     |

The single **High** item is the previously documented architectural risk that
this is a custom 4DH+ML-KEM combiner, not RFC 9807 / RFC 9497 OPAQUE-3DH —
re-stated here only for traceability; no new evidence.

---

## 1. Environment & Stack

- Workspace: 4 crates, pinned versions (`=x.y.z`) for all crypto dependencies.
- Toolchain: `rust-toolchain.toml` pins **Rust 1.93.1** with `clippy`, `rustfmt`.
- Lints: `clippy::correctness = deny`, `clippy::suspicious = deny`,
  `cast_possible_truncation/sign_loss = warn`. `unsafe_code` is **forbidden**
  in all production crates except `opaque-ffi`.
- Release profile: `lto = true`, `codegen-units = 1`, `strip = "symbols"`,
  `panic = "unwind"` (required for `catch_unwind` at FFI boundary),
  `overflow-checks = true` (defensive — kept on in release).
- CI: `ci.yml`, `security-scan.yml`, `miri.yml`, `sanitizers.yml`, `fuzz.yml`,
  `benchmarks.yml`, `build-and-publish.yml`.
- Dependency management: Dependabot (cargo + github-actions, weekly).
- Secret storage in repo: none found. No `.env*` present. Trufflehog scans on
  every PR with `--only-verified`.

## 2. Dependency Security

### FINDING M-01 — `cargo audit --deny warnings` currently fails CI on RUSTSEC-2026-0097

**File:** `.github/workflows/security-scan.yml:31`, indirect dep on `rand 0.8.5`
and `rand 0.9.2` (via `proptest 1.10.0`).
**Severity:** **Medium** (CI break / policy gap, not a runtime vulnerability).
**OWASP:** A06:2021 — Vulnerable and Outdated Components.

`cargo audit --deny warnings` now reports two *unsound* (not *vulnerable*)
findings for `rand 0.8.5` and `rand 0.9.2`:

```
RUSTSEC-2026-0097 — Rand is unsound with a custom logger using `rand::rng()`
```

The advisory applies to the top-level `rand::rng()` thread-local RNG path when
a custom logger is installed. This repository **does not** use `rand::rng()`;
it uses `rand::rngs::OsRng` directly (`crypto.rs:48,396`, `pq_kem.rs:25,59`)
and `rand_core::RngCore` via the KEM crate. The runtime risk is therefore
negligible. However, CI will now fail on every push with `--deny warnings`
because the advisory lands at warning severity.

**Remediation options:**

1. **Preferred:** bump to a `rand` version that excludes the unsound path once
   available, or wait for `proptest` to pick up a patched release.
2. **Acceptable short-term:** ignore the specific advisory in `rust/deny.toml`
   (`[advisories] ignore = ["RUSTSEC-2026-0097"]`) with a one-line comment
   citing that the project does not use `rand::rng()`. Remove the ignore
   entry after the upstream fix lands.
3. Do **not** silently drop `--deny warnings` — that removes all future
   advisory coverage.

### POSITIVE observations

- `rust/deny.toml` enforces `yanked = "deny"`, allow-list licenses,
  `unknown-registry = "deny"`, `unknown-git = "deny"`, `wildcards = "deny"`.
- All cryptographic primitive crates pinned to exact versions (`=`).
- `ml-kem` built with the `zeroize` feature.
- `Cargo.lock` is committed and `cargo build --locked` is used across CI.

## 3. Secrets / Hardcoded Credentials

### POSITIVE

- No `.env`, private key, AWS key, JWT, GitHub token, or other secret patterns
  found in the tree (Grep across `*.{rs,swift,yml,yaml,toml,sh,ps1,json}` for
  the usual signatures).
- All `password`/`secret` occurrences are cryptographic parameter names or
  label bytes (e.g., `labels::OPRF_SEED_INFO`), not stored credentials.
- `trufflehog` runs on every PR (`security-scan.yml:54`).
- Release workflow uses only `${{ secrets.GITHUB_TOKEN }}`.

## 4. Authentication & State Machine

The agent and relay maintain explicit `InitiatorPhase` / `ResponderPhase`
state machines that enforce correct ordering and terminal-state reuse
rejection. Key properties verified by reading the code:

- **KE1 → KE3 phase gating** (`agent/authentication.rs:88`,
  `relay/authentication.rs:98,252`): each step requires the prior phase and
  rejects with `ValidationError` otherwise.
- **State expiry** (`state.rs:72-83`, `STATE_MAX_LIFETIME_SECS = 300`):
  expired states are zeroized and transitioned to `Finished`.
- **On any crypto failure**, `state.invalidate()` is called
  (`agent/authentication.rs:255-258`, `relay/authentication.rs:265-287`).
- **KE3 retry after failed MAC**: the responder transitions to `Finished` on
  MAC mismatch (`relay/authentication.rs:278-288`) and cannot be reused; a
  dedicated regression test (`security_regressions.rs:267`) enforces this.
- **Registration-response MITM**: client compares `responder_public_key`
  constant-time against the pinned key
  (`agent/registration.rs:73-76`).
- **Identity point rejection**: `decode_non_identity_point`
  (`crypto.rs:28-41`) rejects all-zero compressed points *and* the identity
  point; regression test `regression_identity_point_injection_is_rejected`.
- **Account binding**: `ACCOUNT_CONTEXT_BINDING` (v2 label,
  `types.rs:120`) is hashed into both transcripts
  (`agent/authentication.rs:44-48`, `relay/authentication.rs:117-121`),
  preventing transcript reuse across accounts on the same server.
- **Unknown user / account enumeration**: responder derives a deterministic
  fake envelope from `(oprf_seed, account_id)` via a constant-time select
  (`relay/authentication.rs:63-77`). Both real and fake paths execute the
  same operations and produce a syntactically valid KE2; the client then
  fails envelope opening, yielding a `-5` at the same code point.

### FINDING L-01 — Request creation path does not invalidate state on downstream errors

**File:** `rust/crates/opaque-ffi/src/agent_ffi.rs:432-440`
**Severity:** **Low**.

`opaque_agent_create_registration_request` mutates `state` via
`create_registration_request` and **only then** attempts
`protocol::write_registration_request` into the caller's output buffer. If the
write fails (e.g. caller-supplied short buffer — already guarded earlier, but
any future addition would affect this) the state is zeroized via
`invalidate_agent_state`. Good. However, if `create_registration_request`
itself returns `Err` after partially mutating state (it doesn't today, but the
library function writes into `state.initiator_private_key`,
`state.secure_key`, `state.oblivious_prf_blind_scalar` before any fallible
call), the FFI wrapper does **not** call `invalidate_agent_state`. The library
relies on `state.phase != Created` failure gating any future step. Consider
invalidating on any non-success return to reduce residual state risk.

### POSITIVE

- `security_proptest.rs` and `security_properties.rs` between them cover >40
  properties including forward secrecy (classical LTK compromise, full
  LTK+DH compromise), hybrid AND-model (DH-only and KEM-only breaks must both
  be insufficient), per-byte tampering detection on KE2/KE3, and
  dictionary-attack resistance on envelopes without the password.

## 5. Input Validation

All public FFI entry points validate:

- Non-null pointers for every buffer.
- Exact-length equality for wire messages (`!= KE1_LENGTH`, `!= KE2_LENGTH`,
  `!= KE3_LENGTH`, `!= REGISTRATION_REQUEST_WIRE_LENGTH`,
  `!= REGISTRATION_RESPONSE_WIRE_LENGTH`, `!= REGISTRATION_RECORD_LENGTH`).
- Ranges for variable-length inputs (`1..=MAX_SECURE_KEY_LENGTH`,
  `1..=MAX_ACCOUNT_ID_LENGTH`).
- Version byte via `check_version` in every parser
  (`protocol.rs:45-53`); unknown versions collapse to `-10` at the FFI.

Static assertions in `types.rs:86-100` enforce wire-size invariants at
compile time.

### POSITIVE

- Parser fuzzers (`rust/fuzz/fuzz_targets/{parse_ke1,parse_ke2,parse_registration_record,ffi_lengths}.rs`)
  run for 15s each on every PR. Consider lengthening the schedule (see I-01).

## 6. Data Protection & Zeroization

- All state structs implement `ZeroizeOnDrop`
  (`agent/state.rs:31,160,179,201,229,248`, `relay/state.rs:26,132,173,192,223`).
- `opaque-core` crypto paths wrap sensitive intermediates in
  `Zeroizing::new([...])` (see `agent/authentication.rs:116,126,141-143,
  164-168,183,189,195,213,219,222,225,228,231,238`).
- `Hmac` output bytes are zeroized post-comparison (`crypto.rs:176`).
- XSalsa20-Poly1305 decryption releases plaintext and internal buffers via
  explicit `zeroize()` on heap `Vec`s (`crypto.rs:381,388`). The aead
  crate's internal temporaries during `cipher.encrypt/decrypt` are NOT
  explicitly zeroized — acceptable since the envelope plaintext is derived
  from the password via KSF and re-sealed with fresh nonce each registration;
  worst case a temporary heap copy survives the function frame until dropped.
- `SecureBytes::resize` shrinks via `zeroize` before resize (`types.rs:243-248`).

### FINDING L-02 — Swift-side key material lives briefly in unlocked heap memory

**File:** `swift/Sources/AuraOPAQUE/OpaqueAgent.swift:274-297`
**Severity:** **Low**.

`finish(state:)` allocates `sessionKey`/`masterKey` as plain
`Data(count: ...)` (heap, not `mlock`ed), calls the FFI which writes the key
material, and only wraps them in the `AuthenticationKeys` type
(which `mlock`s them post-facto in its initializer). Between allocation and
`mlock`, and before the `defer { secureZeroData(...) }` fires on the local
`Data`, the key material is eligible for paging. Copy-on-write semantics
mean `secureZeroData(&sessionKey)` in the `defer` zeroes only the *local*
CoW copy after `AuthenticationKeys` already holds its own reference to the
original buffer — this is the documented behaviour but worth explicit
comment.

**Remediation:**
- Allocate `Data` of the correct size, `mlock` it **before** the FFI call,
  and pass it directly to `AuthenticationKeys`.
- Add a code comment explaining the CoW semantics so reviewers understand
  why the local `secureZeroData` is the right thing even though it looks
  like it would also zero the `AuthenticationKeys` copy.

## 7. FFI Boundary

All `extern "C"` functions are marked `unsafe`, carry a
`# Safety` doc-comment, wrap the body in
`panic::catch_unwind(AssertUnwindSafe(...))`, and return `FFI_PANIC = -99`
on panic (preventing UB from unwind across the C boundary — required because
`panic = "unwind"` is retained in release).

### FINDING M-02 — `'static` references synthesised from FFI handles rely on caller discipline

**Files:** `rust/crates/opaque-ffi/src/agent_ffi.rs:156-182`,
`rust/crates/opaque-ffi/src/relay_ffi.rs:157-204`.
**Severity:** **Medium** (soundness hazard under caller misuse, not currently
exploitable from the Swift wrapper which serialises access via `NSLock`).

`acquire_agent`, `acquire_agent_state`, `acquire_relay`,
`acquire_relay_state`, `acquire_relay_keypair` all do roughly:

```rust
let ptr = handle as *mut AgentHandle;
let in_use = unsafe { &(*ptr).in_use };
if in_use.swap(true, Ordering::Acquire) { return None; }
Some((unsafe { &*ptr }, guard))
```

The returned reference is extended to `'static`. This is sound **only if**
the caller guarantees the handle is valid for the lifetime of the call
(standard FFI contract, explicitly stated in the `# Safety` sections). But:

1. The `in_use` dereference happens **before** the atomic swap. A concurrent
   `opaque_*_try_destroy` that wins the `swap` first would free the box while
   this load races. The atomic ordering prevents the successful-swap case
   from reading freed memory, but the losing caller still dereferenced `ptr`
   once to take `&in_use` before even knowing the handle is theirs. If the
   handle was *already* freed out-of-band by a buggy caller, this load is UB.
2. Returning `&'static (mut) T` from a pointer whose real lifetime is
   bounded by the Box invites future accidental escape. Miri in the current
   `miri.yml` job only runs `cargo miri test -p opaque-{core,agent,relay}
   --lib` and therefore does **not** exercise these FFI acquire paths under
   Stacked Borrows.

**Remediation:**

- Tighten the returned reference lifetime to `'a` bounded by a temporary
  `PhantomData<&'a ()>` held in the `BusyGuard`; this is mostly mechanical
  and removes the `'static` fib.
- Add a Miri run over `opaque-ffi` tests (even if it's slow). The public
  `tests/ffi_roundtrip.rs` and `tests/ffi_error_lifecycle.rs` already cover
  the acquire paths.
- Document in the `# Safety` section that concurrent destroy+use on the
  same handle is UB (already implicit, make it explicit).

### FINDING L-03 — `opaque_agent_finish` does not mark phase `Finished` before returning

**File:** `rust/crates/opaque-agent/src/authentication.rs:262-290`
**Severity:** **Low**.

`initiator_finish` sets `state.phase = InitiatorPhase::Finished` only on the
success path (line 288). If `is_all_zero(&state.session_key)` fires (line
270) the state stays in `Ke3Generated` with partially zeroized material,
which the FFI layer then gates on `sh.ke3_exported`. In practice the FFI
busy flag and `ke3_exported` prevent reuse, but defensively the library
should also invalidate on the `InvalidInput` branch.

### POSITIVE

- `response_length != REGISTRATION_RESPONSE_WIRE_LENGTH` and similar use
  strict **equality** for fixed-length wire messages, not `>=` / `<`.
- `ke3_exported` flag is cleared on failure
  (`agent_ffi.rs:686-689`) and after key extraction (`agent_ffi.rs:769`).
- `BusyGuard::drop` releases the in-use flag on every return path, including
  panic unwind inside `catch_unwind`.

## 8. Cryptographic Review (delta on prior audits)

- Argon2id parameters `m=262144 KiB, t=3, p=1, out=64` are at/above current
  OWASP / RFC 9807 recommendations; deliberate and documented.
- All scalar/point temporaries in `crypto.rs` are explicitly zeroized after
  use (confirms resolution of prior M-01).
- `decode_non_identity_point` guards **all** point decompression paths.
- `InMemoryEvaluator::new` refuses all-zero OPRF seeds (`oprf.rs:111-117`).
- `key_derivation_expand` bounds `N <= 255` per RFC 5869 and early-errors on
  oversized requests (`crypto.rs:200-205`).
- `verify_hmac` uses `ct_eq` (`crypto.rs:175`); `ct_select_bytes`
  (`types.rs:330-337`) uses `ConditionallySelectable`.

No new cryptographic defects identified.

## 9. Logging & Error Handling

### POSITIVE

- No `log::*`, `tracing::*`, `println!`, or `eprintln!` calls in production
  crates (`opaque-core`, `opaque-agent`, `opaque-relay`, `opaque-ffi`). Error
  paths return `OpaqueError` enums that are mapped to a small set of FFI
  codes; most protocol/authentication errors collapse to `-5` to reduce
  stage-fingerprinting signals — documented on `OpaqueError::to_c_int`
  (`types.rs:186-210`).
- `SecureBytes::Debug` redacts content (`types.rs:276-280`).

### FINDING L-04 — Error code `-101` (`FFI_CORRUPTED_RECORD`) has a unique value distinct from `-5`

**File:** `rust/crates/opaque-ffi/src/relay_ffi.rs:749,754`
**Severity:** **Low** (minor information leak, current behaviour is intentional
and scoped to the server — not exposed to a remote attacker).

`opaque_relay_generate_ke2` returns `-101` when a non-null credentials buffer
fails to parse, rather than collapsing into `-5`. This differentiates between
"bad credentials blob from DB" and "authentication failed" at the server
FFI. Because this code is only observable by the relay operator (and never
echoed to the remote client in raw form), it is informational for the
operator and not an enumeration oracle on the wire. Still worth an explicit
comment that callers **must not** forward raw FFI codes to remote peers.

## 10. Supply Chain / CI

### FINDING M-03 — Third-party GitHub Actions are not pinned to commit SHAs

**Files:** all `.github/workflows/*.yml`.
**Severity:** **Medium**.

Every workflow references actions by tag (`@v2`, `@v4`, `@stable`, `@master`,
`@v3.88.16`). Tags are mutable. For a project whose artifacts are binary
cryptographic libraries shipped to mobile clients, this is below the bar set
by SLSA L3 and GitHub's own hardening guide.

Particularly risky:

- `dtolnay/rust-toolchain@master` (used in every workflow).
- `dtolnay/rust-toolchain@stable` in `build-and-publish.yml:93`.
- `swift-actions/setup-swift@v2`.

**Remediation:**

- Pin every third-party action to a 40-char commit SHA with a
  `# v1.2.3` comment. Dependabot supports SHA pins and will keep them current.
- First-party actions (`actions/checkout`, `actions/upload-artifact`,
  `actions/download-artifact`, `actions/attest-build-provenance`) are a
  judgement call — pinning to SHA is safer but not mandatory.

### FINDING L-05 — Build-and-publish grants `contents: write` to every job in the workflow

**File:** `.github/workflows/build-and-publish.yml:13-17`.
**Severity:** **Low**.

Workflow-level permissions are:

```yaml
permissions:
  contents: write
  packages: write
  id-token: write
  attestations: write
```

Only the `publish-release` job needs `contents: write` (to create the GitHub
release). The three build jobs only need `contents: read` plus
`id-token: write` + `attestations: write` for provenance.

**Remediation:** set workflow-level to the intersection (`contents: read`,
`id-token: write`, `attestations: write`) and override per-job for the
release step.

### FINDING I-01 — Only Apple XCFramework has build provenance; native Linux/Windows libraries do not

**File:** `.github/workflows/build-and-publish.yml:181-184`.
**Severity:** **Info** (policy, not a vulnerability).

`actions/attest-build-provenance` is only applied to
`AuraOPAQUE.xcframework.zip`. Server-native and portable Linux/Windows
artifacts are uploaded to the release without attestation. Consumers of
those binaries have no way to verify provenance.

**Remediation:** attest every release artifact (`dylib`, `so`, `dll`,
static libs). Consider sigstore cosign signatures on top, especially for
the server-native profile.

### FINDING I-02 — Fuzz smoke budget is 15 seconds per target

**File:** `.github/workflows/fuzz.yml:19-27`.
**Severity:** **Info**.

`cargo fuzz run ... -- -max_total_time=15` per target is a smoke test, not
a corpus-growing run. Consider a weekly scheduled `fuzz.yml` variant with
`-max_total_time=1800` or longer on `parse_ke1`, `parse_ke2`, `ffi_lengths`
targets, and persist the discovered corpus back to a branch (as many
crypto projects do).

### FINDING I-03 — `miri.yml` does not exercise `opaque-ffi`

**File:** `.github/workflows/miri.yml:20-29`.
**Severity:** **Info**.

Miri runs only `opaque-core`, `opaque-agent`, `opaque-relay` — the three
`#![forbid(unsafe_code)]` crates. The one crate that *contains* unsafe code
(`opaque-ffi`) is not covered. Miri is expensive but the `ffi_roundtrip.rs`
and `ffi_error_lifecycle.rs` tests together run in seconds under normal
cargo; scaled 20–100× under Miri that's still minutes. Running Miri against
the FFI boundary would catch aliasing and provenance bugs in the acquire
paths flagged in FINDING M-02.

### FINDING I-04 — `build-native-server` uses `dtolnay/rust-toolchain@stable` instead of pinned 1.93.1

**File:** `.github/workflows/build-and-publish.yml:93-95`.
**Severity:** **Info**.

The portable build jobs (client-facing artifacts) pin `1.93.1`. The
`build-native-server` job uses floating `stable`. For reproducible server
builds, align to the same pinned toolchain.

## 11. Infrastructure / Headers

- `rust-toolchain.toml` pins the compiler — reproducibility is baseline.
- Public C headers are curated in `rust/include/` and copied verbatim into
  the XCFramework; the module map imports the umbrella header.
  `ffi-smoke` job validates header presence + umbrella on every push.
- No network service in repo; no cookies / CORS / CSP apply.

## 12. Headers, CORS, CSP

Not applicable — this is a cryptographic library, not a web service.

## 13. POSITIVE Observations (highlights)

- `#![forbid(unsafe_code)]` in every production crate except `opaque-ffi`.
- All `unsafe extern "C"` entry points wrapped in `catch_unwind`.
- Constant-time comparison (`subtle`) used consistently; `ct_select_bytes`
  implements the registered/unregistered branch uniformly.
- OPRF fake-credentials derived deterministically from
  `(oprf_seed, account_id)` so enumeration via KE2 shape or timing is
  mitigated; dedicated regression test exists.
- Static `const _: () = assert!(...)` block in `types.rs` locks wire sizes
  at compile time; any accidental protocol change triggers a build failure.
- `SECURITY.md` documents the responsible-disclosure contact and the
  precise operator boundary on the `oprf_seed`.
- Thorough test suite: `155 passed; 1 ignored` in workspace, with
  >40 security-oriented properties.
- `trufflehog`, `cargo-audit`, `cargo-deny`, `cargo-fuzz`, Miri, ASan all
  wired into CI.

---

## Prioritised Remediation Plan

| ID    | Severity | Effort | Action |
|-------|----------|--------|--------|
| M-01  | Medium   | 1 h    | Ignore RUSTSEC-2026-0097 in `deny.toml` with a comment, or upgrade when patched; un-break CI. |
| M-02  | Medium   | 4–8 h  | Replace `'static` references in `opaque-ffi` acquire paths with `'a`-bounded references; add Miri coverage. |
| M-03  | Medium   | 4 h    | Pin every third-party GitHub Action to a commit SHA; let Dependabot keep them current. |
| L-01  | Low      | 1 h    | Invalidate initiator state on *any* `create_registration_request` error path in FFI. |
| L-02  | Low      | 2 h    | Swift: `mlock` key buffers before the FFI call; document CoW semantics. |
| L-03  | Low      | 30 min | `initiator_finish`: invalidate state on the `is_all_zero(session_key)` branch. |
| L-04  | Low      | 15 min | Comment on `FFI_CORRUPTED_RECORD`: "operator-only; must not be forwarded raw". |
| L-05  | Low      | 30 min | Drop workflow-level `contents: write`; grant only in `publish-release`. |
| I-01  | Info     | 2 h    | Add scheduled long-form fuzz run (30 min+); persist corpus. |
| I-02  | Info     | 1 h    | Attest Linux/Windows release artifacts with `attest-build-provenance`. |
| I-03  | Info     | 1 h    | Extend `miri.yml` to cover `opaque-ffi` `--tests`. |
| I-04  | Info     | 5 min  | Pin `build-native-server` to `1.93.1` for reproducibility. |

---

## Reproduction Commands

```bash
# Environment
cargo --version                      # 1.93.1 (via rust-toolchain.toml)
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Dependency & licence scans
cargo audit                          # observe 2 unsound warnings on rand
cargo audit --deny warnings          # fails — confirms FINDING M-01
cargo deny --manifest-path rust/Cargo.toml check

# Secret scan
# (trufflehog runs in CI; locally: brew install trufflehog; trufflehog git --no-update .)
```

---

_Auditor_: Claude Opus 4.7 (1M context), 2026-04-16
_Commit under review_: `codex/final-paper-polish` @ HEAD
_Prior audit_: `audit/SECURITY_AUDIT_2026-03-03.md`
