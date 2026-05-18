# Artifact Guide

This guide is meant for reviewers, judges, and collaborators who want to
understand what evidence supports which claim in the Hybrid PQ-OPAQUE
work package.

## What This Repository Contains

The repository combines four layers of evidence:

1. Rust implementation in `rust/crates/`
2. Symbolic models in `formal/`
3. Benchmarks and regression suites in `rust/`
4. Scientific narrative in `docs/main_jisa.tex`

The project should therefore be evaluated as an artifact-backed
applied-cryptography submission, not as a paper-only proposal.

`docs/main_jisa.tex` is the canonical English JISA-oriented manuscript.
Older manuscript drafts have been removed from the repository so reviewers
do not encounter stale metrics or earlier phrasing.

## Claim-to-Evidence Map

| Claim | Primary evidence | Secondary evidence |
|------|------------------|--------------------|
| Session-key secrecy | ProVerif + Tamarin logs | Rust security tests |
| Password secrecy on the wire | ProVerif + Rust tests | Wire-format docs |
| Mutual authentication | ProVerif auth model + Rust tests | Relay/agent integration tests |
| Hybrid AND-model contribution | Tamarin surrogate model | Rust combiner tests |
| Fail-closed protocol behaviour | Rust regression tests | FFI/API docs |
| Wire-level exactness | `docs/WIRE_PROTOCOL_VERSIONING.md` | `protocol_tests.rs` |
| Operational trust boundary | `README.md`, `docs/PRODUCTION_READINESS.md` | Regression test covering `oprf_seed` boundary |
| Performance claims | Criterion benchmark suites | Benchmark reports and paper tables |

## Five-Minute Review Path

If you only have a few minutes, follow this path:

1. Read `README.md`
2. Read `docs/main_jisa.tex`
3. Run `cargo test --workspace`
4. Inspect `formal/logs/FULL_VERIFICATION_REPORT.md`
5. Inspect `docs/WIRE_PROTOCOL_VERSIONING.md`

That path is usually enough to verify that the project has real code,
real tests, formal artifacts, and a scoped security story.

## Reproducing the Core Results

### 1. Rust tests

```bash
cd rust
cargo test --workspace
```

Expected result:

- workspace tests pass
- one slow boundary regression may remain intentionally ignored

### 2. Security regression boundary

```bash
cd rust
cargo test -p opaque-agent --test security_regressions
```

This suite is the fastest way to inspect known failure classes at the
agent/relay boundary.

### 3. Benchmarks

```bash
cd rust
cargo bench --workspace
```

This produces three benchmark families:

- micro-benchmarks for primitives
- protocol-benchmarks for registration/authentication phases
- throughput-benchmarks for relay hot paths

### 4. Formal models

```bash
cd formal
proverif hybrid_pq_opaque.pv
proverif hybrid_pq_opaque_auth.pv
./run-tamarin.sh
```

For many reviewers, the archived reports in `formal/logs/` are a practical
starting point because they explain the boundary between the verified
surrogate model and the shipped implementation.

## Important Scope Notes

These points matter for fair evaluation:

- Symbolic models are evidence about the protocol design, not a
  machine-checked proof of the Rust implementation.
- Offline dictionary resistance is scoped to database compromise
  **without** compromise of `oprf_seed`.
- Throughput figures must be read carefully:
  `finish_only` is not the same as full authentication throughput.
- Wire sizes in the paper are reported at the versioned wire level, not
  only as payload sizes.

## Files Worth Inspecting

| File | Why it matters |
|------|----------------|
| `docs/main_jisa.tex` | English JISA-oriented manuscript |
| `README.md` | High-level security and artifact overview |
| `docs/WIRE_PROTOCOL_VERSIONING.md` | Exact wire-message contract |
| `docs/PRODUCTION_READINESS.md` | Operational deployment boundary |
| `formal/README.md` | Symbolic-model orientation |
| `formal/logs/FULL_VERIFICATION_REPORT.md` | Concise summary of formal evidence |
| `rust/crates/opaque-agent/tests/security_regressions.rs` | Boundary-condition security tests |
| `rust/crates/opaque-core/benches/` | Reproducible performance evidence |
