# Formal Evidence for Hybrid PQ-OPAQUE

This directory contains the symbolic verification artifacts for
Hybrid PQ-OPAQUE.

These artifacts should be read as **protocol-level evidence**, not as a
line-by-line proof of the shipped Rust implementation.

## What Is Here

| File | Tool | Purpose |
|------|------|---------|
| `hybrid_pq_opaque.spthy` | Tamarin | Full 4DH-oriented model used as a reference point |
| `hybrid_pq_opaque_ascii.spthy` | Tamarin | ASCII-friendly copy of the full model |
| `hybrid_pq_opaque_verified.spthy` | Tamarin | Verified surrogate 4DH model used for archived proofs |
| `hybrid_pq_opaque.pv` | ProVerif | Secrecy-oriented model |
| `hybrid_pq_opaque_auth.pv` | ProVerif | Authentication-oriented model |
| `logs/` | Reports | Archived verification outputs and interpretation notes |

## Verification Boundary

The formal package is intentionally split.

- The ProVerif models split secrecy and authentication into separate
  files for tractability and clarity.
- The Tamarin proof that actually archives cleanly is the
  surrogate/abstract 4DH model in `hybrid_pq_opaque_verified.spthy`.
- The larger full Tamarin model is useful as a design reference, but it
  should not be confused with the model that produces the archived proof
  bundle.

This split is a feature, not a bug: it makes the proof boundary explicit
instead of hiding it behind a single overclaimed “full verification”
label.

## Properties Supported

The current model set supports evidence for:

- session-key secrecy
- password secrecy on the wire
- mutual authentication / correspondence
- classical forward secrecy
- hybrid AND-model reasoning
- scoped offline dictionary resistance

## Critical Scope Note

Offline dictionary resistance is interpreted only for the case of
database compromise **without** compromise of the global `oprf_seed`.

That trust boundary is part of the protocol story and must not be erased
when citing the formal results.

## How To Inspect Quickly

For most reviewers, the recommended order is:

1. Read `logs/FULL_VERIFICATION_REPORT.md`
2. Read `logs/TAMARIN_VERIFICATION_REPORT.md`
3. Inspect `hybrid_pq_opaque_verified.spthy`
4. Inspect `hybrid_pq_opaque.pv` and `hybrid_pq_opaque_auth.pv`

## How To Run

### ProVerif

```bash
proverif hybrid_pq_opaque.pv
proverif hybrid_pq_opaque_auth.pv
```

### Tamarin

```bash
./run-tamarin.sh
./run-tamarin.sh --lemma=protocol_completion
```

Or directly:

```bash
tamarin-prover hybrid_pq_opaque_verified.spthy --prove -v
```

## Installation

### Tamarin

```bash
brew install tamarin-prover
```

### ProVerif

```bash
brew install proverif
```

## Relation to the Paper

These artifacts back the security-analysis sections of `docs/main_jisa.tex`.
The paper intentionally combines:

- symbolic evidence from this directory,
- implementation evidence from Rust tests,
- benchmark evidence from Criterion,
- explicit discussion of the remaining model gap.

That combined reading is the correct way to evaluate the project.
