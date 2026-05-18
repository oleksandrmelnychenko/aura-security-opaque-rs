# Presentation Outline

This outline is designed for a short competition or defense talk built
around the Hybrid PQ-OPAQUE artifact package.

## Slide 1 — Problem

Message:
- Password authentication is still dominant.
- Classical OPAQUE is strong, but not post-quantum.
- The migration problem is practical, not hypothetical.

Use:
- one sentence from the abstract
- quantum-motivation references from the paper

## Slide 2 — What We Built

Message:
- Hybrid PQ-OPAQUE = OPAQUE + 4DH + ML-KEM-768
- no extra round trips
- wire-versioned protocol with `account_id` binding

Use:
- protocol summary from `docs/main_jisa.tex`

## Slide 3 — Artifact Evidence

Message:
- real Rust implementation
- formal models
- tests
- benchmarks

Use:
- `README.md`
- `docs/ARTIFACT_GUIDE.md`

## Slide 4 — Evidence Stack

Primary visual:
- claim-scope and traceability tables from `docs/main_jisa.tex`

Message:
- claims are supported by multiple independent layers
- no overclaim of “full proof of all code”

## Slide 5 — Wire Cost of Going Post-Quantum

Primary visual:
- Figure `fig:wire-size-growth`

Message:
- the PQ cost is concentrated in KE1 and KE2
- KE3 stays almost unchanged
- no extra message rounds were added

## Slide 6 — Runtime Cost of Going Post-Quantum

Primary visual:
- optional Figure F8 from `docs/FIGURE_PLAN.md` using the refreshed
  Linux/Xeon benchmark measurements

Message:
- ML-KEM-768 adds overhead, but not a new latency class
- the protocol remains interactive and practical

## Slide 7 — Real Bottleneck

Message:
- Argon2id dominates end-to-end latency
- this is intentional and security-relevant
- the real tuning knob is KSF, not whether PQ is feasible

Use:
- benchmark tables and discussion section

## Slide 8 — Security Boundary

Message:
- offline dictionary resistance is scoped
- DB compromise is not the same as `oprf_seed` compromise
- honesty about the trust boundary is a strength, not a weakness

Use:
- threat-boundary discussion in the paper

## Slide 9 — Why This Work Matters

Message:
- reproducible applied cryptography
- hybrid augmented PAKE with code, proofs, and metrics
- bridge between research and deployable systems

## Slide 10 — Closing

Message:
- Hybrid PQ-OPAQUE is practical now
- the repository is reviewable and reproducible
- the work is ready for scrutiny and presentation

## Judge-Facing One-Line Pitch

“This work turns post-quantum augmented PAKE from a theoretical idea
into a reproducible artifact package: protocol, code, tests, formal
evidence, and performance data all aligned in one implementation.”
