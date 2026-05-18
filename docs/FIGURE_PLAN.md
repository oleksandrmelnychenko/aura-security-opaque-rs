# Figure Plan for `main_jisa.tex`

This file is an editorial map for the final visual layer of the OPAQUE
paper. The submission PDF should not contain visible placeholder boxes.
Use the `FIGURE SLOT` comments in `main_jisa.tex` as insertion anchors
when a finished vector figure is ready.

## Visual Rules

- Prefer vector figures: TikZ in LaTeX, PDF, or SVG converted to PDF.
- Avoid stock imagery, decorative graphics, screenshots of code, or UI-like cards.
- Every figure must support one technical claim already stated in the text.
- Do not introduce new security claims in a caption.
- Use short labels, mathematical notation already defined in the paper, and the same colors across figures:
  - classical/Ristretto255 path: blue
  - post-quantum/ML-KEM path: gold
  - transcript/account binding: green
  - trust boundary or limitation: red

## F1 — Evidence Stack Overview

Placement: after `Research Contributions`, before `Terminological Conventions`.

Status: optional.

Purpose: give reviewers a one-screen map of the artifact without claiming that every layer proves the same thing.

Content:
- protocol specification
- symbolic models: ProVerif and Tamarin
- reference implementation in Rust
- deterministic, integration, property, and regression tests
- Criterion benchmarks
- explicit claim boundaries

Recommended caption:
`Layered evidence used in the paper: the specification, symbolic models, reference implementation, tests, and benchmarks support different parts of the claim set under explicit boundaries.`

## F2 — Threat Boundary Diagram

Placement: after Table `tab:threat-boundary`, before `Protocol requirements`.

Status: optional but useful if the paper needs a clearer security boundary.

Purpose: make the most important limitation visually obvious: database compromise is in scope, but compromise of the OPRF root secret is a different threat model.

Content:
- active network adversary controlling messages
- compromised registration database
- `sigma_oprf` outside the compromised store
- post-session long-term key exposure
- quantum recovery of classical DH terms
- excluded: side channels, availability, external crate memory bugs

Recommended caption:
`Threat boundary for the main claims: database compromise, active network control, post-session key exposure, and quantum recovery of classical DH terms are separated from compromise of the OPRF root secret and implementation side channels.`

## F3 — Protocol Flow

Placement: in `Architecture and Overview`, before the primitive and message-size tables.

Status: implemented in `main_jisa.tex` as Figure `fig:protocol-flow`.

Purpose: show the full construction before the equations. This should be the main reader-friendly protocol figure.

Content:
- registration:
  - `C -> S: B`
  - `S -> C: Z || PK_S`
  - client stores/seals envelope and public key material
- authentication:
  - `KE1 = B || E_C || n_C || pk_kem`
  - `KE2 = n_S || E_S || CredResp || MAC_S || ct_kem`
  - `KE3 = MAC_C`
- show where `acct`, `eta`, `tau`, `pk_kem`, and `ct_kem` enter the transcript
- show that the message count remains three for authentication

Recommended caption:
`Hybrid PQ-OPAQUE message flow. ML-KEM public and ciphertext material are carried in KE1 and KE2, while account and transcript binding feed the authenticated key schedule without adding an authentication message.`

## F4 — Wire-Size Growth

Placement: already implemented as Figure `fig:wire-size-growth`.

Status: already present; keep unless replaced by a cleaner vector graphic.

Purpose: show that bandwidth overhead is concentrated in KE1 and KE2.

Required data:
- KE1 classical payload: 88 bytes
- KE1 hybrid wire: 1273 bytes
- KE2 classical payload: 288 bytes
- KE2 hybrid wire: 1377 bytes
- KE3 classical payload: 64 bytes
- KE3 hybrid wire: 65 bytes
- total hybrid wire: 2715 bytes
- total increase: 2272 bytes

Current caption:
`Comparison of authentication-message sizes: the additional wire-format overhead is concentrated in KE1 and KE2, whereas KE3 remains essentially unchanged.`

## F5 — Hybrid Combiner and Key Schedule

Placement: after Eq. `eq:hybrid-prk`, before `Key derivation`.

Status: implemented in `main_jisa.tex` as Figure `fig:hybrid-key-schedule`.

Purpose: make the scientific novelty of the combiner visible.

Content:
- left branch: `dh_1 || dh_2 || dh_3 || dh_4`
- right branch: `ss_kem`
- transcript branch: `tau -> tau_H`
- account branch: `acct -> eta`
- `salt = L_comb || tau_H`
- `HKDF-Extract(salt, combined_ikm) -> PRK`
- `HKDF-Expand -> K_s, K_m, K_mac^S, K_mac^C`

Recommended caption:
`Transcript-bound hybrid combiner. Classical 4DH material and the ML-KEM shared secret are extracted under a transcript-derived salt before expansion into session, master, and confirmation keys.`

## F6 — Verification Evidence Map

Placement: after Table `tab:verification-summary`.

Status: optional.

Purpose: reduce table fatigue and show that evidence is layered rather than monolithic.

Content:
- claims P1--P7
- ProVerif: secrecy/authentication correspondence
- Tamarin: stateful 4DH surrogate lemmas
- Rust tests: serialization, state lifecycle, replay rejection, property and regression checks
- boundary note: no machine-checked proof of compiled code

Recommended caption:
`Evidence map for the main security claims. Symbolic models and executable tests cover complementary properties and must be read with the stated modeling boundaries.`

## F7 — Reference Implementation Architecture

Placement: after Table `tab:code-metrics`, before `Specification-to-Implementation Traceability`.

Status: optional.

Purpose: show that the artifact is structured enough for review and reproduction.

Content:
- `opaque-core`: primitives, key derivation, serialization
- `opaque-agent`: client and server protocol phases
- `opaque-relay`: responder-side service logic
- `opaque-ffi`: external API adapter
- tests and benches as separate validation paths
- formal models as separate analysis artifacts

Recommended caption:
`Reference implementation structure. The protocol core, client/server phases, relay adapter, FFI boundary, tests, benchmarks, and formal models are separated to make specification-to-artifact checks reproducible.`

## F8 — Server Benchmark Runtime Profile

Placement: before or after Table `tab:micro-bench`.

Status: optional; benchmark tables were refreshed on the Linux/Xeon host on 2026-05-18.

Purpose: make the performance result immediately legible: Argon2id dominates latency; ML-KEM and 4DH remain sub-millisecond.

Content:
- platform label: Linux, Intel Xeon E5-2650 v4, 2 sockets, 24 cores / 48 threads
- Argon2id MODERATE: 841.37 ms
- ML-KEM-768 full round: 492.30 us
- Ristretto255 4DH protocol profile: 245.57 us
- KE2 generation: 592.69 us
- KE3 generation: 1.101 s
- end-to-end authentication: 836.11 ms
- use a log-scale horizontal bar chart if both microseconds and milliseconds appear in one figure

Recommended caption:
`Server-side runtime profile on the Linux/Xeon benchmark platform. The password-hardening step dominates end-to-end latency, while the post-quantum and classical key-exchange components remain sub-millisecond.`

## Priority Order

1. F3 Protocol Flow
2. F5 Hybrid Combiner and Key Schedule
3. F8 Server Benchmark Runtime Profile
4. F4 Wire-Size Growth
5. F6 Verification Evidence Map
6. F2 Threat Boundary Diagram
7. F7 Reference Implementation Architecture
8. F1 Evidence Stack Overview

For a tight journal version, keep F3, F4, F5, and F8. Use F2/F6/F7 only if
page budget allows or if reviewers ask for more visual clarification.
