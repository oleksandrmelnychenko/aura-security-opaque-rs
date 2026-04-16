# Release Snapshot

Current snapshot target: `v2.0.0`

## Public Surface

- C headers in `rust/include/` are the canonical ABI.
- Agent-side FFI returns error codes directly; there is no structured `out_error` parameter layer.
- `opaque_agent_generate_ke1` requires `account_id` / `account_id_length`, and the same identifier must be reused on the relay side for `opaque_relay_generate_ke2`.
- Swift imports `AuraOPAQUEBinary` directly and exposes `generateKE1(password:accountId:state:)`.

## Validation Checklist

- `cargo fmt --manifest-path rust/Cargo.toml --all --check`
- `cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --locked -- -D warnings`
- `cargo test --manifest-path rust/Cargo.toml --workspace --tests --lib --locked`
- C smoke test against curated headers
- Swift build against the staged XCFramework/module

## Artifact Expectations

- `dist/apple/AuraOPAQUE.xcframework.zip`
- `dist/apple/AuraOPAQUE.xcframework.zip.checksum`
- Current local checksum: `1d9570eb94989899d55dfe52657ae44118a2d516c9e5a18c9b8ecf56f30946fe`
- `Package.swift` updated to the published `v2.0.0` asset and checksum
