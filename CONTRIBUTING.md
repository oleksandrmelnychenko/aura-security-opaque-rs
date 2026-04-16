# Contributing to Aura OPAQUE

Thank you for your interest in contributing to this project.

## Reporting Issues

- **Security vulnerabilities**: Follow the private reporting path in `SECURITY.md`. Do NOT use public issues.
- **Bugs**: Open an issue using the bug report template.
- **Features**: Open an issue using the feature request template.

## Development Setup

```bash
cd rust
cargo build --workspace
cargo test --workspace
```

## Before Submitting

1. Run `cargo fmt --all` to format code.
2. Run `cargo clippy --workspace --all-targets -- -D warnings` with no warnings.
3. Run `cargo test --workspace` with all tests passing.
4. Ensure no new dependencies with GPL/AGPL licenses.

## Code Style

- Follow standard Rust conventions and `rustfmt` defaults.
- Keep cryptographic code constant-time where it handles secrets.
- Zeroize all sensitive data on drop.

## Pull Requests

- Keep PRs focused on a single change.
- Reference the relevant issue number.
- All CI checks must pass before merge.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
