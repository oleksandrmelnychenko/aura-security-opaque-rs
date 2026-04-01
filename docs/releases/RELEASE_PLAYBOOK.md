# Release Playbook

## Objective

Publish a verified Apple binary release that ships:

- curated headers from `rust/include/`
- matching `module.modulemap`
- a checksum aligned with `Package.swift`
- attested XCFramework provenance
- release notes that document the current ABI and Swift surface

## Pre-Release Validation

1. Run `scripts/release/smoke-release.sh`
2. Run `scripts/release/build-apple-xcframework.sh`
3. Confirm the produced XCFramework contains:
   - `opaque_common.h`
   - `opaque_agent.h`
   - `opaque_relay.h`
   - `opaque_api.h`
   - `module.modulemap`
4. Record the checksum from `dist/apple/EcliptixOPAQUE.xcframework.zip.checksum`

## Package Manifest Update

After the checksum is known, update `Package.swift`:

```bash
scripts/release/update-package-swift.sh 2.0.0 "$(tr -d '[:space:]' < dist/apple/EcliptixOPAQUE.xcframework.zip.checksum)"
```

## GitHub Release Procedure

1. Create a new release tag, for example `v2.0.0`.
2. Push the tag so `.github/workflows/build-and-publish.yml` runs.
3. Verify the workflow uploaded:
   - `EcliptixOPAQUE.xcframework.zip`
   - `EcliptixOPAQUE.xcframework.zip.checksum`
   - build attestation
4. Publish release notes that describe the exact C and Swift surface shipped by the artifact.
5. Verify `Package.swift` points at the same release asset and checksum.

## Post-Release Consumer Check

1. Re-run `swift build` against the published binary target.
2. Re-run the C smoke test against the curated headers.
3. Verify the Swift wrapper imports the packaged binary module directly and that agent authentication requires explicit `accountId` binding.

## Expected End State

- Public ABI and shipped artifact match exactly.
- Package manifest checksum matches the newly published release.
- Consumers see the current major-version API surface reflected in headers, Swift, and release notes.
