# 0010 — GoReleaser, signed release, SBOM and provenance

- Status: accepted
- Date: 2026-10-05

## Context

The `v0.1.0-alpha.1` release came from a home-grown workflow script: 5 bare binaries and a
`SHA256SUMS`, with no signature and no SBOM. The tool holds BMC credentials and writes to
Secure Boot: anyone who downloads it must be able to verify where it comes from.

## Decision

- **GoReleaser** (`.goreleaser.yaml`, version 2) builds the 5 targets (linux, macOS, Windows
  amd64; linux and macOS arm64), without CGO, with `-trimpath`, commit timestamp (reproducible
  build), version injected via `-X main.version`.
- `tar.gz` archives (`zip` on Windows) with `LICENSE` and `README.md`, `checksums.txt`.
- **Keyless cosign signature** of the checksums file (which covers all the
  archives), using the OIDC identity of the GitHub workflow: no key to keep.
- **SBOM** for each archive (syft) and a GitHub **provenance attestation**
  (`actions/attest`) on `checksums.txt`.
- The release is published as a pre-release for any `v0.x` version or one with a suffix.
- The release workflow reruns the tests and `govulncheck` before building.

## Consequences

- Verification: `sha256sum -c`, `cosign verify-blob`, `gh attestation verify` (see README).
- The archives are no longer bare binaries: the file names change.
- `make build-all` remains for local development; `goreleaser release --snapshot` tries
  the release without publishing or signing anything.
- The signature and attestation can only be exercised in CI, on a real tag: the
  first release with this chain is its first real trial.
