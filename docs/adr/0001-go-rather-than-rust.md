# 0001 — Go rather than Rust

- Status: accepted
- Date: 2026-10-05

## Context

The original Python script requires installing an interpreter and the `requests`
library on every workstation. The need: a tool to copy and run, with nothing to
install, on Windows (Git Bash), Linux and macOS. The alternative considered was Rust,
provided it avoids installing a runtime.

## Decision

Go 1.27, standard library only (`net/http`, `encoding/csv`, `log/slog`).

## Rationale

- Go and Rust both produce a standalone binary: Rust brings nothing more on the
  "no installation" criterion.
- Go cross-compiles with a single command (`GOOS`/`GOARCH`), with no per-target toolchain.
- It is the stack already used for the team's exporters.
- Goroutines and the stdlib HTTP client are enough for the worker pool and the
  Redfish sessions: no external dependency.

## Consequences

- No third-party dependency to track or audit (originally; cobra was added later, see ADR 0008).
- The binary embeds the Go runtime and weighs a few MB.
- No manual memory management and none of Rust's guarantees: acceptable for an HTTP client.
