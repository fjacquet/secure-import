# 0012 — Audit log with log/slog

- Status: accepted
- Date: 2026-10-06

## Context

sbmgr changes firmware state on many machines (Secure Boot, certificates, PK/KEK,
resets). Until now it only had a few debug lines on stderr (`-v`). Nothing recorded who
ran what, when, with which inputs, or what each BMC accepted.

## Decision

- `--log-file PATH` appends **JSON lines** (`log/slog` `JSONHandler`) to PATH, mode 0600.
  The console keeps its text handler and its own level (warnings, or debug with `-v`);
  `slog.NewMultiHandler` feeds both. The file records Info and above (Debug with `-v`).
- Every event of a run carries the same `run_id`.
- Events:
  - `run start`: version, action, database, platform, method, `dry_run`, `confirm`,
    host count, input path and SHA-256, output path, certificate file path and SHA-256,
    certificate URI, reset type, signature (a public hash), operator login and machine name.
  - `redfish write`: host, method, path, HTTP status, duration for every request that is not
    GET or HEAD (session login and logout included). Never the body, headers or credentials.
  - `host result`: ip, platform, action, database, `dry_run`, success, message, change
    message, error, duration.
  - `run end`: totals and duration.
- Passwords, session tokens and request or response bodies are never logged. Tests assert
  that a known password and a known body value are absent from the log.
- An unopenable log file stops the run (exit 2) before any write: a run that was asked to
  be recorded must not proceed unrecorded.

## Consequences

- The file is append-only by opening mode, not tamper-proof; ship it to a log collector
  if tamper evidence is needed.
- The log names machines and certificate URIs, so it is created 0600.
