# 0011 — Subcommands, with `-a` kept as a deprecated alias

- Status: accepted
- Date: 2026-10-05
- Builds on: ADR 0008 (cobra)

## Context

The command line was `sbmgr -i nodes.csv -o out.csv -a <action> [flags]`: one command, an
`-a` flag with eleven values, and every flag of every action in one flat list. As actions
grew (`reset_keys`, `probe`, `--database`, `--signature`), the help listed flags that apply
to one action only, nothing prevented passing them to another, and completion could not
offer the flags of the action being typed. ADR 0008 noted that a rework into subcommands
was possible without changing library.

## Decision

- One subcommand per action, grouped in the help:
  - Secure Boot: `status`, `enable`, `disable`, `policy custom|standard`, `reset-keys`;
  - Certificate databases: `db list|import|export|delete`;
  - Diagnostics: `probe`, `version` (and `completion`).
- Flags shared by every command (`-i`, `-o`, `-f`, `--dry-run`, `--platform`, `--method`,
  network and TLS flags, `-v`) are persistent flags of the root. Flags of one action belong
  to that command only: `--cert-file`, `--signature` and `--signature-owner` to `db import`,
  `--cert-uri` to `db export` and `db delete`, `--reset-type` to `reset-keys`, `--probe-dump`
  to `probe`; `--database` and `--confirm` to the `db` group and to `reset-keys`. Passing a
  flag to a command that does not have it is a usage error (exit code 2).
- `-a <action>` and the per-action flags stay on the root command, hidden, so existing
  scripts keep working. Using `-a` prints a deprecation warning naming the replacement
  command. It will be removed in a later release.
- Validation messages, exit codes (0, 1, 2), the report columns and `run()` are unchanged.
  `sbmgr` with no command is a usage error.

## Consequences

- The help shows only the flags that apply, shell completion works inside each command
  (`sbmgr db <TAB>`, `sbmgr db list --database <TAB>`), and a misplaced flag fails instead
  of being ignored.
- The report's `Action` column keeps the old names (`db_list`, `set_policy_custom`, ...),
  so result files and tooling that read them are unaffected.
- Two ways to do the same thing exist until `-a` is removed; the tests cover both.
