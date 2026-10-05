# 0008 — cobra for the command line (shell completion)

- Status: accepted
- Date: 2026-10-05
- Replaces in part: the "standard library only" goal of ADR 0001

## Context

The command line was built on the standard library `flag` package. It has no shell
completion, no way to show a short and a long option as a single entry in the help (each
alias appeared twice), and no subcommands. Completion (values of `-a`,
`--platform`, `--reset-type`, files for `--cert-file`...) is genuinely useful for
operators who manage a fleet with long action names. A Go binary remains
a single binary with dependencies: the "nothing to install" criterion is untouched.

## Decision

- Adopt **cobra** (`spf13/cobra` v1.9.1; dependencies: `spf13/pflag`, and
  `inconshreveable/mousetrap` for Windows).
- Why cobra rather than kong: cobra natively generates bash, zsh, fish
  and PowerShell completion and dynamic completion of option values; kong does not offer
  this built in.
- A single root command, which keeps `-a <action>` (no contract change for existing
  scripts), plus `sbmgr version` and `sbmgr completion <shell>`. Cobra only creates the
  `completion` command if the root has a subcommand, hence `version`.
- `run(args, stdout, stderr) int` and the exit codes (0, 1, 2) are unchanged.
- Visible changes: a short option and its long form fit on one line
  (`-i, --input`); single-dash long forms (`-input`) are no longer accepted;
  `-v` gains `--verbose`; `-h` help goes to standard output.

## Consequences

- The module now has dependencies: `go.sum` is versioned, Dependabot watches the Go
  modules, and the README no longer advertises "stdlib only".
- The binary grows by about 0.3 MB (measured: 6.96 → 7.25 MB, macOS arm64).
- A later rework into subcommands (`sbmgr probe`, `sbmgr reset-keys`) would not
  require changing library; it is not decided here.
