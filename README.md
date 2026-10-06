# sbmgr

[![CI](https://github.com/fjacquet/secure-import/actions/workflows/ci.yml/badge.svg)](https://github.com/fjacquet/secure-import/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/Go-1.27-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-alpha-orange)
![Dependencies](https://img.shields.io/badge/dependencies-cobra-brightgreen)
![Binary](https://img.shields.io/badge/binary-single%2C%20no%20runtime-blue)
![OS](https://img.shields.io/badge/OS-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Redfish](https://img.shields.io/badge/Redfish-DMTF%20DSP0266%201.14-informational)

Manage Secure Boot and the UEFI `db` certificate database across a fleet of
servers, over Redfish. One binary per OS, nothing to install.

> **Status: alpha.** The code is written and tested against a fake BMC; only the
> iDRAC9 behavior relies on a script proven in production. No platform has been
> validated on hardware with this tool: start with `sbmgr probe`, then `sbmgr status` and `sbmgr db list`.

## Supported platforms

| Platform | v1 actions | Validation |
|---|---|---|
| Dell iDRAC9 | `status`, `enable`, `disable`, `set_policy_custom`, `set_policy_standard`, `db_list`, `db_import`, `db_export`, `db_delete`, `reset_keys` | Behavior of the production script; simulated tests |
| Dell iDRAC10 | same actions as iDRAC9 (confirmed by OpenAPI 1.30) | Not validated on hardware; import through the standard POST |
| HPE iLO (ProLiant) | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete`, `reset_keys` | Not validated on hardware |
| Lenovo XCC | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete`, `reset_keys` | Not validated on hardware; import requires the Secure Boot policy to be "Custom Policy" |
| Supermicro | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete`, `reset_keys` | Not validated on hardware |

The platform is detected automatically from Redfish (`--platform` to force it).
Secure Boot and BIOS changes stay pending until the reboot; the tool never
reboots a server.

## Usage

```sh
sbmgr status  -i examples/nodes.example.csv -o status.csv
sbmgr db list -i nodes.csv -o db.csv
sbmgr db import -i nodes.csv -o import.csv --cert-file ./certs/vendor_db.der
sbmgr db import -i nodes.csv -o plan.csv --cert-file ./certs/vendor_db.der --dry-run   # nothing is written
sbmgr reset-keys -i nodes.csv -o reset.csv --reset-type ResetDB --confirm              # destructive
sbmgr probe -i nodes.csv -o probe.csv --probe-dump probe.json                          # read-only check
```

Commands: `status`, `enable`, `disable`, `policy custom|standard`, `reset-keys`,
`db list|import|export|delete`, `probe`, `version`, `completion`. `sbmgr -h` lists them by
group; `sbmgr <command> -h` shows the flags of one command.

> The earlier form `sbmgr -i f -o f -a db_list` still works but is deprecated and prints
> the replacement command ([ADR 0011](docs/adr/0011-subcommand-cli.md)).

Main options (`sbmgr -h` gives the full list):

| Option | Purpose |
|---|---|
| `sbmgr probe`, `--probe-dump` | read-only check of what each BMC answers; `--probe-dump f.json` keeps the raw, redacted responses |
| `--dry-run` | reads and validates everything, writes nothing: the result says what would change |
| `--database` | `db` (default), `KEK`, `PK` or `dbx`. PK, KEK and dbx require `--confirm`; PK and KEK also require `SetupMode` or `AuditMode` |
| `--signature`, `--signature-owner` | dbx: adds a SHA-256 signature (`db_import --database dbx`); POST format not confirmed |
| `--cert-file`, `--cert-uri` | certificate file (PEM or DER, 64 KiB max); certificate URI for `db_export` and `db_delete` |
| `--reset-type`, `--confirm` | `reset_keys` type; confirmation required for this destructive action |
| `--retries N` | retries on transient error (default 2); a write is never replayed |
| `--concurrency`, `--timeout`, `--task-timeout`, `--no-wait` | parallel hosts (20); per-request timeout (30 s); task tracking duration (120 s); do not track tasks |
| `--platform`, `--method` | force the platform; Dell import method `oem` or `standard` |
| `--verify-tls`, `--ca-file` | verify the BMC certificates |
| `--allow-custom-when-disabled` | `policy custom` only: allow the Custom policy while Secure Boot is disabled (refused by default) |
| `--log-file PATH` | append a JSON-lines audit log (run id, inputs hashes, every write, per-host result; never secrets) |
| `--version` | binary version |

Exit code: `0` everything succeeded; `1` at least one host failed or a CSV row was
skipped; `2` usage or input error (unreadable file, no host).

**New platform or new firmware?** Run `sbmgr probe` first: it only reads, and reports
what each BMC answers (`OK`, `FAIL`, `ABSENT`).

A `db_import` of an entry that is already present writes nothing ("already present", compared by SHA-256).
`enable` and `disable` stay pending until the next boot.

Input file: see [`examples/nodes.example.csv`](examples/nodes.example.csv)
(single IP, range on any octet, CIDR). Passwords are in plaintext there:
do not commit it.

## Shell completion

```sh
sbmgr completion bash > /etc/bash_completion.d/sbmgr          # bash
sbmgr completion zsh  > "${fpath[1]}/_sbmgr"                  # zsh
sbmgr completion fish > ~/.config/fish/completions/sbmgr.fish # fish
sbmgr completion powershell | Out-String | Invoke-Expression  # PowerShell
```

The shell completes actions (`-a`), `--platform`, `--method`, `--reset-type`, `--format`
and files (`-i`, `--cert-file`, `--ca-file`, `--probe-dump`).

## Security

TLS verification is **disabled by default** (BMCs almost always have a
self-signed certificate); the tool warns about it on every run. On an uncontrolled
management network, someone in an interception position could impersonate
a BMC and capture the credentials. Use `--ca-file ca.pem` (or `--verify-tls`
with valid certificates) and accounts dedicated to Secure Boot.

## Verifying a release

Each release publishes the per-OS archives, `checksums.txt`, the signature of that file
(`checksums.txt.sigstore.json`, a cosign "keyless" signature tied to the GitHub workflow), an SBOM
per archive and a provenance attestation.

```sh
sha256sum -c checksums.txt --ignore-missing
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/fjacquet/secure-import/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
gh attestation verify sbmgr_<version>_linux_amd64.tar.gz --owner fjacquet
```

## Building

```sh
make build        # local binary in bin/sbmgr
make build-all    # linux amd64/arm64, windows amd64, macOS arm64/amd64 (no CGO, no runtime)
make test         # tests against a fake BMC
```

## License

[MIT](LICENSE).

## Documentation

- [Design spec](docs/superpowers/specs/2026-10-05-secure-boot-manager-go-design.md)
  : architecture, per-platform behavior, unvalidated points.
- Architecture decision records (ADR):
  - [0001 — Go rather than Rust](docs/adr/0001-go-rather-than-rust.md)
  - [0002 — Redfish link discovery](docs/adr/0002-redfish-link-discovery.md)
  - [0003 — One driver per platform](docs/adr/0003-one-driver-per-platform.md)
  - [0004 — Success is read from `ExtendedInfo`](docs/adr/0004-success-read-from-extendedinfo.md)
  - [0005 — Dell: OEM import on iDRAC9, standard on iDRAC10](docs/adr/0005-dell-import-method.md)
  - [0006 — `reset_keys`: a destructive, explicit, confirmed action](docs/adr/0006-reset-keys.md)
  - [0007 — `probe`: validate a platform with reads](docs/adr/0007-probe-action.md)
  - [0008 — cobra for the command line](docs/adr/0008-cobra-for-the-cli.md)
  - [0009 — Other Secure Boot databases (PK, KEK, dbx)](docs/adr/0009-other-secure-boot-databases.md)
  - [0010 — GoReleaser, signed release, SBOM and provenance](docs/adr/0010-goreleaser-signed-release.md)
  - [0011 — Subcommands, with `-a` kept as a deprecated alias](docs/adr/0011-subcommand-cli.md)
  - [0012 — Audit log with log/slog](docs/adr/0012-audit-log.md)
  - [0013 — Custom policy refused while Secure Boot is disabled](docs/adr/0013-custom-policy-guard.md)
