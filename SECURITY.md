# Security policy

## Reporting a vulnerability

Do not publish a vulnerability in an issue. Use GitHub's private reporting:
**Security → Report a vulnerability** on this repository. Include the version (`sbmgr --version`),
the affected platform and, if possible, how to reproduce the problem without a real password.

## Supported versions

Only the latest published version is supported. The project is in **alpha**.

## What to know before using it

- **Nothing has been validated on hardware** with this tool. Try `sbmgr probe`, then `sbmgr status` and `sbmgr db list`
  on a test server before any write, and `--dry-run` before an import, a deletion
  or a `reset_keys`.
- **TLS verification is disabled by default** (BMCs almost always have a self-signed
  certificate). On an uncontrolled management network, someone in an interception position
  can impersonate a BMC and capture the credentials. Use `--ca-file` or
  `--verify-tls`, and accounts dedicated to Secure Boot.
- The input CSV contains passwords in plaintext: `0600` permissions, never committed.
- `reset_keys` with `DeleteAllKeys` or `DeletePK` puts the server in Setup Mode: Secure
  Boot no longer protects it. The tool requires `--confirm`.
- The tool never reboots a server: changes stay pending until the
  next boot.
