# 0007 — `probe`: validate a platform with reads, not with a warning

- Status: accepted
- Date: 2026-10-05

## Context

Outside iDRAC9, nothing has run on a real BMC with this tool. The help and the README said
so through a caveat ("not validated on hardware"), which informs without proving anything and
gives no way to lift it. Several points of the spec are waiting on a fact: the value of
`Vendor` (HPE, Supermicro), the iDRAC9 firmware range, the fields actually populated in
`Certificate`, the presence of `ResetKeys` and its values, the Supermicro license.

## Decision

- New action `-a probe`, **strictly read-only**: only `GET`s.
- For each host, it replays the reads the drivers depend on (service root, platform
  detection, manager firmware, system, `SecureBoot`, the `ResetKeys` action, databases,
  `db` certificates and the fields present, `Bios/SecureBootPolicy` on Dell) and
  runs the drivers' actual reads (`status`, `db_list`).
- Each check is `OK`, `FAIL` or `ABSENT` (the BMC does not expose it: information, not
  an error) with its reason. A failing check does not stop the following ones. The exit
  code is 1 if any check is `FAIL`.
- `--probe-dump FILE` keeps the raw responses, **redacted**: the values of keys that
  identify a machine or carry a secret (serial numbers, UUIDs, addresses, host names,
  passwords, tokens...) are replaced with `<redacted>`. The file is mode 0600.
- A platform whose `probe` output has been reviewed and confirmed loses its "not validated"
  note; spec §11 is updated with the facts.

## Consequences

- The "not validated" points become verifiable facts on any fleet, with no write
  risk, and the captures can serve as test fixtures for `testbmc`.
- `probe` does not prove the behavior of writes (import, delete, reset):
  `--dry-run` followed by a trial on a test server are still required.
- Redaction is by key name: sensitive data under an unexpected name could slip
  through. Review the capture before sharing it.
