# 0003 — One driver per platform behind a `Platform` interface

- Status: accepted
- Date: 2026-10-05

## Context

The scope covers Dell iDRAC9 and iDRAC10, HPE iLO, Lenovo XCC and Supermicro. All
follow Redfish, but diverge where it matters:

- Dell: OEM certificate import as multipart, `Custom`/`Standard` policy via a
  BIOS attribute, and a reduced `ResetKeys` on iDRAC10.
- HPE and Supermicro: import via JSON `POST` `{CertificateString, CertificateType}` on
  `SecureBootDatabases/{db}/Certificates`.
- Lenovo: no documented `SecureBootDatabases`, only `SecureBoot`.

## Decision

A `Platform` interface (`Status`, `SetSecureBoot`, `SetPolicy`, `DBList`, `DBImport`,
`DBExport`, `DBDelete`) and one package per family (`dell`, `hpe`, `lenovo`, `supermicro`).
The Redfish client, the CSV, the worker pool and the report remain shared. The platform
is detected from `Vendor` and `FirmwareVersion`; `--platform` forces it. An unsupported
action returns `ErrUnsupported`, which becomes a result row, never a crash.

## Rationale

- Dell OEM specifics are confined to one package: iDRAC10 or another vendor can be added without
  touching the rest.
- Each driver carries its own success rule and its own "validated / not validated" status.

## Consequences

- More packages than a single script, but each is testable with its own fake BMC.
- HPE and Supermicro share the same POST schema and differ only by a size limit:
  a single parameterized driver (`stdsb.Driver`) covers them. Lenovo and Dell keep their own
  (own success rule and OEM specifics).
- Adding a vendor requires its official documentation (see spec §3).
