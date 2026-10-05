# 0009 — Other Secure Boot databases (PK, KEK, dbx) and per-database reset

- Status: accepted
- Date: 2026-10-05

## Context

So far the tool only manages the `db` database. The Dell OpenAPIs (iDRAC10 1.30 verified) expose
for each database in `SecureBootDatabases` a `Certificates` collection (GET, POST, DELETE
of a member) and a `Signatures` collection (GET, POST, DELETE of a member), as well as a
`SecureBootDatabase.ResetKeys` action limited to `ResetAllKeysToDefault` and `DeleteAllKeys`.
No source consulted (sushy, gofish, the Lenovo and Supermicro guides, the Dell OpenAPI)
shows a safe write on PK or KEK, nor the body of the POST on `Signatures` for dbx:
the Dell schema describes no useful property there.

## Decision

- Option `--database db|KEK|PK|dbx` (default: `db`, behavior unchanged).
- A driver is bound to one database per host (`WithDatabase`); the `Platform` interface
  changes only by `AddSignature`. Dell's multipart OEM store exists only for `db`: any
  other database goes through the standard collections, whatever `--method` says.
- `dbx` carries signatures, not certificates: `db_list --database dbx` counts the
  members of `Signatures`; `db_import --database dbx --signature <sha256 hex>
  [--signature-owner GUID]` adds a SHA-256 signature. The POST body reuses the DMTF names
  of the `Signature` resource (`SignatureString`, `SignatureType`
  `EFI_CERT_SHA256_GUID`, `SignatureTypeRegistry` `UEFI`, `UefiSignatureOwner`). **This format
  is not confirmed by any BMC.**
- Guard rules, applied before any import or delete (including `db_delete` of a member whose
  URI contains a `PK`, `KEK` or `dbx` path segment):
  - PK, KEK and dbx require `--confirm`;
  - PK and KEK additionally require a `SecureBootMode` equal to `SetupMode` or `AuditMode`:
    the platform key of a deployed server is not replaced by accident.
  - `--dry-run` applies the same refusals.
  - The certificate URI is normalised before it is checked **and sent** (percent-decoded
    repeatedly, `.` `..` `;` parameters, query and spaces removed), so a spelling the BMC
    normalises (`%4BEK`, `kek;x=1`) cannot slip past the guard.
- Resets are not gated on the mode: `reset_keys` (whole SecureBoot or one database) needs
  `--confirm` and nothing else, as in ADR 0006. A mode requirement would forbid the very
  operations that lead to Setup Mode (`DeletePK`, `DeleteAllKeys`), and a whole-SecureBoot
  reset reaches PK and KEK in any case, so one rule covers every spelling.
- `reset_keys --database X` calls the database's `SecureBootDatabase.ResetKeys` action,
  validated against its `AllowableValues`; only `ResetAllKeysToDefault` and `DeleteAllKeys`
  exist at this level.
- `-a probe` reports, per database, the collection exposed, the number of members, the
  permitted `ResetKeys` values and the `*Default` databases present.

## Out of scope

`dbr` and `dbt`, the `*Default` databases (read-only by definition), importing
certificates into dbx, writing PK or KEK by any means other than the standard
collections.

## Consequences

- Everything concerning PK, KEK and dbx is **not validated on hardware**; `-a probe` tells
  what each BMC exposes before any write.
- The format of the `Signatures` POST is a documented assumption. A BMC that rejects it
  returns an error that is reported as is; nothing is presented as a success without a
  success message (ADR 0004).
- An unreadable `SecureBootMode` is treated as "not in Setup/Audit": refusal.
