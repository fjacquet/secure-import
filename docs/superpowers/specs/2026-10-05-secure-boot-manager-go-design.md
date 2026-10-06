# sbmgr — Secure Boot management over Redfish (design)

Date: 2026-10-05 · Status: for review · Language: Go 1.27, standard library + cobra (ADR 0008)

## 1. Intent

Go port of the Python script `secure_boot_manager.py` (Dell iDRAC9), to inject
vendor certificates into the UEFI `db` database of a fleet of servers so that Secure Boot
is allowed. One binary per OS, with no runtime or interpreter to
install (cross-compilation for Windows / Linux / macOS).

Success:
- The 9 script actions run identically on iDRAC9 (same CSV columns).
- The 6 bugs listed in `secure_boot_manager_changes.md` are covered by tests.
- The design follows the DMTF DSP0266 1.14 spec: no assumed URIs, everything starts from `/redfish/v1/`.
- iLO (ProLiant) and iDRAC10 are supported according to the scope in §3, with each
  driver explicitly marked validated or not validated.

Stated by the user: Go rather than Rust; improvements allowed; iDRAC9 is
the main target; iLO and iDRAC10 included according to §3. Assumption: deployment
is done from a Windows workstation (Git Bash) or Linux, with direct network access to the BMCs.

Structuring decisions are recorded as ADRs in `docs/adr/` (0001 to 0010: Go, link discovery,
one driver per platform, success read from `ExtendedInfo`, and the later ones).

## 2. Sources

- Scripts and changelog provided (iDRAC9 reference behavior).
- Dell iDRAC9 7.00.00.00 OpenAPI (`docs/openapi-7.xx.yaml`) and iDRAC10 I10-1.10.00.00
  (`docs/11017-1.30.xx.json`).
- HPE iLO Redfish docs (SecureBootDatabases) via Context7.
- DMTF DSP0266 1.14 (sessions, tasks, ETag, link discovery).
- Existing projects read for their behavior (no code copied): `bmc-toolbox/bmclib`
  (Apache-2.0), `stmcginnis/gofish` (BSD-3), Ansible module `dellemc.openmanage.idrac_secure_boot`
  (GPL-3.0) and `dell/iDRAC-Redfish-Scripting`. None does "certificate injection across
  a multi-vendor fleet"; they were used to correct the design (§7, §11).

## 3. Scope

| Driver | v1 actions | Status |
|---|---|---|
| `idrac9` | `status`, `enable`, `disable`, `set_policy_custom`, `set_policy_standard`, `db_list`, `db_import`, `db_export`, `db_delete`, `reset_keys` | Behavior taken from the production script; simulated tests |
| `idrac10` | the 10 actions, same as `idrac9` | Checked in the 1.30 OpenAPI: `SecureBoot` PATCH, `Bios/Settings` (`SecureBootPolicy`), `Certificates` collections, `ResetKeys`. Import/delete through the standard POST/DELETE (Dell Ansible module method); export read from `CertificateString` in the JSON; **not validated on hardware** |
| `ilo` | `status`, `db_list`, `db_import`, `db_delete`, `enable`, `disable` | Standard Redfish based on the HPE docs; **not validated on hardware** |
| `lenovo` | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete` | `status`/`enable`/`disable` based on the XCC REST API Guide; `db_*` through the standard POST/DELETE like `bmclib`, which the guide does not document; **not validated on hardware** |
| `supermicro` | `status`, `enable`, `disable`, `db_list`, `db_import`, `db_delete` | Based on the Supermicro Redfish guide; **not validated on hardware**. Import documented for `dbt` only; `db` assumed identical |

The Supermicro YAML provided (`super-micro-computer-chassis-api-openapi.yml`) only covers
`/Chassis`, `Power` and `Thermal`: it is not used. The `supermicro` driver relies
on the official Redfish guide 1.22.2-00.04 (User Guide 4.0, 320-page PDF).

An action not supported by a driver produces a result line
`Success=No` with the error `action not supported on <platform>`, never a crash.
Out of scope for v1: automatic reboot, `PK`/`KEK`/`dbx` write access, `ResetKeys`,
standard write on iDRAC9 (iDRAC9 keeps the OEM multipart, see §7).

## 4. Architecture

```
cmd/sbmgr/            flags, wiring, exit code
internal/inventory/   CSV reading (BOM), IP expansion
internal/redfish/     client: session, discovery, tasks, ExtendedInfo, ETag
internal/platform/    Platform interface, shared types, action names
internal/stdsb/       standard SecureBoot helper (DMTF) + generic driver (ilo, supermicro)
internal/dell/        idrac9 and idrac10 drivers (Dell OEM isolated here)
internal/lenovo/      lenovo driver (XCC-specific success rule)
internal/detect/      platform detection and driver factory
internal/actions/     orchestration of the 9 actions into a result
internal/report/      CSV (Python columns) and JSON
internal/runner/      worker pool, session lifecycle
internal/testbmc/     fake BMC for tests
```

The `ilo` and `supermicro` drivers are identical except for the certificate size limit:
a single parameterized driver (`stdsb.Driver`) avoids the duplication planned by ADR 0003.

Interface (one per BMC, created after detection):

```go
type Platform interface {
    Name() string
    Supports(action string) bool
    Status(ctx context.Context) (Status, error)
    SetSecureBoot(ctx context.Context, enable bool) (Change, error)
    SetPolicy(ctx context.Context, policy string) (Change, error)
    DBList(ctx context.Context) ([]Cert, error)
    DBImport(ctx context.Context, file string) (Change, error)
    DBExport(ctx context.Context, uri, file string) (Change, error)
    DBDelete(ctx context.Context, uri string) (Change, error)
}
```

`Supports` lets the orchestrator refuse an action without a network call. A
`platform.Unsupported` type, embedded by the drivers, returns `ErrUnsupported` for
unhandled methods. `Status` also carries `PendingPolicy` (pending value in
`Bios/Settings`, see §7).

## 5. Redfish client (`internal/redfish`)

- **Discovery**: `GET /redfish/v1/` → `Links.Sessions`, `Systems`, `Managers`. The
  `Systems` member is followed by `@odata.id` (no hard-coded `System.Embedded.1`).
  `SecureBoot`, `Bios` and the `@Redfish.Settings` link are read from the parent
  resources. URI resolution is cached per host.
- **Authentication**: `POST` on `Links.Sessions`, `X-Auth-Token` token,
  `DELETE` of the session at the end (`defer`). Falls back to HTTP Basic if session
  creation fails (401/403/404/405). The password never appears in logs.
- **Accepted responses**: 200, 201, 202, 204 (like `try_request`); other statuses
  → error `HTTP <code>: <body>`. Interpreting success is left to the driver
  (on Lenovo, a 200 can carry a failure in `ExtendedInfo`).
- **Sessions**: always released (`DELETE`). Supermicro documents a maximum of 16
  simultaneous sessions per BMC; a leaking session eventually blocks access.
- **ExtendedInfo**: the 3 case-insensitive, version-independent regexes
  (`^Base\.\d+\.\d+\.Success$`, `^i?DRAC\.\d+\.\d+\.SYS4\d+$`,
  `^Bios\.\d+\.\d+\.BiosPropertyModified$`); **a message of `Critical` severity is never
  a success** (`IDRAC.2.9.SYS403`, "resource not found", matches the `SYS4xx` pattern but
  is an error); "restart / reboot" detection in `Resolution`/`Message`.
- **ETag**: the `PATCH` is sent without `If-Match`; on `428 Precondition Required`,
  the resource is re-read, its `ETag` is taken and the request is retried (once).
- **Tasks**: on 202, follow `Location` as-is (opaque URI); honor
  `Retry-After`; state `New`/`Scheduled` with OK status = "pending
  reboot" success; `Completed` = success; `Exception`/`Killed` = failure. Maximum
  timeout `--task-timeout` (default 120 s). `--no-wait` disables tracking.
- **Redirects**: never followed (they could carry the token or the
  password to another host); a 3xx becomes an HTTP error.
- **Retries** (`--retries`, default 2, wait doubled on each attempt):
  connection drop on a read (GET/HEAD), and any "BMC busy" response
  (`ActionParameterValueConflict`, `UnableToModifyDuringSystemPOST`). A write is never
  replayed after a drop (it may have been applied), and neither is an authentication or
  certificate error. A `Retry-After` longer than the remaining time yields one last
  poll at the deadline.
- **Limits**: responses read up to 8 MiB; the body of an HTTP error is truncated to
  512 characters in reports.
- **TLS**: verification disabled by default (self-signed BMCs); `--verify-tls`
  and `--ca-file` to enable it. A warning on stderr reminds on every run
  that credentials may be intercepted on an untrusted network.

## 6. Platform detection

The platform is inferred from the Redfish data; the user does not enter it.
The `Platform` column of the result is computed, never read from the input CSV.

1. `GET /redfish/v1/` → `Vendor`. `Dell` → iDRAC family; `HPE` → `ilo`;
   `Lenovo` → `lenovo` (value confirmed by the XCC REST API Guide example);
   `Supermicro` → `supermicro` (**unconfirmed value**: the guide does not show
   the service root; the `--platform` override is provided for this case).
2. For Dell, `GET Managers/<id>` (member `ManagerType: BMC`) → `FirmwareVersion`:
   major version 1 → `idrac10`; major 3 to 7 → `idrac9`. `Model` (`16G…`, `17G…`)
   is read and reported, but is not the criterion.
3. `--platform auto|idrac9|idrac10|ilo|lenovo|supermicro` forces the choice (default `auto`).

Finding: `Vendor` (`Dell`) and `Product` (`Integrated Dell Remote Access Controller`)
are identical between iDRAC9 and iDRAC10 in the examples of the two OpenAPI specs; only
`FirmwareVersion` (`7.20.30.50` versus `1.30.60.50`) and `Model` (`16G` versus `17G
Monolithic`) distinguish them. These values come from the spec examples, not from a real
BMC. If `Vendor` is unknown or the version is unreadable, the host is reported
as an error `cannot detect platform (use --platform)`.

## 7. Per-driver behavior

### idrac9 (reference: Python script)
- `status`: `GET SecureBoot` (`SecureBootEnable`, `SecureBootCurrentBoot`,
  `SecureBootMode`, `Oem.Dell.Certificates`) + `SecureBootPolicy` read from
  `Bios?$select=Attributes/SecureBootPolicy`.
- `enable`/`disable`: `PATCH SecureBoot {"SecureBootEnable": bool}`; no
  re-read after the PATCH; new state = `Enabled|Disabled (Pending - Reboot Required)`
  if the message mentions restart/reboot.
- `set_policy_*`: `PATCH` on the BIOS Settings resource with
  `{"Attributes":{"SecureBootPolicy":P},"@Redfish.SettingsApplyTime":{"ApplyTime":"OnReset"}}`;
  guard: if Secure Boot is enabled and the mode ≠ `DeployedMode` → refuse. The
  "Custom requires Secure Boot enabled" guard from the changelog is **absent** from the current code; we
  follow the code. Success requires `Location` and a job identifier.
  **Idempotence fixed**: the script skips the write if the *applied* policy
  (`Bios`) already equals the target. However, another value may be *pending* in
  `Bios/Settings` (observed in the field by `bmclib`). The driver therefore also reads the pending
  value (`PendingPolicy`): success without a PATCH only if applied = target **and**
  no different value is pending; if a pending value already equals the target,
  "already pending" success without a new PATCH; otherwise PATCH.
- `db_list`: GET of the OEM `DB` store (`Oem.Dell.Certificates` link), fields
  `Certificates` or `Hash`.
- `db_import`: `POST multipart/form-data` (`file` field) on the OEM `DB` store.
  The OpenAPI spec describes a JSON body with `CryptographicHash` required, and the
  official Dell script sends a `text` part `{"CryptographicHash": ...}` along with the
  file (useful for `dbx` hashes). The production script only sends `file` and
  works for `db` certificates (changelog no. 4): we keep this multipart.
  Success = ExtendedInfo regex or HTTP 2xx. `--method standard` switches to the standard
  POST (see idrac10); `--method oem` is the default on iDRAC9.
- `db_export`: `GET` of the certificate URI with `Accept: application/octet-stream`,
  written in streaming mode to the file (bug no. 1).
- `db_delete`: `DELETE` of the certificate URI.
- `--cert-uri` goes through `sanitizeRedfishPath` (bug no. 5, kept for Git Bash).

### idrac10 (standard, based on the I10-1.10 OpenAPI and the Dell Ansible module)
- `status`: same resources as idrac9 (`SecureBoot`, `Bios`), the OpenAPI
  exposes them with `{ComputerSystemId}`; the identifier comes from discovery.
- `db_list`: standard collection `SecureBootDatabases/db/Certificates`; falls back to the
  Dell OEM store if the standard collection fails.
- `db_import`: JSON `POST` `{"CertificateString":"<PEM>","CertificateType":"PEM"}` on the
  `Certificates` collection of the `db` database, URI discovered through links (method of the Ansible
  module `idrac_secure_boot`, also used by `bmclib`). DER file converted to PEM.
- `db_delete`: `DELETE` of the certificate URI.
- `--method oem` switches to the OEM multipart (inherited from iDRAC9); default `standard`.
- OpenAPI finding: `SecureBoot.ResetKeys` only accepts `ResetAllKeysToDefault`,
  `DeleteAllKeys`, `DeletePK` (per database: the first two).
- `enable`, `disable`, `set_policy_*`, `db_export` and `reset_keys`: same resources
  as iDRAC9 (`SecureBoot` PATCH, `Bios/Settings` with `SecureBootPolicy`, `Certificates`
  collections, `ResetKeys`), checked in the 1.30 OpenAPI. Export reads
  `CertificateString` in the JSON resource; a response that contains only
  metadata (OEM `DellCertificate` resource) is an error.

### Other Secure Boot databases (ADR 0009)
- `--database db|KEK|PK|dbx` (default `db`). `db_list` and `db_import` target the chosen database;
  on Dell, any database other than `db` goes through the standard collections (the OEM multipart
  exists only for `db`).
- `dbx`: `db_list` counts the members of `Signatures`; `db_import --signature <sha256>
  [--signature-owner GUID]` adds a signature (POST `{SignatureString, SignatureType:
  EFI_CERT_SHA256_GUID, SignatureTypeRegistry: UEFI[, UefiSignatureOwner]}`). Format
  **not confirmed** by any BMC.
- Safeguards: PK, KEK and dbx require `--confirm`; PK and KEK also require `SetupMode` or
  `AuditMode`. Applies to `db_import` and to `db_delete` of a member under a `PK`, `KEK` or
  `dbx` path segment (the URI is normalised before it is checked and sent). `--dry-run`
  applies the same refusals. Resets (`reset_keys`, with or without `--database`) need
  `--confirm` only (ADR 0006, ADR 0009).
- `reset_keys --database X`: `SecureBootDatabase.ResetKeys` action of the database, types
  `ResetAllKeysToDefault` or `DeleteAllKeys` only.

### Features common to all drivers
- **Idempotent import**: before `db_import`, the database certificates are read and
  compared by SHA-256 (certificate text, otherwise the `Fingerprint` field if its algorithm
  is SHA-256). Already present: "already present", no POST. On the Dell OEM store,
  each entry is downloaded then compared. Unreadable or unknown: the import takes place.
- **`db_list`**: adds, when the BMC provides them, subject (CN) and expiration date.
  Only `Id`, `CertificateString` and `CertificateType` are assumed present.
- **`status`**: "not supported" when the `SecureBoot` resource is missing (404);
  "license required" on `OemLicenseNotPassed` (Supermicro).
- **`reset_keys`**: see ADR 0006. `--reset-type` and `--confirm` mandatory; type
  validated against `ResetKeysType@Redfish.AllowableValues`; a 202 response is followed.
- **`--dry-run`**: reads and validates everything, writes nothing. The result says what would change
  (`DRY RUN: would ...`); an invalid certificate file fails even in a dry run;
  `db_delete` checks that the certificate is in the database.

### ilo (standard Redfish, based on HPE docs)
- `db_list`: `GET SecureBootDatabases/db/Certificates`.
- `db_import`: JSON `POST` `{"CertificateString":"<PEM>","CertificateType":"PEM"}`.
  If the file is DER, converted to PEM client-side.
- `db_delete`: `DELETE` of `.../Certificates/{Id}`.
- `enable`/`disable`: `PATCH SecureBoot`; **to be validated** whether a reboot is required.
- Limits: 3 KiB per certificate (size check before sending); a `db` database that
  already contains 16 certificates refuses the import with a clear message, without a POST.
- `set_policy_*`: not supported (no Custom/Standard policy at HPE).

### lenovo (XCC, based on the XCC REST API Guide)
- Paths: `/redfish/v1/Systems/1/SecureBoot` (in practice followed through discovery).
- `status`: `GET SecureBoot` (`SecureBootEnable`, `SecureBootCurrentBoot`,
  `SecureBootMode` ∈ `UserMode|SetupMode|AuditMode|DeployedMode`). No
  `SecureBootPolicy`: the `Current Policy` column is `N/A`.
- `enable`/`disable`: `PATCH SecureBoot {"SecureBootEnable": bool}`. **Success is not
  read from the HTTP code**: the guide documents HTTP 200 in both cases.
  `@Message.ExtendedInfo` containing `RebootRequired` = "pending reboot" success;
  `PhysicalPresenceError` = failure ("Remote Physical Presence" not obtained); with no
  recognized message = "unknown response" failure. This rule is specific to the Lenovo driver.
- `ResetKeys` (`ResetAllKeysToDefault`, `DeleteAllKeys`, `DeletePK`) exists but is
  not exposed as an action in v1 (not in the reference script).
- `db_list`, `db_import`, `db_delete`: standard POST/DELETE on `SecureBootDatabases/db`
  (like `bmclib`). The XCC REST API Guide does not document them: **not validated**.
  Known prerequisite: the BIOS attribute `SecureBootConfiguration.SecureBootPolicy` must be
  "Custom Policy", otherwise XCC returns the Lenovo error `FQXSFPU4097G`. This attribute is
  not modifiable by the tool (accessibility through `/Bios` unconfirmed). A
  `FQXSFPU4097G` error is therefore reported with the hint "Secure Boot policy must be set to
  Custom Policy (UEFI setup or OneCLI)".
- `set_policy_*`: not supported.

### supermicro (based on the Redfish User Guide 1.22.2-00.04)
- `status`: `GET /redfish/v1/Systems/1/SecureBoot` (`SecureBootEnable`,
  `SecureBootCurrentBoot`, `SecureBootMode`). No `SecureBootPolicy`: `N/A`.
- `enable`/`disable`: `PATCH SecureBoot {"SecureBootEnable": bool}`, 200 response. The
  change is pending until reboot. Result: `Enabled|Disabled (Pending - Reboot
  Required)`, always: `Bios/SD` ("BIOS Configuration Pending Settings") is not read,
  because its Secure Boot attributes are not documented and a read could
  only produce a false "no reboot needed".
- `db_list`: `GET SecureBootDatabases/db/Certificates` (`db`, `dbt`, `dbr`, `KEK`, `PK`
  carry certificates; `dbx` carries signatures, not certificates).
- `db_import`: `POST SecureBootDatabases/db/Certificates` JSON
  `{"CertificateString":"<PEM>","CertificateType":"PEM"}`; success = HTTP 201 (any other
  2xx remains a success, with a note "HTTP n, the guide documents 201"). The guide
  illustrates import only for `dbt`; `db` is assumed identical. The DER file is
  converted to PEM client-side.
- `db_delete`: `DELETE` of the certificate URI (the guide lists GET/DELETE).
- The SecureBoot and BIOS URIs require the `SFT-DCMS-SINGLE` license; hardware
  prerequisite: X13/H13 or newer for `SecureBootDatabases`. A `403`/`404` on
  `SecureBoot` is reported with a reminder of the `SFT-DCMS-SINGLE` license and of the generation
  prerequisite.
- `set_policy_*`: not supported.
- `ResetKeys` (`ResetAllKeysToDefault`, `DeleteAllKeys`, `DeletePK`) exists, not exposed in v1.

## 8. CLI

```
sbmgr <command> -i nodes.csv -o out.csv [flags]        (ADR 0011)

Secure Boot:
  status | enable | disable
  policy custom|standard
  reset-keys   --reset-type TYPE [--database NAME] --confirm
                 (ResetAllKeysToDefault, DeleteAllKeys, DeletePK, ResetPK, ResetKEK, ResetDB,
                  ResetDBX; --confirm is not needed with --dry-run)
Certificate databases (group flags: --database NAME, --confirm):
  db list
  db import    --cert-file PATH | --signature SHA256 [--signature-owner GUID]
  db export    --cert-uri URI --cert-file PATH      (file name suffixed with the host IP)
  db delete    --cert-uri URI
Diagnostics:
  probe        [--probe-dump PATH]      read-only check of what each BMC answers (ADR 0007)
  version | completion bash|zsh|fish|powershell   (ADR 0008)

Flags of every command:
  -i, --input / -o, --output PATH      input CSV / result file
  -f, --format csv|json                output format (default csv)
  --dry-run                            write nothing, say what would change
  --platform auto|idrac9|idrac10|ilo|lenovo|supermicro
  --method oem|standard                Dell import/delete method (default: oem on iDRAC9, standard on iDRAC10)
  --concurrency N (20)  --timeout 30s  --retries N (2)  --task-timeout 120s  --no-wait
  --verify-tls  --ca-file PATH         TLS verification (off by default)
  -v, --verbose                        detailed logs (never any secret)
  --log-file PATH                      JSON-lines audit log, mode 0600 (ADR 0012)
  --version                            prints the version

Deprecated (hidden, for existing scripts): -a <action> with the per-action flags on the root
command; it prints the replacement command.
```

`--hashtype` is removed (never used in the script).

**CSV input**: `start_ip,end_ip,username,password` (BOM tolerated). `start_ip` and
`end_ip` may differ on any octet; `start_ip` may be a CIDR
(`end_ip` empty). Old files remain valid. A row cannot exceed
4096 addresses (clear error beyond that).

**CSV output**: the Python columns, in the same order (for the
`db_*` actions: `IP Address, Action, Success, Message, Error, Certificate Count`), plus a
final `Platform` column. Exit code 0 if everything succeeded, 1 if at least one host
failed or if a CSV row was skipped, 2 on a usage or input error
(unreadable file, no usable host).

## 9. Errors and security

- An error on one host never stops the others; it becomes a result line.
  An invalid CSV row is reported on stderr then skipped; empty or
  `,,,` rows are skipped, short rows are padded, duplicate addresses are processed only
  once (first credentials).
- A `Critical` message is a failure on **any** write, even in a 2xx response
  (enable, policy, import, delete, reset).
- A certificate file is limited to 64 KiB and must contain only valid
  `CERTIFICATE` blocks (a private key is refused). The `--cert-uri` of `db_export` and
  `db_delete` must target a `Certificates` collection.
- Texts coming from the BMC that start with `=`, `+`, `-` or `@` are prefixed with an
  apostrophe in the CSV (formula injection).
- The exported file is written with mode 0600.
- An `enable`/`disable` is always "pending reboot": `SecureBootEnable` only
  applies at the next boot, whatever the messages.
- Passwords and tokens are neither logged nor written to the output.
  (The Python script printed the input CSV rows, passwords included.)
- The input CSV file contains plaintext passwords: warning in the
  help if its permissions are wider than `0600` (Unix). Deliberate choice (owner's decision):
  no vault, environment variable or CSV encryption;
  the permissions warning is the only protection provided.
- `SYS011` ("Pending configuration values are already committed") is reported
  as-is: two pending BIOS changes require two reboot cycles.

## 10. Tests

- Fake BMC (`httptest`) per driver, with fixtures taken from the changelog
  (`Base.1.12.Success`, `IDRAC.2.9.SYS430`, `SYS011`, `Location` under
  `TaskService/Tasks/`, `Location` under `TaskMonitors/`).
- One test per changelog bug: non-empty export (no. 1), new pending-reboot
  state (no. 2), tracking of the supplied `Location` (no. 3), success regexes for all versions
  (no. 4), URI mangled by MSYS (no. 5), `set_policy_standard` (no. 6).
- Unit tests: IP expansion (same octet, multi-octet, CIDR), CSV reading
  with BOM, session (success, Basic fallback, logout), `428`/ETag, `Retry-After`.
- Golden files for the CSV and JSON.
- The two OpenAPI specs serve as a check: a test verifies that every path used
  by the `idrac9`/`idrac10` drivers exists in the corresponding spec (after
  substituting the path variables).
- Multi-OS build: `make build-all` (linux/amd64, windows/amd64, darwin/arm64).
- **No hardware validation in this project.** Recommended first trials on
  a test server: `status`, then `db_list`, before any write.

## 11. Unvalidated points (to be confirmed on hardware)

1. Detection: `Vendor` and `FirmwareVersion` are taken from the Dell OpenAPI examples;
   the iDRAC9 firmware ranges (3 to 7) and the Supermicro `Vendor` value remain to be
   confirmed on real BMCs. **Observed**: a captured HPE iLO 7 tree (ProLiant DL360 Gen12,
   from HPE's `ilo-redfish-emulator`, BSD-3-Clause, embedded in `internal/testbmc/testdata`)
   reports `Vendor` = `HPE`, so detection of iLO from `Vendor` is confirmed on that
   capture (the data comes from an emulator project, not from a BMC the tool talked to).
2. iDRAC10: import and delete through the standard POST/DELETE follow the Dell Ansible module
   and `bmclib` but are not validated on hardware; the body schema is not
   documented in the Dell OpenAPI. The OEM multipart fallback (`--method oem`) is not
   documented for iDRAC10 either.
3. iLO: accepted certificate format (PEM only or DER), reboot after import.
4. iDRAC9: whether `--method standard` works on the fleet firmware (the standard
   POST is in the 7.00 OpenAPI but its body is not described there): to be tested before
   making it the default.
5. Lenovo: `db` import through the standard POST (`bmclib`) is not in the XCC guide provided;
   the "Custom Policy" condition and the `FQXSFPU4097G` code come from `bmclib`. The
   behavior of `PhysicalPresenceError` (RPP) remains to be observed on hardware.
   Supermicro: `Vendor` value, import into `db` (guide example limited to `dbt`),
   per-database limits, DCMS license requirement and minimum BMC generation.
6. Removal of the "Custom requires Secure Boot active" guards: firmware behavior
   to be confirmed.
7. Implementation status: the code and its tests (fake BMC, Dell OpenAPI specs) are in place;
   the whole remains not validated on hardware. Recommended trial order: `status`, `db_list`,
   then a write on a test server.
8. Other databases (ADR 0009): the POST body on `Signatures` (dbx) reuses the DMTF names and
   is confirmed by no BMC; the actual BMC behavior for PK and KEK writes
   (often reserved for a signed request in User mode) remains to be observed; the list of
   databases and their actions is read first with `sbmgr probe`.
9. Observed on the iLO 7 capture (read-only integration tests, `internal/probe`): certificates
   carry `CertificateString`, `Subject`, `Issuer` and `ValidNotAfter` but no `Fingerprint`, so
   idempotent import must compare the PEM text (it does); `SecureBoot.ResetKeys` exists with no
   `AllowableValues` (the allowed-value check then passes any type and the BMC decides); the
   databases `PK`, `KEK`, `db`, `dbx`, `dbt`, `dbr` and their `*Default` counterparts are all
   exposed. Write behaviour (import, delete, reset) is still not observed.
