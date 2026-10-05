# 0005 — Dell: OEM import on iDRAC9, standard on iDRAC10

- Status: accepted
- Date: 2026-10-05

## Context

The production script imports a certificate as `multipart/form-data` (`file` field) into
the OEM store `SecureBoot/Oem/Dell/Certificates/DB/`. The Dell OpenAPI nevertheless describes this
POST as JSON with `CryptographicHash` required, and both the iDRAC9 7.00 and the iDRAC10 OpenAPI
also expose `SecureBootDatabases/{id}/Certificates` (POST, DELETE).

Existing projects (GitHub search) point to the standard path:

- the official Ansible module `dellemc.openmanage.idrac_secure_boot` sends
  `{"CertificateString": "<PEM>", "CertificateType": "PEM"}` to the database's `Certificates`
  collection, with the URI discovered via links, and supports iDRAC10 (17G);
- `bmclib` imports a certificate the same way on all vendors.

The production script, for its part, is proven on the user's fleet using OEM multipart.

## Decision

- iDRAC9: OEM multipart by default (behavior proven in production).
- iDRAC10: standard POST/DELETE by default (the Dell Ansible module's method, the only one
  documented for this generation).
- `--method oem|standard` forces the other path on Dell.

## Consequences

- No behavior change for the current iDRAC9 fleet.
- iDRAC10 writes rely on Dell documentation, not on a hardware test: they are
  marked not validated on hardware (spec §11).
- To be tested on a test iDRAC9: if `--method standard` works, standard could
  become the default and the OEM path a fallback.
- The Dell script also sends `CryptographicHash` (useful for `dbx` hashes); out of scope
  as long as only the `db` database is targeted.
