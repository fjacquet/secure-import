# 0006 — `reset_keys`: a destructive action, explicit and confirmed

- Status: accepted
- Date: 2026-10-05

## Context

Research (sushy, gofish, the Lenovo XCC guide, the Dell OpenAPI) shows a standard action
`#SecureBoot.ResetKeys` (`POST SecureBoot/Actions/SecureBoot.ResetKeys`, body
`{"ResetKeysType": ...}`). The common values are `ResetAllKeysToDefault`,
`DeleteAllKeys` and `DeletePK`; the BMC advertises the permitted list in
`ResetKeysType@Redfish.AllowableValues`. `DeleteAllKeys` and `DeletePK` put the system
in "Setup Mode": Secure Boot stops protecting the server. Yet this is the only escape
hatch when a `db` has been populated incorrectly. Ironic exposes these operations with a
priority of zero: they run only on an explicit request from the operator.

## Decision

- New action `reset_keys`, never implicit.
- `--reset-type` is mandatory, limited to `ResetAllKeysToDefault`, `DeleteAllKeys`, `DeletePK`
  (DMTF values, identical in the iDRAC10 1.30 OpenAPI) and `ResetPK`, `ResetKEK`, `ResetDB`,
  `ResetDBX` (documented by the iDRAC9 7.00 OpenAPI; `ResetDB` only touches `db`), then
  validated against the BMC's `AllowableValues` when it advertises any. A 202 response is
  followed until the task completes; a failure or an unverified task is an error.
- `--confirm` is mandatory: without it, the tool refuses. `--dry-run` shows what would be done.
- The action is looked up in `Actions` of the `SecureBoot` resource; its absence is an
  "unsupported" error, not a guessed URI.
- Success is read from `ExtendedInfo` (ADR 0004), as for any write; the tool does not
  reboot.

## Consequences

- An operator can recover a corrupted `db` without going through the BMC interface.
- The risk (Setup Mode) is written in the command help and in the README.
- Behavior not validated on hardware, including on iDRAC9 and iDRAC10: the production scripts do not cover it.
