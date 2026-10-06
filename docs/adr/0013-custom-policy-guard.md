# 0013 — Custom policy refused while Secure Boot is disabled

- Status: accepted
- Date: 2026-10-06

## Context

The Python script for iDRAC10 used in production refuses `set_policy_custom` when Secure
Boot is disabled, and offers `--allow-custom-when-disabled` to override. The iDRAC9
script, which the Go port started from, had no such guard, so `sbmgr policy custom`
changed the policy on a machine whose Secure Boot was off.

## Decision

- `policy custom` (and the deprecated `-a set_policy_custom`) fails with
  `Cannot set Custom policy: Secure Boot is disabled (use --allow-custom-when-disabled to override)`
  when Secure Boot is disabled, unless `--allow-custom-when-disabled` is given.
- The check runs before the idempotence check and also applies to `--dry-run`.
- `policy standard` is not affected. The existing `DeployedMode` guard is unchanged.

## Consequences

- A command that used to succeed on a host with Secure Boot disabled now reports an
  error for that host; scripts that rely on it add the flag.
- Behavior now matches the validated production script on both iDRAC generations.
