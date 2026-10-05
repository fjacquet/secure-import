# 0004 — Success read from `@Message.ExtendedInfo`, not from the HTTP code

- Status: accepted
- Date: 2026-10-05

## Context

The Python script treats HTTP 200/202/204 as success (`try_request`), then looks for
specific `MessageId` values. The changelog shows that `MessageId` values vary with the firmware
(`Base.1.0.Success` versus `Base.1.12.Success`, `iDRAC.1.6.SYS413` versus
`IDRAC.2.9.SYS430`) and that this produced false failures. The Lenovo XCC guide goes
further: `PATCH SecureBoot` and `ResetKeys` return **HTTP 200 in all cases**.
`RebootRequired` means success; `PhysicalPresenceError` means failure.

## Decision

The Redfish client accepts 200, 201, 202 and 204 as valid responses, but **does not
decide** on success: each driver interprets the response.

- Dell: case-insensitive, version-independent regexes
  (`^Base\.\d+\.\d+\.Success$`, `^i?DRAC\.\d+\.\d+\.SYS4\d+$`,
  `^Bios\.\d+\.\d+\.BiosPropertyModified$`), falling back to the HTTP status. A message of
  `Critical` severity is never a success: the `SYS4xx` pattern also matches
  `IDRAC.2.9.SYS403` ("resource not found"), an error that the Python script could
  mistake for a success.
- Lenovo: `RebootRequired` = success pending reboot; `PhysicalPresenceError` =
  failure; unknown message = "unknown response" failure.
- Supermicro: 201 expected for the import; pending change read from `Bios/SD`.
- A 202 task is followed via its `Location`; `New`/`Scheduled` mean "pending
  reboot", `Exception`/`Killed` mean failure.

## Consequences

- No false success on Lenovo, no false failure on recent Dell firmware.
- Each driver must be tested with its real responses (fixtures from the changelog and the guides).
- Unknown is an explicit failure: a false negative is preferred over a false success on a
  security change.
