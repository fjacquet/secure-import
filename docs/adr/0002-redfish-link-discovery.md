# 0002 — Redfish link discovery, no hardcoded URIs

- Status: accepted
- Date: 2026-10-05

## Context

The Python script hardcodes `System.Embedded.1`, `Bios/Settings` and the OEM path
`SecureBoot/Oem/Dell/Certificates/DB`. The changelog shows the cost: task tracking
broke (404) because the `TaskMonitors/` path was assumed while the firmware returned
`Tasks/`. The DMTF DSP0266 1.14 spec forbids such assumptions:
"Clients shall not make assumptions about the URIs for the members of a resource
collection". The Dell iDRAC9 and iDRAC10 OpenAPI specs use `{ComputerSystemId}`.

## Decision

Everything starts from `/redfish/v1/` and follows the `@odata.id` links: `Links.Sessions`, `Systems` (the
member is discovered), `SecureBoot`, `Bios` and its `@Redfish.Settings` link. The
`Location` of a 202 response is followed as-is and treated as opaque. Resolutions
are cached per host. A hardcoded path is only a fallback, never the nominal path.

## Consequences

- Robust to firmware changes and to iDRAC10 (system identifier not fixed).
- One extra discovery request per host at startup.
- A BMC that does not publish an expected link produces an explicit error, not an obscure 404.
- Fake BMC tests must expose these links (complete fixtures from the root).
