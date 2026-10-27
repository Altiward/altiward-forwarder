# Changelog

User-facing changes to the relay (`altiward-forwarder`, released as `vX.Y.Z`) and the on-Mac
hook (`altiward-forwarder-hook`, released as `hook-vX.Y.Z`). A release needs its section dated
(`## Relay X.Y.Z - YYYY-MM-DD`) with a `### Changes` heading; `scripts/release-notes.sh`
checks.

## Relay 0.9.0 - 2026-10-27

### Changes

- The version moves from 0.1.0 to 0.9.0 to match Altiward server, agent and altiward-siem
  0.9.0. Nothing else follows from the jump.
- Splunk delivery requires an explicit accepted HEC acknowledgement. Redirects, HTML,
  incomplete or invalid responses leave records queued and report a delivery error.
- Event identifiers preserve subsecond timestamps, separate configured sites and distinguish
  changes in reason, expiry or custom data within a whole second. Exact retries still share
  an identifier, including delayed delivery. Newly generated identifiers change after the
  upgrade; queued records retain their identifiers. See [delivery](docs/design.md#delivery)
  for SIEM deduplication at the upgrade boundary and the limit for identical webhook reports.

## Hook 0.9.0 - 2026-10-27

### Changes

- The version moves from 0.1.0 to 0.9.0 to match Altiward server, agent and altiward-siem
  0.9.0. Nothing else follows from the jump.
- Splunk delivery requires an explicit accepted HEC acknowledgement. Redirects, HTML,
  incomplete or invalid responses leave records queued and report a delivery error.
- Every observed membership transition receives its own identity before queuing, so repeated
  clock values cannot merge separate changes. Resending a queued record retains its identity.

## Relay 0.1.0 - 2026-10-21

### Changes

- First release. Takes SAP Privileges' webhook and forwards each change to Splunk, Microsoft
  Sentinel, syslog or stdout as the same OCSF records the Altiward server emits.
- Stores every event on disk before answering, so an event Privileges has handed over survives
  a SIEM outage or a restart of the relay.
- Requires each Mac's client certificate, either itself or through a proxy's
  `X-Forwarded-Client-Cert` header.

## Hook 0.1.0 - 2026-10-21

### Changes

- First release. Runs as SAP Privileges' post-change executable and sends each change straight
  from the Mac to Splunk, Microsoft Sentinel or an HTTPS webhook, as the same OCSF records the
  Altiward server emits.
- Reports the user's real admin membership, not what it was told, and only when it changes.
- Queues events it can't send and resends them every 5 minutes.
- Installs as Altiward Forwarder, the name macOS and Privileges show, with a profile that makes
  its background item managed, and a `TrustedCAs` setting for destinations with private
  certificates.
