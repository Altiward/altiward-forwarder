# Changelog

User-facing changes to the relay (`altiward-forwarder`, released as `vX.Y.Z`) and the on-Mac
hook (`altiward-forwarder-hook`, released as `hook-vX.Y.Z`). A release needs its section dated
(`## Relay X.Y.Z - YYYY-MM-DD`) with a `### Changes` heading; `scripts/release-notes.sh`
checks.

## Relay 0.1.0 - unreleased

### Changes

- First release. Takes SAP Privileges' webhook and forwards each change to Splunk, Microsoft
  Sentinel, syslog or stdout as the same OCSF records the Altiward server emits.
- Stores every event on disk before answering, so an event Privileges has handed over survives
  a SIEM outage or a restart of the relay.
- Requires each Mac's client certificate, either itself or through a proxy's
  `X-Forwarded-Client-Cert` header.

## Hook 0.1.0 - unreleased

### Changes

- First release. Runs as SAP Privileges' post-change executable and sends each change straight
  from the Mac to Splunk, Microsoft Sentinel or an HTTPS webhook, as the same OCSF records the
  Altiward server emits.
- Reports the user's real admin membership, not what it was told, and only when it changes.
- Queues events it can't send and resends them every 5 minutes.
- Installs as Altiward Forwarder, the name macOS and Privileges show, with a profile that makes
  its background item managed, and a `TrustedCAs` setting for destinations with private
  certificates.
