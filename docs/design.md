# How altiward-forwarder works

altiward-forwarder turns SAP Privileges' own reports of admin-rights changes into the OCSF
records the [Altiward](https://github.com/Altiward/altiward) server emits, and sends them to a
SIEM. It has two ways in: a relay for Privileges' webhook, and a hook that runs on the Mac.

## The relay

```
Mac: Privileges ──webhook (mTLS)──▶ relay ──▶ spool/splunk/   ──▶ Splunk
                                         ├──▶ spool/sentinel/ ──▶ Sentinel
                                         └──▶ spool/syslog/   ──▶ syslog
```

### Delivery

Privileges treats any HTTP answer, even a 503, as delivered. It keeps an event and sends it
again only when the connection itself fails: it can't reach the relay, TLS fails, or the
connection closes without an answer. It retries after 5, 15 and 30 minutes, then hourly, and
on the next change. So the relay never relies on an error status:

1. It decodes the body and maps it to an OCSF record.
2. It writes the record into each destination's spool directory and syncs it to disk.
3. Only then does it answer `202`.

If it can't store the event (a spool is full, or the disk fails), it closes the connection
without answering, so Privileges keeps the event queued. The relay speaks HTTP/1.1 only, so
that's always a closed connection rather than a reset HTTP/2 stream. A body that isn't a Privileges event
gets a `400` and is kept under `<spool>/rejected/` for a person to look at, because Privileges
won't send it again.

Each destination has its own spool and its own sender, so one SIEM being down doesn't hold up
the others. A sender sends the oldest records first, deletes each only after the SIEM accepted
it, and waits 30 seconds after a failure, doubling up to an hour. A record that can't be read
back is renamed `<uid>.json.corrupt`, logged, counted in `/healthz`, and skipped.

Each record's `metadata.uid` is a UUID derived from a versioned structured identity: the
source, tenant, URL-secret name (when used), Mac, user, change, full timestamp precision,
reason, expiry and custom data. Secret values never enter the identity, and rotating a URL
secret under the same name keeps retry IDs stable. Keep each independent site's name stable
and unique. Receipt time, product version and the `delayed` flag are excluded, so a delayed
retry and reordered JSON object keys keep the same ID. A change Privileges sends again while
the first copy is still queued is stored once. Delivery is
at least once, though: if the relay's answer is lost after the event reached a SIEM,
Privileges sends it again and the SIEM gets a second copy with the same `metadata.uid`
(`EventUid` in Sentinel). Deduplicate on that ID where it matters.

Privileges' webhook has no occurrence ID. Two reports with identical source fields and
timestamps are indistinguishable from a retry, even if two real changes happened in the same
whole second. They share an ID. Different reasons, expiries or custom data distinguish
whole-second reports; fractional timestamps keep all source precision, even though OCSF's
`time` field has milliseconds. The on-Mac hook adds a fresh random transition identity before
queuing each observed membership change, so a frozen or repeated clock value cannot merge
separate changes. Sending a queued record again preserves its stored ID.

Run one relay per spool. Two relays sharing a spool directory would send the same events
twice.

### Authentication

Privileges can authenticate its webhook only with a client certificate. The relay requires one
issued by a CA you choose, either in its own TLS handshake or, behind a proxy that terminates
TLS, from the proxy's `X-Forwarded-Client-Cert` header. It checks the chain, the dates and
the client-authentication usage itself in both cases, and a request that fails gets no answer,
so Privileges keeps the event. Where Macs can't have certificates, the relay can instead take a
secret in the URL path, which any user on the Mac can read: weaker, and offered as a fallback.
See [configuration.md](configuration.md#how-macs-authenticate).

## The event

Each change becomes one OCSF 1.9.0 User Access Management record (`class_uid` 3005): Assign
Privileges (`activity_id` 1) for a grant, Revoke Privileges (2) for a revoke. It has the same
fields, with the same meanings, as the Altiward server's record for the same change, so
detections, the Sentinel workbook and the Splunk dashboard work for both. A test compares the
two field by field.

| Field | Value |
|---|---|
| `time` | when Privileges made the change (epoch milliseconds) |
| `metadata.uid` | a stable ID for the change |
| `metadata.logged_time` | when the relay received it |
| `metadata.labels` | `["delayed"]` when Privileges queued the event and sent it later |
| `metadata.product` | `Altiward Forwarder`, vendor `Altiward`, and the forwarder's version |
| `device.uid` | the Mac's hardware UUID |
| `device.hw_info.serial_number`, `device.hostname`, `device.os.version` | from the hook only; the webhook doesn't send them |
| `user.name` | the user's short name |
| `unmapped.altiward.event_type` | `elevation.granted` or `elevation.revoked` |
| `unmapped.altiward.source` | `privileges`: Privileges made the change |
| `unmapped.altiward.reported_by` | `privileges_webhook` or `privileges_hook`: how the forwarder heard about it |
| `unmapped.altiward.verified` | always `false` (see below) |
| `unmapped.altiward.url_secret_name` | with [URL secrets](configuration.md#with-a-secret-in-the-url) only: the name of the secret the Mac sent |
| `unmapped.altiward.reason`, `expires_time` | the user's reason, and when the rights expire, when Privileges reports them |
| `unmapped.altiward.custom_data` | the profile's `WebhookCustomData`, as sent |

Severity is Informational. Syslog carries the record as CEF or as the JSON record; the CEF
fields match the Altiward server's.

## What it can't tell you

- **Every event is the Mac's own report.** The forwarder can't check it, so events are marked
  `verified: false`. A local admin can stop Privileges reporting, and a change made outside
  Privileges shows up only as Privileges' "changed by another process" report, if Privileges'
  agent is running to notice it.
- **There's no session ID**, so grants and revokes aren't paired the way Altiward pairs them.
- The [Altiward agent](https://github.com/Altiward/altiward) watches the admin group itself and
  reports changes Privileges didn't make. It uses Privileges' post-change hook, a different
  setting from the webhook, so the relay and the agent can run on the same Macs.

## The on-Mac hook

For teams with nothing to host, `altiward-forwarder-hook` runs as Privileges' post-change
executable and sends events straight from the Mac. It checks the user's real admin membership,
queues each event before sending it and removes it once a destination accepts it, and reports
`reported_by: privileges_hook`. It can't know when the
rights expire, the SIEM credentials sit on every Mac, and it uses the same hook setting as the
Altiward agent, so a Mac can run one or the other.
