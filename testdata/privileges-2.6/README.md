# Privileges 2.6 webhook bodies

Bodies SAP Privileges 2.6.0 sent on macOS 26, captured on a test Mac with a listener standing
in for the relay. The user name, the Mac's hardware UUID and the reason text are replaced; the
rest is byte for byte what Privileges sent: one compact JSON object, keys sorted.

| Key | JSON type | Value |
|---|---|---|
| `admin` | boolean | whether the user is in the admin group when the event is created |
| `custom_data` | object | the profile's `WebhookCustomData`, on grants and revokes alike; left out when that is empty |
| `delayed` | boolean | true when the event is sent more than 5 seconds after `timestamp`. Privileges works it out when it sends, so a queued event arrives with `true` |
| `event` | string | `corp.sap.privileges.granted` or `corp.sap.privileges.revoked` |
| `expires` | string | ISO 8601 in UTC, or `""` when there is no expiry (always `""` on a revoke) |
| `machine` | string | the Mac's hardware UUID, or `""` if it couldn't be read |
| `reason` | string | the user's reason; `requested by user` or `privileges expired` on a revoke; `""` if none |
| `timestamp` | string | ISO 8601 in UTC, whole seconds, when the event was created |
| `user` | string | the console user's short name |

| File | Change |
|---|---|
| `grant-with-reason.json` | a grant with a reason |
| `revoke-manual.json` | the user gave admin back |
| `revoke-expired.json` | the grant expired (sent a second after `expires`) |
| `grant-delayed.json` | a grant Privileges couldn't deliver at first, sent later from its queue |

What else the captures showed:

- The request is `POST`, `Content-Type: application/json;charset=utf-8`, with a
  `PrivilegesAgent/<build>` User-Agent, and presents the client certificate whose issuer
  matches a CA name the server lists.
- Any HTTP answer, a 503 included, counts as delivered. Privileges keeps an event and sends it
  again only when the connection fails (TLS failure, no answer): after 5, 15 and 30 minutes,
  then about hourly, and first thing at the next change, oldest first.
- After a dropped connection the same body can arrive twice within a second, so the relay
  stores a resend under the same `metadata.uid` once.
