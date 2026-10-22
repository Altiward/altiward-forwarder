# The on-Mac hook

`altiward-forwarder-hook` sends SAP Privileges events straight from each Mac, for teams with no
server to run the relay on. Privileges runs it after each grant and revoke; it sends the change
to Splunk, Microsoft Sentinel or an HTTPS webhook as an OCSF record.

[The relay](../README.md#quick-start-the-relay) is the other option. It needs a host, but it
gets the expiry time, keeps SIEM credentials off the Macs, and works alongside the Altiward
agent. The hook needs nothing hosted and no certificates.

## What it does with each change

1. **Checks the real membership.** Privileges runs the hook as the logged-in user, and anyone
   can run it by hand with any arguments. So it refuses a call naming a user other than the
   one running it, and asks Directory Services whether the user is in the admin group. If the answer disagrees with what Privileges said, it checks again
   after a second, and reports what it finds.
2. **Skips what it already reported.** If the user's membership is the same as last time,
   it sends nothing.
3. **Queues the event**, in `~/Library/Application Support/com.altiward.forwarder/queue/`,
   before trying to send it, so it isn't lost if the hook is stopped mid-send.
4. **Sends one attempt** within 4 seconds of starting, and removes the event from the queue
   once the destination accepts it. The process ends within 5 seconds whatever happens.
   A LaunchAgent sends what's left in the queue at login and every 5 minutes, oldest first,
   deleting each event only after the destination accepted it. It also refreshes the user's
   remembered membership, so a change made outside Privileges doesn't hide the next one.

Each record is marked `reported_by: privileges_hook` and `verified: false`, and carries the
Mac's serial number, host name and macOS version. It has no expiry time: Privileges doesn't
pass it to the hook.

## Installing it

Deploy four things through your MDM, all from the hook's GitHub release:

1. **`Altiward-Forwarder-<version>.pkg`**, signed with Developer ID and notarized. It installs
   `Altiward Forwarder.app` in `/Library/Application Support/Altiward Forwarder/`, and the
   LaunchAgent `com.altiward.forwarder.flush`, which macOS lists as Altiward Forwarder under
   Login Items & Extensions.
2. **`altiward-forwarder-hook-settings.mobileconfig`**, with your destination filled in (the
   `com.altiward.forwarder` settings, below).
3. **`altiward-forwarder-privileges-hook.mobileconfig`**, which points Privileges' `PostChangeExecutablePath` at
   the hook (Privileges shows it as Altiward Forwarder), with `PassReasonToExecutable`. Use
   the copy from the same release: its `PostChangeExecutableChecksum` is that build's
   SHA-256, and Privileges runs the hook only when the file matches.
4. **`altiward-forwarder-login-items.mobileconfig`**, which marks the LaunchAgent as managed, so users
   can't turn it off and see no "background items added" notification. macOS accepts it only
   from an MDM.

Privileges passes the hook a reason only when it requires one, so we suggest setting
`ReasonRequired` (and `ReasonMinLength`) in your Privileges profile if you want reasons in your
SIEM.

Privileges has one post-change setting, and the Altiward agent uses it too. A Mac runs either
the hook or the Altiward agent. Installing the agent's profile replaces the hook, and the
records carry on in the same format.

## Settings

Set in the `com.altiward.forwarder` domain, normally by
[profiles/altiward-forwarder-hook-settings.mobileconfig](../profiles/altiward-forwarder-hook-settings.mobileconfig):

| Key | |
|---|---|
| `SplunkHECURL`, `SplunkHECToken` | Splunk HTTP Event Collector |
| `SentinelEndpoint`, `SentinelDCRID`, `SentinelStream`, `SentinelTenantID`, `SentinelClientID`, `SentinelClientSecret` | Sentinel's Logs Ingestion API, with an app registration's client secret. `SentinelStream` defaults to `Custom-AltiwardOCSF`, the Altiward table's stream |
| `WebhookURL`, `WebhookHeaders` | An HTTPS endpoint that takes a JSON array of records, with any headers it needs |
| `TrustedCAs` | PEM text of CA certificates to trust, besides the system's, when a destination's certificate comes from a private CA, as an on-premises Splunk's often does. A CA that macOS trusts isn't enough on its own: the hook checks certificates with Go, which doesn't follow every macOS trust setting |
| `QueueMax` | Events kept per destination while it can't be reached (default 500). Beyond that the oldest are dropped, and the next event sent says how many in `unmapped.altiward.dropped_before` |

**Any local user can read these settings**, so use credentials that can only write events: an
HEC token limited to one index, a Sentinel app registration whose only role is Monitoring
Metrics Publisher on the one data collection rule, or a webhook token that can only post.

## Checking it

```sh
"/Library/Application Support/Altiward Forwarder/Altiward Forwarder.app/Contents/MacOS/altiward-forwarder-hook" --test
```

sends one event, marked `unmapped.altiward.test: true`, to each destination now and prints
`sent` or the error for each. `--flush` sends the queue by hand.

## Removing it

```sh
sudo "/Library/Application Support/Altiward Forwarder/uninstall.sh"
```

removes the hook and its LaunchAgent and keeps each user's queue; `--purge` deletes the queues
too. Remove `altiward-forwarder-privileges-hook.mobileconfig` as well, or Privileges will try to run a file that's
gone.
