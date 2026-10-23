# altiward-forwarder

Forward SAP Privileges events to Splunk, Sentinel or syslog, from a relay or straight from the
Mac. Works with SAP Privileges.

Each time someone gains or gives up admin rights through
[SAP Privileges](https://github.com/SAP/macOS-enterprise-privileges), the forwarder sends your
SIEM an OCSF record: the same record the [Altiward](https://github.com/Altiward/altiward) server
emits for that change. So the [altiward-siem](https://github.com/Altiward/altiward-siem)
detections, the Sentinel workbook and the Splunk dashboard work with both.

**Status:** 0.1.0, the first [release](https://github.com/Altiward/altiward-forwarder/releases)
of both the relay (`v0.1.0`) and the hook (`hook-v0.1.0`).

## Choose how to forward

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/forwarding-dark.svg">
  <img src="docs/images/forwarding-light.svg" width="1000" alt="Two options; use one or the other. The relay: SAP Privileges on each Mac sends a webhook for each change, over HTTPS with a client certificate, and queues what it can't send. The relay, on your host, checks each Mac's certificate, maps each change to OCSF and stores it on disk before it answers, then sends it to Splunk, Microsoft Sentinel or syslog as OCSF or CEF over HTTPS or TLS. Or the on-Mac hook: SAP Privileges runs the hook as the user on each change. The hook checks the admin group, queues events until they are sent, and sends OCSF over HTTPS straight from each Mac to Splunk, Microsoft Sentinel or an HTTPS webhook, with the SIEM token on every Mac.">
</picture>

| | Privileges' own syslog | The relay | The on-Mac hook |
|---|---|---|---|
| What runs where | Nothing to install: Privileges sends syslog itself | A small container you host; each Mac's Privileges sends it a webhook | A binary on each Mac, run by Privileges after each change |
| Destinations | Syslog only, Privileges' own format | Splunk, Sentinel, syslog, stdout | Splunk, Sentinel, an HTTPS webhook |
| Event format | Privileges' log line | OCSF, as Altiward's | OCSF, as Altiward's |
| Expiry time | | Yes | No |
| Offline Macs | Privileges can queue | Privileges queues and resends; the relay keeps what it has accepted on disk | The hook queues and resends every 5 minutes |
| SIEM credentials | | On the relay only | On every Mac |
| Alongside the Altiward agent | Yes | Yes | No: both use Privileges' one hook setting |

## Quick start: the relay

1. Get certificates. You provide them; the forwarder doesn't ship any. You need a server
   certificate for the relay, and a client certificate on each Mac from a CA you choose.
   Privileges can't send a token, so the client certificate is how the relay knows a Mac. If
   your Macs already have device certificates for Wi-Fi or VPN, those usually work as they
   are. [Certificates](docs/configuration.md#certificates) says what you need and where each
   goes; for a first look, [throwaway ones](docs/configuration.md#trying-it-with-a-throwaway-ca)
   can be made with `openssl`. If your Macs can't have certificates,
   [a secret in the URL](docs/configuration.md#with-a-secret-in-the-url) is a weaker fallback.
2. Put [deploy/compose.yaml](deploy/compose.yaml) on a host the Macs can reach, with the
   certificates in `certs/` and a `.env` naming the version and your SIEM:

   ```sh
   FORWARDER_VERSION=0.1.0
   FORWARDER_SPLUNK_HEC_URL=https://splunk.example.com:8088
   FORWARDER_SPLUNK_HEC_TOKEN=…
   ```

   Then `docker compose up -d`. Every setting is in
   [docs/configuration.md](docs/configuration.md).
3. Deploy [profiles/altiward-forwarder-privileges-webhook.mobileconfig](profiles/altiward-forwarder-privileges-webhook.mobileconfig)
   through your MDM, with your relay's address and certificates filled in. It turns on
   Privileges' webhook, and its queue for events it couldn't send.

The relay stores each event on disk before it answers Privileges, and answers nothing at all
when it can't store one, so Privileges keeps the event and sends it again. How that works, and
the fields of each record, are in [docs/design.md](docs/design.md).

## Quick start: the on-Mac hook

1. Get a SIEM token that can only send events: a Splunk HEC token limited to one index, a
   Sentinel app registration whose only role is Monitoring Metrics Publisher on the data
   collection rule, or a webhook token that can only post. It goes on every Mac, where any
   local user can read it.
2. From the hook's GitHub release, deploy these through your MDM:
   - `Altiward-Forwarder-<version>.pkg`, the signed and notarized hook, with a LaunchAgent
     that resends anything queued;
   - `altiward-forwarder-hook-settings.mobileconfig`, with your destination and token filled
     in, for example `SplunkHECURL` and `SplunkHECToken`;
   - `altiward-forwarder-privileges-hook.mobileconfig`, which makes Privileges run the hook.
     Use the copy from the same release: Privileges runs the hook only when it matches the
     checksum in it;
   - `altiward-forwarder-login-items.mobileconfig`, so users can't turn the LaunchAgent off.
3. On one Mac, send a test event to each destination:

   ```sh
   "/Library/Application Support/Altiward Forwarder/Altiward Forwarder.app/Contents/MacOS/altiward-forwarder-hook" --test
   ```

   It prints `sent`, or the error, for each.

A Mac runs either the hook or the Altiward agent: both use Privileges' one post-change
setting. Every setting, and how the hook checks and queues each change, is in
[docs/hook.md](docs/hook.md).

## What this can't tell you

- **The events are the Mac's own report.** Nothing checks them, so every record says
  `unmapped.altiward.verified: false`. A local admin can stop Privileges from reporting.
- **Changes made outside Privileges** show up only as Privileges' "changed by another process"
  report, and only while Privileges' agent runs.
- **Grants and revokes aren't paired into sessions**, so the Sentinel workbook's session views
  show them as separate events.

For verified records, run the [Altiward agent](https://github.com/Altiward/altiward): it
watches the admin group itself, reports changes Privileges didn't make, and can remove admin
rights that outlive their expiry. The relay and the agent can run on the same Macs.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately, as the
[security policy](https://github.com/Altiward/.github/blob/main/SECURITY.md) describes.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). SAP and SAP Privileges are
trademarks of SAP SE; this project isn't affiliated with or endorsed by SAP.
