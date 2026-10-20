# Configuring the relay

The relay reads its settings from `FORWARDER_*` environment variables. With
[`deploy/compose.yaml`](../deploy/compose.yaml) they go in a `.env` file next to it. The SIEM
settings match the Altiward server's (`ALTIWARD_*` there), so both can share one SIEM setup.

## How Macs authenticate

Privileges can't send a password or token with its webhook, only a client certificate, so the
relay identifies Macs by certificate. Where Macs can't have one, a secret in the URL is a
weaker fallback. Choose one mode:

| Mode | When | Settings |
|---|---|---|
| Direct (default) | The relay is reachable from the Macs and terminates TLS itself | `FORWARDER_TLS_CERT_FILE`, `FORWARDER_TLS_KEY_FILE`, `FORWARDER_CLIENT_CA_FILE` |
| Behind a proxy | A load balancer or ingress terminates TLS, asks for the client certificate and passes it on in a header | `FORWARDER_CLIENT_CERT_HEADER`, `FORWARDER_CLIENT_CA_FILE` |
| [URL secret](#with-a-secret-in-the-url) | Your Macs have no client certificates, or your proxy can't ask for them. Weaker: see below | `FORWARDER_URL_SECRETS`, and `FORWARDER_TLS_CERT_FILE`, `FORWARDER_TLS_KEY_FILE` unless a proxy terminates TLS |
| Unauthenticated | Trying the relay out on a trusted network only | `FORWARDER_ALLOW_UNAUTHENTICATED=true` |

In both certificate modes, the relay checks the certificate itself: it must chain to
`FORWARDER_CLIENT_CA_FILE`, be in date, and allow client authentication. A request without
a good certificate gets no answer at all, because Privileges deletes an event on any HTTP
answer and keeps it queued only when the connection fails.

Behind a proxy:

- The header must be in Envoy's `X-Forwarded-Client-Cert` form (`Cert="<URL-encoded PEM>"`),
  which Azure Container Apps uses.
- The proxy must **replace** any copy of the header a client sends. The relay refuses a header
  that appears twice or holds more than one element, which is what a proxy that appends
  produces.
- The relay's plain-HTTP port must be reachable **only from the proxy**. Anyone who can reach
  it directly can send any header they like.
- When the proxy can't reach the relay, or the relay closes the connection, the proxy answers
  the Mac itself (usually 502), and Privileges treats that as delivered. Check the relay's
  logs and `/healthz` after a change.

In direct mode, the relay lists the client CA's name when it asks for a certificate. Privileges
uses that list to choose which identity to present, and presents nothing without it. A proxy
that doesn't send the list won't work with Privileges.

### With a secret in the URL

Privileges posts to `https://relay.example.com/v1/privileges/<secret>`, with the secret in
`ServerAddress` in its profile. TLS still proves the relay to the Macs, but nothing proves a
Mac to the relay: whoever has the secret can send events. It works behind any proxy and needs
no certificates on the Macs, so use it when certificates aren't an option.

```sh
FORWARDER_URL_SECRETS=london=<secret>,paris=<secret>
```

Make each secret with `openssl rand -hex 32` (at least 32 letters, digits, `.`, `_`, `~` or
`-`). Each one has a name, which every event sent with it carries as
`unmapped.altiward.url_secret_name`.

Before you choose it, know that:

- **Any local user can read the secret.** Managed preferences aren't private on a Mac, so
  anyone using one can post events under that secret, fake ones included. Events are marked
  unverified in every mode, but here the relay can't even tell which Mac sent one. Give each
  site or group its own secret, so a leak is limited to it and its events can be told apart.
- **It ends up in access logs.** Proxies and load balancers usually log the request path.
  Check yours, and keep those logs as private as the secret. The relay never logs the path.
- **Rotate with overlap.** Add the new secret to `FORWARDER_URL_SECRETS`, deploy the profile
  with it, and remove the old one only once every Mac has the new profile. A Mac sending a
  secret the relay doesn't know gets no answer, so it keeps its events, but behind a proxy
  it gets the proxy's 502 instead, and Privileges deletes them.

Without `FORWARDER_TLS_CERT_FILE` and `FORWARDER_TLS_KEY_FILE` the relay serves plain HTTP on
`:8080`, for a proxy that terminates TLS. Make that port reachable only from the proxy, as in
header mode: the secret would otherwise cross the network unencrypted.

## Certificates

You provide the certificates; the forwarder doesn't ship or issue any. The relay needs three
things, and an organisation whose Macs already have device certificates (for Wi-Fi or VPN)
usually has two of them.

| What | What it's for | Where it comes from | Where it goes |
|---|---|---|---|
| The relay's server certificate | Macs check they're talking to your relay, as with any HTTPS server | Any CA your Macs trust. With a public CA (Let's Encrypt, or your usual provider) there's nothing to do on the Macs. With an internal CA, deploy its root to the Macs through your MDM | `FORWARDER_TLS_CERT_FILE` and `FORWARDER_TLS_KEY_FILE` in direct mode, or the proxy in front of the relay |
| The client CA | The relay accepts only Macs whose certificate this CA issued | The CA your MDM issues device certificates from | `FORWARDER_CLIENT_CA_FILE` (PEM; add any intermediate CAs that issue the Macs' certificates) |
| A client certificate on each Mac | Each Mac proves it's one of yours; Privileges can't send a token | Your MDM | A payload in the profile that turns on Privileges' webhook |

A CA root in a profile someone installs by hand isn't trusted for TLS on recent macOS, so
deploy roots through your MDM.

### If your Macs already have device certificates

Point `FORWARDER_CLIENT_CA_FILE` at the CA that issues them, and there's nothing new to put on
the Macs. Each certificate must:

- be issued by that CA: Privileges presents the identity whose issuer matches a CA name the
  relay sends;
- allow client authentication (the client-auth extended key usage, or no extended key usage);
- have a private key PrivilegesAgent can use without a prompt: `AllowAllAppsAccess` in a SCEP
  or PKCS#12 payload. A key your MDM makes hardware-bound may not be usable by other apps.

Try one Mac first. If the relay logs `TLS handshake error ... client didn't provide a
certificate` for it and its events stay in Privileges' queue
(`/Library/Application Support/Privileges/QueuedEvents.plist`), the agent couldn't use the
certificate.

### If they don't

Add a SCEP or ACME payload to the profile that turns on Privileges' webhook, in place of the
PKCS#12 payload in [profiles/altiward-forwarder-privileges-webhook.mobileconfig](../profiles/altiward-forwarder-privileges-webhook.mobileconfig),
so each Mac gets its own certificate from your CA. Jamf Pro, Intune and Kandji, among others,
can issue them.

For a trial or a small fleet, one PKCS#12 identity shared by every Mac also works. It's
weaker: you can't revoke one Mac's certificate, and the relay can't tell Macs apart by it.

The `openssl` commands under [Trying it with a throwaway CA](#trying-it-with-a-throwaway-ca) are
for a first look only.

## Settings

| Variable | Default | |
|---|---|---|
| `FORWARDER_LISTEN_ADDR` | `:8443` when the relay terminates TLS, `:8080` otherwise | Where Privileges' webhook arrives (`POST /v1/privileges`, or `POST /v1/privileges/<secret>` with URL secrets) |
| `FORWARDER_HEALTH_ADDR` | `:8081` | Plain HTTP, `GET /healthz` only. Don't expose it publicly |
| `FORWARDER_TLS_CERT_FILE`, `FORWARDER_TLS_KEY_FILE` | | The relay's server certificate and key, PEM (direct mode, or URL secrets without a proxy) |
| `FORWARDER_CLIENT_CA_FILE` | | PEM certificates of the CA that issues the Macs' client certificates |
| `FORWARDER_CLIENT_CERT_HEADER` | | The header a proxy puts the client certificate in, for example `X-Forwarded-Client-Cert` |
| `FORWARDER_URL_SECRETS` | | `name=secret` pairs, separated by commas: [URL-secret mode](#with-a-secret-in-the-url) |
| `FORWARDER_ALLOW_UNAUTHENTICATED` | `false` | `true` accepts events from anyone who can reach the relay |
| `FORWARDER_SPOOL_DIR` | `/var/lib/altiward-forwarder` | Where events wait until each SIEM accepts them. Keep it on persistent storage |
| `FORWARDER_SPOOL_MAX` | `10000` | Events each SIEM's queue holds before the relay stops taking new ones |
| `FORWARDER_TENANT_UID` | | Sets `metadata.tenant_uid` on every event, to tell sites apart in one SIEM |
| `FORWARDER_TRUSTED_CAS_FILE` | | PEM certificates of CAs to trust, on top of the public ones, when connecting to a destination: for a SIEM whose certificate comes from an internal CA |

Set at least one destination:

| Destination | Variables |
|---|---|
| Splunk HTTP Event Collector | `FORWARDER_SPLUNK_HEC_URL` (for example `https://splunk.example.com:8088`), `FORWARDER_SPLUNK_HEC_TOKEN`, and optionally `FORWARDER_SPLUNK_INDEX`. Events use sourcetype `altiward:ocsf` and source `altiward-forwarder` |
| Microsoft Sentinel (Logs Ingestion API) | `FORWARDER_SENTINEL_ENDPOINT`, `FORWARDER_SENTINEL_DCR_ID`, `FORWARDER_SENTINEL_STREAM` (default `Custom-AltiwardOCSF`), and `FORWARDER_SENTINEL_AUTH`: `secret` (default) with `FORWARDER_SENTINEL_TENANT_ID`, `FORWARDER_SENTINEL_CLIENT_ID` and `FORWARDER_SENTINEL_CLIENT_SECRET`, or `managed-identity` on Azure (with `FORWARDER_SENTINEL_CLIENT_ID` for a user-assigned identity) |
| Syslog | `FORWARDER_SYSLOG_ADDR` (`host:port`), `FORWARDER_SYSLOG_TLS` (default `true`), `FORWARDER_SYSLOG_CA_FILE` (the only CAs trusted for the receiver, in place of the public ones and `FORWARDER_TRUSTED_CAS_FILE`), `FORWARDER_SYSLOG_FORMAT` (`cef`, the default, or `json`), `FORWARDER_SYSLOG_FRAMING` (`octet`, the default, or `newline`) |
| Standard output | `FORWARDER_STDOUT=true`: one JSON record per line, in the container log |

The image trusts only public CAs. If your Splunk or syslog receiver has a certificate from an
internal CA, mount that CA's certificate into the container and point
`FORWARDER_TRUSTED_CAS_FILE` at it. Don't turn certificate checks off instead: the relay has no
setting for that.

The Sentinel stream and table are the Altiward server's: if your workspace is already set up
for Altiward (`deploy/sentinel/setup.sh` in the
[Altiward repository](https://github.com/Altiward/altiward)), use the same endpoint, rule and
stream, and both sets of events land in `AltiwardOCSF_CL`.

## Health

`GET /healthz` on `FORWARDER_HEALTH_ADDR` answers 200 while the relay runs, so a SIEM outage
doesn't get the container restarted. The body shows each destination's queue and last error:

```json
{"status":"ok","sinks":{"splunk":{"queued":0,"last_success":"2026-10-20T09:00:01Z"}}}
```

`status` is `degraded` while a destination is failing, or when it has events `set_aside`:
spooled events that couldn't be read back. Those are kept as `<uid>.json.corrupt` in the
destination's spool folder and logged; they won't be sent. A queue that keeps growing means a
SIEM isn't accepting events; the log says why. The image's health check runs
`altiward-forwarder health`, which calls this endpoint.

At startup the relay creates each destination's spool folder and checks it can write there. If
it can't, it stops with an error rather than starting and refusing every event.

## Trying it with a throwaway CA

For a first look, make a CA, a server certificate and one Mac's client certificate with
`openssl`. Use your own PKI in production.

```sh
mkdir certs && cd certs
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout ca.key -out ca.pem \
  -subj "/CN=Forwarder test CA" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=relay.example.com"
printf 'subjectAltName=DNS:relay.example.com,DNS:localhost\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -out server.pem -extfile server.ext

openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=test Mac"
printf 'extendedKeyUsage=clientAuth\n' > client.ext
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -out client.pem -extfile client.ext
chmod 644 server.key   # the container runs as uid 65532; use chown in production
cd ..
```

Then start the relay with `deploy/compose.yaml` (`FORWARDER_VERSION` and `FORWARDER_STDOUT=true`
in `.env`) and send it one of the example bodies:

```sh
curl --cert certs/client.pem --key certs/client.key --cacert certs/ca.pem \
  -d @testdata/privileges-2.6/grant-with-reason.json https://localhost:8443/v1/privileges
```

It answers `202` with the event's `uid`, and `docker compose logs` shows the OCSF record.

## Pointing Privileges at the relay

[`profiles/altiward-forwarder-privileges-webhook.mobileconfig`](../profiles/altiward-forwarder-privileges-webhook.mobileconfig)
sets Privileges' `RemoteLogging` to the relay, with `QueueUnsentEvents` so Privileges keeps
events it couldn't send. Its comments list what to fill in. Two things to know:

- **Deploy it through your MDM.** On recent macOS, a CA certificate in a profile installed by
  hand isn't trusted for TLS, and Privileges then can't connect.
- **Privileges reads the setting when its agent starts.** After installing the profile, log
  out and in, or run `launchctl kickstart -k gui/$(id -u)/corp.sap.privileges.agent`.
- **Turn on reasons if you want them in your SIEM.** Privileges keeps the reason someone gives
  only when it requires one, so we suggest setting `ReasonRequired` (and `ReasonMinLength`) in
  your Privileges profile. Without it, events arrive with no reason, even from
  `PrivilegesCLI --add --reason`.
