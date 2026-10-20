// Package config reads the relay's settings from the environment. The SIEM settings mirror
// the Altiward server's (ALTIWARD_* there, FORWARDER_* here), so one .env style serves both.
package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Altiward/altiward/integrations/sentinel"
	"github.com/Altiward/altiward/integrations/splunk"
	"github.com/Altiward/altiward/integrations/syslog"

	"github.com/Altiward/altiward-forwarder/internal/sink"
)

type Splunk struct {
	URL   string // FORWARDER_SPLUNK_HEC_URL
	Token string // FORWARDER_SPLUNK_HEC_TOKEN
	Index string // FORWARDER_SPLUNK_INDEX (optional)
}

type Sentinel struct {
	Endpoint string // FORWARDER_SENTINEL_ENDPOINT (the rule's logs ingestion URL, or a DCE's)
	RuleID   string // FORWARDER_SENTINEL_DCR_ID (immutable ID)
	Stream   string // FORWARDER_SENTINEL_STREAM, default Custom-AltiwardOCSF, the Altiward table's
	Auth     string // FORWARDER_SENTINEL_AUTH: secret (default) or managed-identity
	TenantID string // FORWARDER_SENTINEL_TENANT_ID; secret only
	// FORWARDER_SENTINEL_CLIENT_ID: the app registration's, or with a managed identity, a
	// user-assigned identity's (empty = the system-assigned identity)
	ClientID     string
	ClientSecret string // FORWARDER_SENTINEL_CLIENT_SECRET; secret only
}

type Syslog struct {
	Addr    string // FORWARDER_SYSLOG_ADDR, host:port
	TLS     bool   // FORWARDER_SYSLOG_TLS, default true; "false" for plain TCP on a trusted network
	CAFile  string // FORWARDER_SYSLOG_CA_FILE (optional): PEM roots for the receiver
	Format  string // FORWARDER_SYSLOG_FORMAT: cef (default) or json
	Framing string // FORWARDER_SYSLOG_FRAMING: octet (default, RFC 6587) or newline
}

// URLSecret is one of FORWARDER_URL_SECRETS: Macs post to /v1/privileges/<Secret>, and the
// record names the site or group by Name.
type URLSecret struct {
	Name, Secret string
}

// Config is the relay's settings. It authenticates Macs in one of four modes:
//   - direct (the default): the relay terminates TLS and requires a client certificate
//     issued by FORWARDER_CLIENT_CA_FILE;
//   - header: a proxy in front terminates TLS and passes the client certificate in
//     FORWARDER_CLIENT_CERT_HEADER, which the relay checks against the same CA;
//   - URL secret: Macs post to /v1/privileges/<secret>, one of FORWARDER_URL_SECRETS, over
//     the relay's own TLS or a proxy's;
//   - unauthenticated (FORWARDER_ALLOW_UNAUTHENTICATED=true), for evaluation only.
type Config struct {
	Listen               string      // FORWARDER_LISTEN_ADDR: :8443 direct, :8080 otherwise
	HealthAddr           string      // FORWARDER_HEALTH_ADDR, default :8081, plain HTTP
	TLSCertFile          string      // FORWARDER_TLS_CERT_FILE, direct mode
	TLSKeyFile           string      // FORWARDER_TLS_KEY_FILE, direct mode
	ClientCAFile         string      // FORWARDER_CLIENT_CA_FILE
	ClientCertHeader     string      // FORWARDER_CLIENT_CERT_HEADER, header mode
	AllowUnauthenticated bool        // FORWARDER_ALLOW_UNAUTHENTICATED
	URLSecrets           []URLSecret // FORWARDER_URL_SECRETS, URL-secret mode
	SpoolDir             string      // FORWARDER_SPOOL_DIR, default /var/lib/altiward-forwarder
	SpoolMax             int         // FORWARDER_SPOOL_MAX, records per sink, default 10000
	TenantUID            string      // FORWARDER_TENANT_UID (optional), as metadata.tenant_uid
	// FORWARDER_TRUSTED_CAS_FILE (optional): PEM certificates trusted on top of the system's
	// roots for every destination, for a SIEM with a private CA's certificate
	TrustedCAsFile string

	Splunk   *Splunk
	Sentinel *Sentinel
	Syslog   *Syslog
	Stdout   bool // FORWARDER_STDOUT
}

const (
	SentinelSecret          = "secret"
	SentinelManagedIdentity = "managed-identity"
)

// FromEnv reads and checks the settings.
func FromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		HealthAddr:       or(getenv("FORWARDER_HEALTH_ADDR"), ":8081"),
		TLSCertFile:      getenv("FORWARDER_TLS_CERT_FILE"),
		TLSKeyFile:       getenv("FORWARDER_TLS_KEY_FILE"),
		ClientCAFile:     getenv("FORWARDER_CLIENT_CA_FILE"),
		ClientCertHeader: getenv("FORWARDER_CLIENT_CERT_HEADER"),
		SpoolDir:         or(getenv("FORWARDER_SPOOL_DIR"), "/var/lib/altiward-forwarder"),
		SpoolMax:         10000,
		TenantUID:        getenv("FORWARDER_TENANT_UID"),
		TrustedCAsFile:   getenv("FORWARDER_TRUSTED_CAS_FILE"),
	}
	var err error
	if c.AllowUnauthenticated, err = boolean(getenv, "FORWARDER_ALLOW_UNAUTHENTICATED", false); err != nil {
		return c, err
	}
	if c.Stdout, err = boolean(getenv, "FORWARDER_STDOUT", false); err != nil {
		return c, err
	}
	if v := getenv("FORWARDER_SPOOL_MAX"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, fmt.Errorf("FORWARDER_SPOOL_MAX: want a number of at least 1, got %q", v)
		}
		c.SpoolMax = n
	}

	if v := getenv("FORWARDER_URL_SECRETS"); v != "" {
		if c.URLSecrets, err = urlSecrets(v); err != nil {
			return c, err
		}
	}

	switch {
	case len(c.URLSecrets) > 0:
		if c.ClientCAFile != "" || c.ClientCertHeader != "" || c.AllowUnauthenticated {
			return c, errors.New("FORWARDER_URL_SECRETS is a way for Macs to authenticate on its own: remove it, or remove " +
				"FORWARDER_CLIENT_CA_FILE, FORWARDER_CLIENT_CERT_HEADER and FORWARDER_ALLOW_UNAUTHENTICATED")
		}
		switch {
		case c.TLSCertFile != "" && c.TLSKeyFile != "":
			c.Listen = or(getenv("FORWARDER_LISTEN_ADDR"), ":8443")
		case c.TLSCertFile == "" && c.TLSKeyFile == "":
			c.Listen = or(getenv("FORWARDER_LISTEN_ADDR"), ":8080")
		default:
			return c, errors.New("set both FORWARDER_TLS_CERT_FILE and FORWARDER_TLS_KEY_FILE, or neither behind a proxy that terminates TLS")
		}
	case c.AllowUnauthenticated:
		if c.ClientCAFile != "" || c.ClientCertHeader != "" || c.TLSCertFile != "" {
			return c, errors.New("FORWARDER_ALLOW_UNAUTHENTICATED=true turns client certificates off: " +
				"remove it, or remove the TLS and client CA settings")
		}
		c.Listen = or(getenv("FORWARDER_LISTEN_ADDR"), ":8080")
	case c.ClientCertHeader != "":
		if c.ClientCAFile == "" {
			return c, errors.New("FORWARDER_CLIENT_CA_FILE is required with FORWARDER_CLIENT_CERT_HEADER")
		}
		if c.TLSCertFile != "" || c.TLSKeyFile != "" {
			return c, errors.New("FORWARDER_TLS_CERT_FILE and FORWARDER_TLS_KEY_FILE aren't used with " +
				"FORWARDER_CLIENT_CERT_HEADER: the proxy in front terminates TLS")
		}
		c.Listen = or(getenv("FORWARDER_LISTEN_ADDR"), ":8080")
	default:
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return c, errors.New("set FORWARDER_TLS_CERT_FILE and FORWARDER_TLS_KEY_FILE (or FORWARDER_CLIENT_CERT_HEADER " +
				"behind a proxy that checks client certificates)")
		}
		if c.ClientCAFile == "" {
			return c, errors.New("FORWARDER_CLIENT_CA_FILE is required: Macs authenticate with a client certificate it issued")
		}
		c.Listen = or(getenv("FORWARDER_LISTEN_ADDR"), ":8443")
	}

	if url := getenv("FORWARDER_SPLUNK_HEC_URL"); url != "" {
		c.Splunk = &Splunk{URL: url, Token: getenv("FORWARDER_SPLUNK_HEC_TOKEN"), Index: getenv("FORWARDER_SPLUNK_INDEX")}
		if c.Splunk.Token == "" {
			return c, errors.New("FORWARDER_SPLUNK_HEC_TOKEN is required with FORWARDER_SPLUNK_HEC_URL")
		}
	}
	if ep := getenv("FORWARDER_SENTINEL_ENDPOINT"); ep != "" {
		c.Sentinel = &Sentinel{
			Endpoint:     ep,
			RuleID:       getenv("FORWARDER_SENTINEL_DCR_ID"),
			Stream:       or(getenv("FORWARDER_SENTINEL_STREAM"), "Custom-AltiwardOCSF"),
			Auth:         or(getenv("FORWARDER_SENTINEL_AUTH"), SentinelSecret),
			TenantID:     getenv("FORWARDER_SENTINEL_TENANT_ID"),
			ClientID:     getenv("FORWARDER_SENTINEL_CLIENT_ID"),
			ClientSecret: getenv("FORWARDER_SENTINEL_CLIENT_SECRET"),
		}
		s := c.Sentinel
		switch s.Auth {
		case SentinelSecret:
			if s.RuleID == "" || s.TenantID == "" || s.ClientID == "" || s.ClientSecret == "" {
				return c, errors.New("FORWARDER_SENTINEL_* needs DCR_ID, TENANT_ID, CLIENT_ID and CLIENT_SECRET " +
					"(or FORWARDER_SENTINEL_AUTH=managed-identity on Azure)")
			}
		case SentinelManagedIdentity:
			if s.RuleID == "" {
				return c, errors.New("FORWARDER_SENTINEL_DCR_ID is required with FORWARDER_SENTINEL_ENDPOINT")
			}
			if s.ClientSecret != "" {
				return c, errors.New("FORWARDER_SENTINEL_CLIENT_SECRET isn't used with FORWARDER_SENTINEL_AUTH=managed-identity: remove it")
			}
		default:
			return c, fmt.Errorf("FORWARDER_SENTINEL_AUTH: want secret or managed-identity, got %q", s.Auth)
		}
	}
	if addr := getenv("FORWARDER_SYSLOG_ADDR"); addr != "" {
		c.Syslog = &Syslog{
			Addr: addr, CAFile: getenv("FORWARDER_SYSLOG_CA_FILE"),
			Format: or(getenv("FORWARDER_SYSLOG_FORMAT"), "cef"), Framing: or(getenv("FORWARDER_SYSLOG_FRAMING"), "octet"),
		}
		s := c.Syslog
		if s.TLS, err = boolean(getenv, "FORWARDER_SYSLOG_TLS", true); err != nil {
			return c, err
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return c, fmt.Errorf("FORWARDER_SYSLOG_ADDR: want host:port, got %q", addr)
		}
		if s.Format != "cef" && s.Format != "json" {
			return c, fmt.Errorf("FORWARDER_SYSLOG_FORMAT: want cef or json, got %q", s.Format)
		}
		if s.Framing != "octet" && s.Framing != "newline" {
			return c, fmt.Errorf("FORWARDER_SYSLOG_FRAMING: want octet or newline, got %q", s.Framing)
		}
		if s.CAFile != "" && !s.TLS {
			return c, errors.New("FORWARDER_SYSLOG_CA_FILE needs TLS")
		}
	}
	if c.Splunk == nil && c.Sentinel == nil && c.Syslog == nil && !c.Stdout {
		return c, errors.New("no destination: set FORWARDER_SPLUNK_HEC_URL, FORWARDER_SENTINEL_ENDPOINT, " +
			"FORWARDER_SYSLOG_ADDR or FORWARDER_STDOUT=true")
	}
	return c, nil
}

// urlSecrets parses FORWARDER_URL_SECRETS, name=secret pairs separated by commas. Errors name
// the entry by position or name, never by its secret.
func urlSecrets(v string) ([]URLSecret, error) {
	var out []URLSecret
	names, secrets := map[string]bool{}, map[string]bool{}
	for i, entry := range strings.Split(v, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, secret, ok := strings.Cut(entry, "=")
		switch {
		case !ok || !allIn(name, "._-") || name == "":
			return nil, fmt.Errorf("FORWARDER_URL_SECRETS entry %d: want name=secret, with a name of letters, digits, '.', '_' and '-'", i+1)
		case len(secret) < 32 || !allIn(secret, "._~-"):
			return nil, fmt.Errorf("FORWARDER_URL_SECRETS %s: want a secret of at least 32 letters, digits, '.', '_', '~' and '-' "+
				"(for example from openssl rand -hex 32)", name)
		case names[name]:
			return nil, fmt.Errorf("FORWARDER_URL_SECRETS: the name %s appears twice", name)
		case secrets[secret]:
			return nil, fmt.Errorf("FORWARDER_URL_SECRETS %s: the same secret appears under another name", name)
		}
		names[name], secrets[secret] = true, true
		out = append(out, URLSecret{Name: name, Secret: secret})
	}
	if len(out) == 0 {
		return nil, errors.New("FORWARDER_URL_SECRETS holds no name=secret entries")
	}
	return out, nil
}

// allIn reports whether s holds only ASCII letters, digits and the given punctuation.
func allIn(s, punctuation string) bool {
	for _, r := range s {
		if !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune(punctuation, r)) {
			return false
		}
	}
	return true
}

// Sinks builds the configured destinations, in a fixed order.
func (c Config) Sinks() ([]sink.Sink, error) {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	var roots *x509.CertPool // nil: the system's
	if c.TrustedCAsFile != "" {
		pem, err := os.ReadFile(c.TrustedCAsFile)
		if err != nil {
			return nil, fmt.Errorf("FORWARDER_TRUSTED_CAS_FILE: %w", err)
		}
		if roots, err = x509.SystemCertPool(); err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("FORWARDER_TRUSTED_CAS_FILE %s: no PEM certificates", c.TrustedCAsFile)
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		httpClient.Transport = transport
	}
	var sinks []sink.Sink
	if s := c.Splunk; s != nil {
		sinks = append(sinks, &sink.Splunk{Client: &splunk.Client{URL: s.URL, Token: s.Token, HTTP: httpClient}, Index: s.Index})
	}
	if s := c.Sentinel; s != nil {
		var tokens sentinel.TokenSource = &sentinel.ClientCredentials{TenantID: s.TenantID, ClientID: s.ClientID, ClientSecret: s.ClientSecret, HTTP: httpClient}
		if s.Auth == SentinelManagedIdentity {
			tokens = &sentinel.ManagedIdentity{ClientID: s.ClientID} // its own client: IMDS mustn't go through a proxy
		}
		sinks = append(sinks, &sink.Sentinel{Client: &sentinel.Client{
			Endpoint: s.Endpoint, RuleID: s.RuleID, Stream: s.Stream, Tokens: tokens, HTTP: httpClient,
		}})
	}
	if s := c.Syslog; s != nil {
		client := &syslog.Client{Addr: s.Addr}
		if s.Framing == "newline" {
			client.Framing = syslog.Newline
		}
		if s.TLS {
			client.TLS = &tls.Config{RootCAs: roots}
			if s.CAFile != "" { // replaces the roots, trusted CAs included
				pem, err := os.ReadFile(s.CAFile)
				if err != nil {
					return nil, fmt.Errorf("FORWARDER_SYSLOG_CA_FILE: %w", err)
				}
				client.TLS.RootCAs = x509.NewCertPool()
				if !client.TLS.RootCAs.AppendCertsFromPEM(pem) {
					return nil, fmt.Errorf("FORWARDER_SYSLOG_CA_FILE %s: no PEM certificates", s.CAFile)
				}
			}
		}
		sinks = append(sinks, &sink.Syslog{Client: client, Format: s.Format})
	}
	if c.Stdout {
		sinks = append(sinks, &sink.Stdout{W: os.Stdout})
	}
	return sinks, nil
}

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func boolean(getenv func(string) string, key string, fallback bool) (bool, error) {
	switch v := getenv(key); v {
	case "":
		return fallback, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("%s: want true or false, got %q", key, v)
	}
}
