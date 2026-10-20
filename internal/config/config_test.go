package config_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/config"
	"github.com/Altiward/altiward-forwarder/internal/ocsf"
)

func env(kv map[string]string) func(string) string {
	return func(k string) string { return kv[k] }
}

// direct is the minimum for the default mode: TLS with client certificates, and one sink.
func direct() map[string]string {
	return map[string]string{
		"FORWARDER_TLS_CERT_FILE":  "/certs/server.pem",
		"FORWARDER_TLS_KEY_FILE":   "/certs/server.key",
		"FORWARDER_CLIENT_CA_FILE": "/certs/ca.pem",
		"FORWARDER_STDOUT":         "true",
	}
}

// with returns a copy of base with the given keys set ("" deletes one).
func with(base map[string]string, kv ...string) map[string]string {
	out := maps.Clone(base)
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(out, kv[i])
		} else {
			out[kv[i]] = kv[i+1]
		}
	}
	return out
}

func wantErr(t *testing.T, kv map[string]string, mentions string) {
	t.Helper()
	_, err := config.FromEnv(env(kv))
	if err == nil || !strings.Contains(err.Error(), mentions) {
		t.Errorf("err %v, want one mentioning %s", err, mentions)
	}
}

func TestDefaults(t *testing.T) {
	c, err := config.FromEnv(env(direct()))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" || c.HealthAddr != ":8081" || c.SpoolDir != "/var/lib/altiward-forwarder" || c.SpoolMax != 10000 {
		t.Errorf("got %+v", c)
	}
	if !c.Stdout || c.Splunk != nil || c.Sentinel != nil || c.Syslog != nil {
		t.Errorf("sinks %+v", c)
	}

	c, err = config.FromEnv(env(with(direct(),
		"FORWARDER_SENTINEL_ENDPOINT", "https://dcr.example", "FORWARDER_SENTINEL_DCR_ID", "dcr-1",
		"FORWARDER_SENTINEL_TENANT_ID", "t", "FORWARDER_SENTINEL_CLIENT_ID", "c", "FORWARDER_SENTINEL_CLIENT_SECRET", "s",
		"FORWARDER_SYSLOG_ADDR", "siem.example:6514", "FORWARDER_SPOOL_MAX", "50")))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sentinel == nil || c.Syslog == nil {
		t.Fatalf("sinks %+v", c)
	}
	if c.Sentinel.Stream != "Custom-AltiwardOCSF" || c.Sentinel.Auth != "secret" {
		t.Errorf("sentinel %+v", c.Sentinel)
	}
	if !c.Syslog.TLS || c.Syslog.Format != "cef" || c.Syslog.Framing != "octet" || c.SpoolMax != 50 {
		t.Errorf("syslog %+v, spool max %d", c.Syslog, c.SpoolMax)
	}
}

func TestNoSinkRefuses(t *testing.T) {
	wantErr(t, with(direct(), "FORWARDER_STDOUT", ""), "FORWARDER_STDOUT")
}

func TestDirectModeNeedsCertAndCA(t *testing.T) {
	wantErr(t, with(direct(), "FORWARDER_TLS_CERT_FILE", ""), "FORWARDER_TLS_CERT_FILE")
	wantErr(t, with(direct(), "FORWARDER_TLS_KEY_FILE", ""), "FORWARDER_TLS_KEY_FILE")
	wantErr(t, with(direct(), "FORWARDER_CLIENT_CA_FILE", ""), "FORWARDER_CLIENT_CA_FILE")
}

func TestHeaderModeNeedsCA(t *testing.T) {
	header := map[string]string{"FORWARDER_CLIENT_CERT_HEADER": "X-Forwarded-Client-Cert", "FORWARDER_STDOUT": "true"}
	wantErr(t, header, "FORWARDER_CLIENT_CA_FILE")

	c, err := config.FromEnv(env(with(header, "FORWARDER_CLIENT_CA_FILE", "/certs/ca.pem")))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.ClientCertHeader != "X-Forwarded-Client-Cert" {
		t.Errorf("got %+v", c)
	}
	// The proxy in front terminates TLS, so a server certificate here would be a mistake.
	wantErr(t, with(direct(), "FORWARDER_CLIENT_CERT_HEADER", "X-Forwarded-Client-Cert"), "FORWARDER_TLS_CERT_FILE")
}

func TestUnauthenticatedNeedsNoCA(t *testing.T) {
	c, err := config.FromEnv(env(map[string]string{"FORWARDER_ALLOW_UNAUTHENTICATED": "true", "FORWARDER_STDOUT": "true"}))
	if err != nil {
		t.Fatal(err)
	}
	if !c.AllowUnauthenticated || c.Listen != ":8080" {
		t.Errorf("got %+v", c)
	}
	// Asking for both is a mistake that would silently drop authentication.
	wantErr(t, with(direct(), "FORWARDER_ALLOW_UNAUTHENTICATED", "true"), "FORWARDER_ALLOW_UNAUTHENTICATED")
	wantErr(t, map[string]string{"FORWARDER_ALLOW_UNAUTHENTICATED": "yes", "FORWARDER_STDOUT": "true"}, "FORWARDER_ALLOW_UNAUTHENTICATED")
}

func TestSentinelSecretWithManagedIdentityRefused(t *testing.T) {
	mi := with(direct(), "FORWARDER_SENTINEL_ENDPOINT", "https://dcr.example", "FORWARDER_SENTINEL_DCR_ID", "dcr-1",
		"FORWARDER_SENTINEL_AUTH", "managed-identity")
	if _, err := config.FromEnv(env(mi)); err != nil {
		t.Fatalf("managed identity alone: %v", err)
	}
	wantErr(t, with(mi, "FORWARDER_SENTINEL_CLIENT_SECRET", "s"), "FORWARDER_SENTINEL_CLIENT_SECRET")
	wantErr(t, with(mi, "FORWARDER_SENTINEL_AUTH", "password"), "FORWARDER_SENTINEL_AUTH")
	wantErr(t, with(mi, "FORWARDER_SENTINEL_AUTH", ""), "FORWARDER_SENTINEL_") // secret needs tenant, client, secret
}

func TestSyslogFormatValidated(t *testing.T) {
	s := with(direct(), "FORWARDER_SYSLOG_ADDR", "siem.example:6514")
	wantErr(t, with(s, "FORWARDER_SYSLOG_FORMAT", "xml"), "FORWARDER_SYSLOG_FORMAT")
	wantErr(t, with(s, "FORWARDER_SYSLOG_FRAMING", "lines"), "FORWARDER_SYSLOG_FRAMING")
	wantErr(t, with(s, "FORWARDER_SYSLOG_TLS", "maybe"), "FORWARDER_SYSLOG_TLS")
	wantErr(t, with(s, "FORWARDER_SYSLOG_ADDR", "siem.example"), "FORWARDER_SYSLOG_ADDR")
	wantErr(t, with(s, "FORWARDER_SYSLOG_TLS", "false", "FORWARDER_SYSLOG_CA_FILE", "/ca.pem"), "FORWARDER_SYSLOG_CA_FILE")
}

func TestSplunkNeedsToken(t *testing.T) {
	wantErr(t, with(direct(), "FORWARDER_SPLUNK_HEC_URL", "https://splunk.example:8088"), "FORWARDER_SPLUNK_HEC_TOKEN")
}

func TestSpoolMaxValidated(t *testing.T) {
	wantErr(t, with(direct(), "FORWARDER_SPOOL_MAX", "0"), "FORWARDER_SPOOL_MAX")
	wantErr(t, with(direct(), "FORWARDER_SPOOL_MAX", "lots"), "FORWARDER_SPOOL_MAX")
}

func TestSinksInOrder(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, []byte("not a certificate"), 0o600)
	all := with(direct(),
		"FORWARDER_SPLUNK_HEC_URL", "https://splunk.example:8088", "FORWARDER_SPLUNK_HEC_TOKEN", "t",
		"FORWARDER_SENTINEL_ENDPOINT", "https://dcr.example", "FORWARDER_SENTINEL_DCR_ID", "dcr-1",
		"FORWARDER_SENTINEL_AUTH", "managed-identity",
		"FORWARDER_SYSLOG_ADDR", "siem.example:6514")
	c, err := config.FromEnv(env(all))
	if err != nil {
		t.Fatal(err)
	}
	sinks, err := c.Sinks()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range sinks {
		names = append(names, s.Name())
	}
	if strings.Join(names, " ") != "splunk sentinel syslog stdout" {
		t.Fatalf("sinks %v", names)
	}

	c, _ = config.FromEnv(env(with(all, "FORWARDER_SYSLOG_CA_FILE", ca)))
	if _, err := c.Sinks(); err == nil || !strings.Contains(err.Error(), "FORWARDER_SYSLOG_CA_FILE") {
		t.Fatalf("err %v, want a bad CA file reported", err)
	}
}

const (
	secretA = "a6Jq3vX9pL2mR8tY4wZ7cN1bK5hG0dFs" // 32 characters; gitleaks:allow (test value)
	secretB = "Qe7Rt2Yu9Io4Pa1Sd6Fg3Hj8Kl5Zx0Cv-_.~"
)

func TestURLSecretsMode(t *testing.T) {
	plain := map[string]string{"FORWARDER_URL_SECRETS": "london=" + secretA + ", paris=" + secretB, "FORWARDER_STDOUT": "true"}
	c, err := config.FromEnv(env(plain))
	if err != nil {
		t.Fatal(err)
	}
	want := []config.URLSecret{{Name: "london", Secret: secretA}, {Name: "paris", Secret: secretB}}
	if c.Listen != ":8080" || len(c.URLSecrets) != 2 || c.URLSecrets[0] != want[0] || c.URLSecrets[1] != want[1] {
		t.Errorf("got listen %s, secrets %+v", c.Listen, c.URLSecrets)
	}
	// With a server certificate the relay terminates TLS itself, without asking for a client's.
	c, err = config.FromEnv(env(with(plain, "FORWARDER_TLS_CERT_FILE", "/certs/server.pem", "FORWARDER_TLS_KEY_FILE", "/certs/server.key")))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" {
		t.Errorf("listen %s with TLS, want :8443", c.Listen)
	}
	wantErr(t, with(plain, "FORWARDER_TLS_CERT_FILE", "/certs/server.pem"), "FORWARDER_TLS_KEY_FILE")
	wantErr(t, with(plain, "FORWARDER_TLS_KEY_FILE", "/certs/server.key"), "FORWARDER_TLS_CERT_FILE")
}

// URL secrets are their own mode: mixing them with certificates or no authentication would
// leave it unclear which one protects the relay.
func TestURLSecretsRefusedWithOtherModes(t *testing.T) {
	s := "london=" + secretA
	wantErr(t, with(direct(), "FORWARDER_URL_SECRETS", s), "FORWARDER_URL_SECRETS")
	wantErr(t, map[string]string{"FORWARDER_URL_SECRETS": s, "FORWARDER_CLIENT_CERT_HEADER": "X-Forwarded-Client-Cert",
		"FORWARDER_CLIENT_CA_FILE": "/certs/ca.pem", "FORWARDER_STDOUT": "true"}, "FORWARDER_URL_SECRETS")
	wantErr(t, map[string]string{"FORWARDER_URL_SECRETS": s, "FORWARDER_ALLOW_UNAUTHENTICATED": "true", "FORWARDER_STDOUT": "true"}, "FORWARDER_URL_SECRETS")
}

func TestURLSecretsValidated(t *testing.T) {
	for name, value := range map[string]string{
		"empty":            " , ",
		"no name":          "=" + secretA,
		"no equals":        secretA,
		"short secret":     "london=tooshort",
		"slash in secret":  "london=" + secretA + "/x",
		"percent":          "london=" + secretA + "%2F",
		"space in name":    "big city=" + secretA,
		"duplicate name":   "london=" + secretA + ",london=" + secretB,
		"duplicate secret": "london=" + secretA + ",paris=" + secretA,
	} {
		_, err := config.FromEnv(env(map[string]string{"FORWARDER_URL_SECRETS": value, "FORWARDER_STDOUT": "true"}))
		if err == nil || !strings.Contains(err.Error(), "FORWARDER_URL_SECRETS") {
			t.Errorf("%s: err %v", name, err)
		}
		if err != nil && strings.Contains(err.Error(), secretA) {
			t.Errorf("%s: the error repeats the secret: %v", name, err)
		}
	}
}

// privateCA makes a CA no system trusts, writes its certificate to a PEM file, and issues a
// server certificate for 127.0.0.1.
func privateCA(t *testing.T, name string) (caFile string, leaf tls.Certificate) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "siem"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile, tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
}

// TestTrustedCAsReachPrivateSIEM: a Splunk HEC and a syslog receiver with certificates from
// a private CA are reachable once FORWARDER_TRUSTED_CAS_FILE names that CA, on top of the
// system's roots. FORWARDER_SYSLOG_CA_FILE still replaces the roots for syslog.
func TestTrustedCAsReachPrivateSIEM(t *testing.T) {
	caFile, leaf := privateCA(t, "Private CA")
	hec := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	hec.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	hec.StartTLS()
	t.Cleanup(hec.Close)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{leaf}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(io.Discard, conn); conn.Close() }()
		}
	}()

	base := with(direct(), "FORWARDER_STDOUT", "",
		"FORWARDER_SPLUNK_HEC_URL", hec.URL, "FORWARDER_SPLUNK_HEC_TOKEN", "t",
		"FORWARDER_SYSLOG_ADDR", ln.Addr().String())
	send := func(kv map[string]string) (splunkErr, syslogErr error) {
		t.Helper()
		c, err := config.FromEnv(env(kv))
		if err != nil {
			t.Fatal(err)
		}
		sinks, err := c.Sinks()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		rec := []ocsf.Record{{"class_uid": 3005, "time": 1}}
		return sinks[0].Send(ctx, rec), sinks[1].Send(ctx, rec)
	}

	if splunkErr, syslogErr := send(base); splunkErr == nil || syslogErr == nil {
		t.Fatalf("a private CA was trusted without the setting: splunk %v, syslog %v", splunkErr, syslogErr)
	}
	if splunkErr, syslogErr := send(with(base, "FORWARDER_TRUSTED_CAS_FILE", caFile)); splunkErr != nil || syslogErr != nil {
		t.Fatalf("with FORWARDER_TRUSTED_CAS_FILE: splunk %v, syslog %v", splunkErr, syslogErr)
	}
	otherCA, _ := privateCA(t, "Another CA")
	if _, syslogErr := send(with(base, "FORWARDER_TRUSTED_CAS_FILE", caFile, "FORWARDER_SYSLOG_CA_FILE", otherCA)); syslogErr == nil {
		t.Fatal("FORWARDER_SYSLOG_CA_FILE didn't replace the roots for syslog")
	}

	bad := filepath.Join(t.TempDir(), "bad.pem")
	os.WriteFile(bad, []byte("not a certificate"), 0o600)
	for _, file := range []string{bad, filepath.Join(t.TempDir(), "missing.pem")} {
		c, err := config.FromEnv(env(with(base, "FORWARDER_TRUSTED_CAS_FILE", file)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Sinks(); err == nil || !strings.Contains(err.Error(), "FORWARDER_TRUSTED_CAS_FILE") {
			t.Errorf("%s: err %v", filepath.Base(file), err)
		}
	}
}
