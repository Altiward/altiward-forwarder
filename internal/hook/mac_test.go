package hook

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
)

func TestParseIoreg(t *testing.T) {
	out := `+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000253, registered, matched, active, busy 0 (1225 ms), retain 39>
    {
      "IOPlatformSerialNumber" = "C02XK0AAJGH5"
      "IOPlatformUUID" = "2AD80C3F-68F4-5F69-A99E-86A4E52B135E"
      "model" = <"MacBookPro18,2">
    }`
	uuid, serial := parseIoreg(out)
	if uuid != "2AD80C3F-68F4-5F69-A99E-86A4E52B135E" || serial != "C02XK0AAJGH5" {
		t.Fatalf("uuid %q serial %q", uuid, serial)
	}
}

func TestParseCheckMember(t *testing.T) {
	cases := map[string]bool{
		"yes jdoe is a member of admin\n":    true,
		"no jdoe is NOT a member of admin\n": false,
	}
	for out, want := range cases {
		got, err := parseCheckMember(out)
		if err != nil || got != want {
			t.Errorf("%q: got %v, %v", out, got, err)
		}
	}
	if _, err := parseCheckMember("dseditgroup: Record was not found.\n"); err == nil {
		t.Error("an unknown answer was taken as an answer")
	}
}

func TestParseSettings(t *testing.T) {
	s, err := parseSettings([]byte(`{"SplunkHECURL":"https://splunk.example:8088","SplunkHECToken":"t","WebhookHeaders":{"Authorization":"Bearer x"},"PayloadUUID":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if s.SplunkHECURL != "https://splunk.example:8088" || s.WebhookHeaders["Authorization"] != "Bearer x" {
		t.Fatalf("got %+v", s)
	}
	if s.QueueMax != 500 || s.SentinelStream != "Custom-AltiwardOCSF" {
		t.Fatalf("defaults: queue max %d, stream %q", s.QueueMax, s.SentinelStream)
	}
}

func TestSinksFor(t *testing.T) {
	all := Settings{
		SplunkHECURL: "https://splunk.example:8088", SplunkHECToken: "t",
		SentinelEndpoint: "https://dcr.example", SentinelDCRID: "dcr-1", SentinelStream: "Custom-AltiwardOCSF",
		SentinelTenantID: "tenant", SentinelClientID: "client", SentinelClientSecret: "secret",
		WebhookURL: "https://collector.example/events",
	}
	sinks, err := SinksFor(all)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range sinks {
		names = append(names, s.Name())
	}
	if strings.Join(names, " ") != "splunk sentinel webhook" {
		t.Fatalf("sinks %v", names)
	}
	if sinks, err := SinksFor(Settings{}); err != nil || len(sinks) != 0 {
		t.Fatalf("empty settings: %d sinks, %v", len(sinks), err)
	}
	bad := map[string]Settings{
		"SplunkHECToken":   {SplunkHECURL: "https://splunk.example:8088"},
		"SentinelDCRID":    {SentinelEndpoint: "https://dcr.example"},
		"WebhookURL https": {WebhookURL: "http://collector.example/events"},
	}
	for want, s := range bad {
		if _, err := SinksFor(s); err == nil || !strings.Contains(err.Error(), strings.Fields(want)[0]) {
			t.Errorf("%s: err %v", want, err)
		}
	}
}

// TestTrustedCAsReachPrivateEndpoint: a destination whose certificate comes from a private CA
// works once that CA is in TrustedCAs; public CAs keep working alongside it.
func TestTrustedCAsReachPrivateEndpoint(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Private CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "collector"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	srv.StartTLS()
	defer srv.Close()

	send := func(s Settings) error {
		sinks, err := SinksFor(s)
		if err != nil {
			return err
		}
		return sinks[0].Send(context.Background(), []ocsf.Record{{"n": 1}})
	}
	if err := send(Settings{WebhookURL: srv.URL}); err == nil {
		t.Fatal("a private CA's certificate was accepted without TrustedCAs")
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	if err := send(Settings{WebhookURL: srv.URL, TrustedCAs: caPEM}); err != nil {
		t.Fatalf("with TrustedCAs: %v", err)
	}
	if _, err := SinksFor(Settings{WebhookURL: srv.URL, TrustedCAs: "not a certificate"}); err == nil || !strings.Contains(err.Error(), "TrustedCAs") {
		t.Fatalf("bad TrustedCAs: err %v", err)
	}
}
