package server_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/deliver"
	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/privileges"
	"github.com/Altiward/altiward-forwarder/internal/server"
	"github.com/Altiward/altiward-forwarder/internal/sink"
	"github.com/Altiward/altiward-forwarder/internal/spool"
)

const fixtures = "../../testdata/privileges-2.6"

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func body(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func spools(t *testing.T, max int, names ...string) []*spool.Spool {
	dir := t.TempDir()
	var out []*spool.Spool
	for _, n := range names {
		out = append(out, &spool.Spool{Dir: filepath.Join(dir, n), Max: max})
	}
	return out
}

func options(t *testing.T, sp []*spool.Spool) server.Options {
	return server.Options{
		Spools: sp, Wake: func() {}, Log: quiet,
		Meta:        ocsf.Meta{Via: ocsf.ViaWebhook, ProductVersion: "0.1.0"},
		Now:         func() time.Time { return time.Date(2026, 10, 20, 9, 0, 1, 0, time.UTC) },
		RejectedDir: filepath.Join(t.TempDir(), "rejected"),
	}
}

func post(t *testing.T, h http.Handler, b []byte, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/privileges", bytes.NewReader(b))
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAcceptsAndSpools(t *testing.T) {
	sp := spools(t, 10, "splunk", "syslog")
	o := options(t, sp)
	woke := 0
	o.Wake = func() { woke++ }
	rec := post(t, server.Handler(o), body(t, "grant-with-reason"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var resp struct{ UID string }
	json.Unmarshal(rec.Body.Bytes(), &resp)
	for _, s := range sp {
		items, _ := s.Oldest(10)
		if len(items) != 1 || items[0].UID != resp.UID {
			t.Errorf("%s: %d items, want the one with uid %s", s.Dir, len(items), resp.UID)
		}
	}
	if woke != 1 {
		t.Errorf("woke %d times", woke)
	}
	// Privileges resending the same change after a lost answer is stored once.
	post(t, server.Handler(o), body(t, "grant-with-reason"))
	if n, _ := sp[0].Len(); n != 1 {
		t.Errorf("%d queued after a resend, want 1", n)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/privileges", nil)
	rec := httptest.NewRecorder()
	server.Handler(options(t, spools(t, 10, "stdout"))).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestSpoolFullAbortsConnection(t *testing.T) {
	srv := httptest.NewServer(server.Handler(options(t, spools(t, 0, "splunk"))))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/privileges", "application/json", bytes.NewReader(body(t, "grant-with-reason")))
	if err == nil {
		resp.Body.Close()
		t.Fatalf("got HTTP %d; want no answer, so Privileges keeps the event queued", resp.StatusCode)
	}
}

func TestBadBodyKeptAndRejected(t *testing.T) {
	o := options(t, spools(t, 10, "splunk"))
	rec := post(t, server.Handler(o), []byte(`{"event":"corp.sap.privileges.granted"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	kept, _ := filepath.Glob(filepath.Join(o.RejectedDir, "*.json"))
	if len(kept) != 1 {
		t.Fatalf("%d rejected bodies kept, want 1", len(kept))
	}
	if b, _ := os.ReadFile(kept[0]); string(b) != `{"event":"corp.sap.privileges.granted"}` {
		t.Fatalf("kept %q", b)
	}
	if n, _ := o.Spools[0].Len(); n != 0 {
		t.Fatalf("%d spooled", n)
	}
}

func TestRejectedBodiesCapped(t *testing.T) {
	o := options(t, spools(t, 10, "splunk"))
	os.MkdirAll(o.RejectedDir, 0o700)
	for i := range 1000 {
		os.WriteFile(filepath.Join(o.RejectedDir, fmt.Sprintf("%04d.json", i)), nil, 0o600)
	}
	if rec := post(t, server.Handler(o), []byte(`not json`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	if kept, _ := filepath.Glob(filepath.Join(o.RejectedDir, "*.json")); len(kept) != 1000 {
		t.Fatalf("%d kept, want the cap of 1000", len(kept))
	}
}

func TestTooLarge413(t *testing.T) {
	big := bytes.Repeat([]byte(" "), privileges.MaxBody+1)
	if rec := post(t, server.Handler(options(t, spools(t, 10, "splunk"))), big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", rec.Code)
	}
}

// tlsServer runs the handler with TLSConfig, as the relay does in direct mode.
func tlsServer(t *testing.T, ca *testCA) (*httptest.Server, *x509Pool) {
	t.Helper()
	certFile, keyFile := files(t, ca.issue(t, "relay", true))
	cfg, err := server.TLSConfig(certFile, keyFile, ca.pool())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(server.Handler(options(t, spools(t, 10, "splunk"))))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &x509Pool{ca}
}

type x509Pool struct{ ca *testCA }

func client(roots *x509Pool, cfg *tls.Config) *http.Client {
	cfg.RootCAs = roots.ca.pool()
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
}

func TestNoClientCertTLSFails(t *testing.T) {
	ca := newCA(t, "Mac CA")
	srv, roots := tlsServer(t, ca)
	resp, err := client(roots, &tls.Config{}).Post(srv.URL+"/v1/privileges", "application/json", bytes.NewReader(body(t, "grant-with-reason")))
	if err == nil {
		resp.Body.Close()
		t.Fatalf("got HTTP %d without a client certificate", resp.StatusCode)
	}
	other := newCA(t, "Someone else's CA").issue(t, "intruder", false)
	resp, err = client(roots, &tls.Config{Certificates: []tls.Certificate{other}}).Post(srv.URL+"/v1/privileges", "application/json", bytes.NewReader(body(t, "grant-with-reason")))
	if err == nil {
		resp.Body.Close()
		t.Fatalf("got HTTP %d with another CA's certificate", resp.StatusCode)
	}
	mac := ca.issue(t, "a Mac", false)
	resp, err = client(roots, &tls.Config{Certificates: []tls.Certificate{mac}}).Post(srv.URL+"/v1/privileges", "application/json", bytes.NewReader(body(t, "grant-with-reason")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d with the right certificate", resp.StatusCode)
	}
}

// TestClientCAListSent: Privileges picks its identity by the CA names the server lists, and
// presents nothing when the list is empty.
func TestClientCAListSent(t *testing.T) {
	ca := newCA(t, "Mac CA")
	srv, roots := tlsServer(t, ca)
	var listed [][]byte
	mac := ca.issue(t, "a Mac", false)
	cfg := &tls.Config{GetClientCertificate: func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		listed = cri.AcceptableCAs
		return &mac, nil
	}}
	resp, err := client(roots, cfg).Post(srv.URL+"/v1/privileges", "application/json", bytes.NewReader(body(t, "grant-with-reason")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(listed) != 1 || !bytes.Equal(listed[0], ca.cert.RawSubject) {
		t.Fatalf("listed %d CA names, want the client CA's", len(listed))
	}
}

func headerOptions(t *testing.T, ca *testCA) server.Options {
	o := options(t, spools(t, 10, "splunk"))
	o.CertHeader, o.ClientCAs = "X-Forwarded-Client-Cert", ca.pool()
	return o
}

// aborted serves one request and reports whether the handler dropped the connection without
// answering (http.ErrAbortHandler), which Privileges treats as "keep the event queued".
func aborted(t *testing.T, h http.Handler, b []byte, header ...string) (gone bool, code int) {
	t.Helper()
	return abortedAt(t, h, "/v1/privileges", b, header...)
}

func abortedAt(t *testing.T, h http.Handler, path string, b []byte, header ...string) (gone bool, code int) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Add(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	defer func() {
		if r := recover(); r != nil {
			if r != http.ErrAbortHandler {
				panic(r)
			}
			gone = true
		}
	}()
	h.ServeHTTP(rec, req)
	return false, rec.Code
}

func TestForwardedCertValid202(t *testing.T) {
	ca := newCA(t, "Mac CA")
	mac := ca.issue(t, "a Mac", false)
	for name, escape := range map[string]func(string) string{"envoy": strictEscape, "query": url.QueryEscape} {
		rec := post(t, server.Handler(headerOptions(t, ca)), body(t, "grant-with-reason"), "X-Forwarded-Client-Cert", xfcc(mac, escape))
		if rec.Code != http.StatusAccepted {
			t.Errorf("%s encoding: status %d: %s", name, rec.Code, rec.Body)
		}
	}
	// Quoted values may hold escaped quotes, as in Envoy's Subject field.
	withSubject := `Subject="CN=a \"quoted\" Mac";` + xfcc(mac, strictEscape)
	if rec := post(t, server.Handler(headerOptions(t, ca)), body(t, "grant-with-reason"), "X-Forwarded-Client-Cert", withSubject); rec.Code != http.StatusAccepted {
		t.Errorf("escaped quotes: status %d: %s", rec.Code, rec.Body)
	}
	// A header captured from Azure Container Apps' ingress, when there is one: it must parse
	// (verifying against no roots then fails for that reason alone).
	if b, err := os.ReadFile("testdata/aca-xfcc.txt"); err == nil {
		err := server.VerifyForwardedCert(strings.TrimSpace(string(b)), nil)
		if err == nil || !strings.Contains(err.Error(), "no client CA") {
			t.Errorf("the captured header didn't parse: %v", err)
		}
	}
}

// A request whose certificate isn't good gets no answer: Privileges deletes an event on any
// HTTP answer, 401 included, and keeps it queued only when the connection fails.
func TestForwardedCertOtherCAAborted(t *testing.T) {
	ca := newCA(t, "Mac CA")
	other := newCA(t, "Someone else's CA").issue(t, "intruder", false)
	if gone, code := aborted(t, server.Handler(headerOptions(t, ca)), body(t, "grant-with-reason"), "X-Forwarded-Client-Cert", xfcc(other, strictEscape)); !gone {
		t.Fatalf("answered %d", code)
	}
}

func TestForwardedCertMissingAborted(t *testing.T) {
	ca := newCA(t, "Mac CA")
	h := server.Handler(headerOptions(t, ca))
	if gone, code := aborted(t, h, body(t, "grant-with-reason")); !gone {
		t.Errorf("no header: answered %d", code)
	}
	for _, value := range []string{"", "Hash=abc", `Cert="not a certificate"`, `Cert="unterminated`} {
		if gone, code := aborted(t, h, body(t, "grant-with-reason"), "X-Forwarded-Client-Cert", value); !gone {
			t.Errorf("%q: answered %d", value, code)
		}
	}
}

func TestForwardedServerCertAborted(t *testing.T) {
	// A certificate the CA issued for a server isn't a Mac's.
	ca := newCA(t, "Mac CA")
	if gone, code := aborted(t, server.Handler(headerOptions(t, ca)), body(t, "grant-with-reason"), "X-Forwarded-Client-Cert", xfcc(ca.issue(t, "relay", true), strictEscape)); !gone {
		t.Fatalf("answered %d", code)
	}
}

// TestForwardedCertQuoteInjection: a client opens a quote that swallows the element a proxy
// appends, so a stolen (public) certificate would be the one checked.
func TestForwardedCertQuoteInjection(t *testing.T) {
	ca := newCA(t, "Mac CA")
	stolen := ca.issue(t, "a real Mac", false)
	attacker := newCA(t, "attacker").issue(t, "attacker", false)
	value := xfcc(stolen, strictEscape) + `;x="` + "," + xfcc(attacker, strictEscape)
	if gone, code := aborted(t, server.Handler(headerOptions(t, ca)), body(t, "grant-with-reason"), "X-Forwarded-Client-Cert", value); !gone {
		t.Fatalf("answered %d", code)
	}
	// Two elements, even well formed, mean the proxy appended rather than replaced.
	two := xfcc(stolen, strictEscape) + "," + xfcc(attacker, strictEscape)
	if gone, code := aborted(t, server.Handler(headerOptions(t, ca)), body(t, "grant-with-reason"), "X-Forwarded-Client-Cert", two); !gone {
		t.Fatalf("two elements: answered %d", code)
	}
}

// TestForwardedCertSecondHeaderLine: a proxy that adds its own line instead of replacing the
// client's mustn't let the client's line be the one read.
func TestForwardedCertSecondHeaderLine(t *testing.T) {
	ca := newCA(t, "Mac CA")
	stolen := ca.issue(t, "a real Mac", false)
	attacker := newCA(t, "attacker").issue(t, "attacker", false)
	if gone, code := aborted(t, server.Handler(headerOptions(t, ca)), body(t, "grant-with-reason"),
		"X-Forwarded-Client-Cert", xfcc(stolen, strictEscape), "X-Forwarded-Client-Cert", xfcc(attacker, strictEscape)); !gone {
		t.Fatalf("answered %d", code)
	}
}

func TestHealthReportsQueues(t *testing.T) {
	sp := spools(t, 10, "splunk")
	sp[0].Put("00000000-0000-5000-8000-000000000001", ocsf.Record{"n": 1})
	d := &deliver.Deliverer{Sink: &sink.Stdout{W: io.Discard}, Spool: sp[0]}
	rec := httptest.NewRecorder()
	server.Health([]*deliver.Deliverer{d}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var got struct {
		Sinks map[string]struct {
			Queued int `json:"queued"`
		} `json:"sinks"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Sinks["stdout"].Queued != 1 {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
}

// lockedBuffer is an io.Writer the deliverer and the test can share.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) lines() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Split(strings.TrimSpace(l.b.String()), "\n")
}

func TestRelayEndToEnd(t *testing.T) {
	sp := spools(t, 10, "stdout")
	out := &lockedBuffer{}
	d := &deliver.Deliverer{Sink: &sink.Stdout{W: out}, Spool: sp[0], Batch: 100, Log: quiet}
	o := options(t, sp)
	o.Wake = d.Wake
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)

	names, _ := filepath.Glob(filepath.Join(fixtures, "*.json"))
	h := server.Handler(o)
	for _, f := range names {
		b, _ := os.ReadFile(f)
		if rec := post(t, h, b); rec.Code != http.StatusAccepted {
			t.Fatalf("%s: status %d", f, rec.Code)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(out.lines()) < len(names) || out.lines()[0] == "" {
		if time.Now().After(deadline) {
			t.Fatalf("got %d lines, want %d", len(out.lines()), len(names))
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, l := range out.lines() {
		var r map[string]any
		if err := json.Unmarshal([]byte(l), &r); err != nil || r["class_uid"] != 3005.0 {
			t.Errorf("line %q", l)
		}
	}
}

type downSink struct{}

func (downSink) Name() string                              { return "splunk" }
func (downSink) Send(context.Context, []ocsf.Record) error { return fmt.Errorf("SIEM is down") }

func TestHealthReportsProblems(t *testing.T) {
	sp := spools(t, 10, "splunk")
	sp[0].Put("00000000-0000-5000-8000-000000000001", ocsf.Record{"n": 1})
	os.WriteFile(filepath.Join(sp[0].Dir, "00000000-0000-5000-8000-000000000002.json.corrupt"), []byte("x"), 0o600)
	held := make(chan struct{})
	d := &deliver.Deliverer{Sink: downSink{}, Spool: sp[0], Log: quiet,
		Sleep: func(ctx context.Context, _ time.Duration) error { close(held); <-ctx.Done(); return ctx.Err() }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	<-held

	rec := httptest.NewRecorder()
	server.Health([]*deliver.Deliverer{d}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var got struct {
		Status string `json:"status"`
		Sinks  map[string]struct {
			Queued    int    `json:"queued"`
			LastError string `json:"last_error"`
			SetAside  int    `json:"set_aside"`
		} `json:"sinks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	s := got.Sinks["splunk"]
	if got.Status != "degraded" || s.Queued != 1 || s.LastError != "SIEM is down" || s.SetAside != 1 {
		t.Fatalf("got %+v", got)
	}
}

// TestDirectModeIsHTTP1: the relay speaks HTTP/1.1 only, so refusing an event closes the
// connection (which Privileges retries) rather than resetting an HTTP/2 stream.
func TestDirectModeIsHTTP1(t *testing.T) {
	ca := newCA(t, "Mac CA")
	certFile, keyFile := files(t, ca.issue(t, "relay", true))
	cfg, err := server.TLSConfig(certFile, keyFile, ca.pool())
	if err != nil {
		t.Fatal(err)
	}
	srv := server.NewServer("127.0.0.1:0", server.Handler(options(t, spools(t, 10, "splunk"))), cfg, quiet)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { srv.Close() })

	mac := ca.issue(t, "a Mac", false)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.pool(), Certificates: []tls.Certificate{mac}}, ForceAttemptHTTP2: true}
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Post("https://"+ln.Addr().String()+"/v1/privileges", "application/json", bytes.NewReader(body(t, "grant-with-reason")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.ProtoMajor != 1 || resp.StatusCode != http.StatusAccepted {
		t.Fatalf("%s %d, want HTTP/1.1 202", resp.Proto, resp.StatusCode)
	}
}

const (
	londonSecret = "a6Jq3vX9pL2mR8tY4wZ7cN1bK5hG0dFs" // gitleaks:allow (test value)
	parisSecret  = "Qe7Rt2Yu9Io4Pa1Sd6Fg3Hj8Kl5Zx0Cv" // gitleaks:allow (test value)
)

func secretOptions(t *testing.T) server.Options {
	o := options(t, spools(t, 10, "splunk"))
	o.URLSecrets = map[string]string{"london": londonSecret, "paris": parisSecret}
	return o
}

// TestURLSecretAccepted: a post to /v1/privileges/<secret> is stored, and the record names the
// secret it came with, so a SIEM can tell sites apart and scope any fake events to one secret.
func TestURLSecretAccepted(t *testing.T) {
	o := secretOptions(t)
	h := server.Handler(o)
	for name, secret := range map[string]string{"london": londonSecret, "paris": parisSecret} {
		req := httptest.NewRequest(http.MethodPost, "/v1/privileges/"+secret, bytes.NewReader(body(t, "grant-with-reason")))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusAccepted {
			t.Fatalf("%s: status %d: %s", name, rec.Code, rec.Body)
		}
		items, _ := o.Spools[0].Oldest(10)
		if len(items) != 1 {
			t.Fatalf("%s: %d queued", name, len(items))
		}
		if got := ocsf.Str(items[0].Record, "unmapped", "altiward", "url_secret_name"); got != name {
			t.Errorf("url_secret_name %q, want %q", got, name)
		}
		o.Spools[0].Delete(items[0].UID)
	}
}

// TestURLSecretWrongAborted: without the right secret there's no answer at all, as with a bad
// certificate, so a Mac with a stale profile keeps its events queued. The log never shows
// what was sent in the path, which could be a real secret mistyped.
func TestURLSecretWrongAborted(t *testing.T) {
	var logs lockedBuffer
	o := secretOptions(t)
	o.Log = slog.New(slog.NewTextHandler(&logs, nil))
	h := server.Handler(o)
	for _, path := range []string{
		"/v1/privileges",
		"/v1/privileges/",
		"/v1/privileges/" + londonSecret + "/",
		"/v1/privileges/" + londonSecret + "x",
		"/v1/privileges/" + londonSecret[:31],
		"/v1/privileges/london",
		"/v1/privileges/" + londonSecret + "/" + parisSecret,
	} {
		if gone, code := abortedAt(t, h, path, body(t, "grant-with-reason")); !gone {
			t.Errorf("%s: answered %d", path, code)
		}
	}
	if n, _ := o.Spools[0].Len(); n != 0 {
		t.Errorf("%d queued", n)
	}
	if out := logs.b.String(); strings.Contains(out, londonSecret[:16]) || !strings.Contains(out, "URL secret") {
		t.Errorf("log:\n%s", out)
	}
}

// TestURLSecretOverTLSWithoutClientCert: in URL-secret mode the relay's own TLS asks for no
// client certificate.
func TestURLSecretOverTLSWithoutClientCert(t *testing.T) {
	ca := newCA(t, "Relay CA")
	certFile, keyFile := files(t, ca.issue(t, "relay", true))
	cfg, err := server.TLSConfig(certFile, keyFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(server.Handler(secretOptions(t)))
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	c := client(&x509Pool{ca}, &tls.Config{})
	resp, err := c.Post(srv.URL+"/v1/privileges/"+londonSecret, "application/json", bytes.NewReader(body(t, "grant-with-reason")))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if resp, err := c.Post(srv.URL+"/v1/privileges/"+parisSecret+"x", "application/json", bytes.NewReader(body(t, "grant-with-reason"))); err == nil {
		resp.Body.Close()
		t.Fatalf("a wrong secret got HTTP %d", resp.StatusCode)
	}
}
