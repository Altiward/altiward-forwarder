package deliver_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/deliver"
	"github.com/Altiward/altiward-forwarder/internal/sink"
	"github.com/Altiward/altiward/integrations/splunk"
)

func TestAmbiguousHECResponsesKeepDeliveryQueued(t *testing.T) {
	for _, response := range []string{"<html>Sign in</html>", "", "null", `{}`, `{"code":null}`, `{"code":"0"}`, `{"code":0} {}`, `{"code":0`} {
		t.Run(response, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, response)
			}))
			defer srv.Close()
			assertHECFailureKeepsSpool(t, &splunk.Client{URL: srv.URL, Token: "synthetic", HTTP: srv.Client()})
		})
	}
}

func TestHECRedirectKeepsDeliveryQueuedWithoutFollowing(t *testing.T) {
	var redirected atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/signin" {
			redirected.Add(1)
			io.WriteString(w, `{"code":0}`)
			return
		}
		http.Redirect(w, r, "/signin", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	assertHECFailureKeepsSpool(t, &splunk.Client{URL: srv.URL, Token: "synthetic", HTTP: srv.Client()})
	if redirected.Load() != 0 {
		t.Fatal("HEC request followed a redirect")
	}
}

func TestTruncatedHECResponseKeepsDeliveryQueued(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		io.WriteString(w, `{"code":0}`)
	}))
	defer srv.Close()
	assertHECFailureKeepsSpool(t, &splunk.Client{URL: srv.URL, Token: "synthetic", HTTP: srv.Client()})
}

func assertHECFailureKeepsSpool(t *testing.T, client *splunk.Client) {
	t.Helper()
	queued := filled(t, 1)
	d := &deliver.Deliverer{Sink: &sink.Splunk{Client: client}, Spool: queued, Log: quiet,
		Sleep: func(context.Context, time.Duration) error { return errors.New("stop after the first delivery attempt") }}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d.Run(ctx)
	status := d.Status()
	if status.Queued != 1 || status.LastError == "" || !status.LastSuccess.IsZero() {
		t.Fatalf("ambiguous acknowledgement changed delivery state: %+v", status)
	}
}
