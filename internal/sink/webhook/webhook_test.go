package webhook_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/sink"
	"github.com/Altiward/altiward-forwarder/internal/sink/webhook"
)

var _ sink.Sink = webhook.Client{}

func TestWebhookSendsArray(t *testing.T) {
	var got []map[string]any
	var auth, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, ctype = r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := webhook.Client{URL: srv.URL, Headers: map[string]string{"Authorization": "Bearer x"}}
	records := []ocsf.Record{{"class_uid": 3005, "n": 1}, {"class_uid": 3005, "n": 2}}
	if err := c.Send(context.Background(), records); err != nil {
		t.Fatal(err)
	}
	if c.Name() != "webhook" || len(got) != 2 || got[1]["n"] != 2.0 {
		t.Fatalf("name %q, got %v", c.Name(), got)
	}
	if auth != "Bearer x" || ctype != "application/json" {
		t.Fatalf("headers %q %q", auth, ctype)
	}
}

func TestWebhookNon2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()
	err := webhook.Client{URL: srv.URL}.Send(context.Background(), []ocsf.Record{{"n": 1}})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err %v, want one naming the status", err)
	}
}
