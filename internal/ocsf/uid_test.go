package ocsf

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/privileges"
)

func TestUUIDv5Vector(t *testing.T) {
	// RFC 9562, Appendix A.4.
	dns := mustUUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if got := uuid5(dns, "www.example.com"); got != "2ed6657d-e927-568b-95e1-2665a8aea6a2" {
		t.Fatalf("got %s", got)
	}
}

func TestUIDSeparatesSourceChangesAndScopes(t *testing.T) {
	at := time.Date(2026, 10, 25, 12, 0, 0, 100, time.UTC)
	expires := at.Add(5 * time.Minute)
	base := privileges.Event{Granted: true, Machine: "mac", User: "alice", At: at, Expires: &expires, Reason: "ticket 1"}
	meta := Meta{Via: ViaWebhook, TenantUID: "tenant", URLSecretName: "london"}
	want := UID(base, meta)
	for name, change := range map[string]func(*privileges.Event, *Meta){
		"nanosecond":          func(e *privileges.Event, _ *Meta) { e.At = e.At.Add(time.Nanosecond) },
		"whole-second reason": func(e *privileges.Event, _ *Meta) { e.Reason = "ticket 2" },
		"whole-second expiry": func(e *privileges.Event, _ *Meta) { exp := expires.Add(time.Second); e.Expires = &exp },
		"custom data":         func(e *privileges.Event, _ *Meta) { e.Custom = map[string]any{"site": "Paris"} },
		"transition":          func(e *privileges.Event, _ *Meta) { e.TransitionID = "new observation" },
		"tenant":              func(_ *privileges.Event, m *Meta) { m.TenantUID = "other" },
		"URL secret name":     func(_ *privileges.Event, m *Meta) { m.URLSecretName = "paris" },
		"source":              func(_ *privileges.Event, m *Meta) { m.Via = ViaHook },
	} {
		t.Run(name, func(t *testing.T) {
			e, m := base, meta
			change(&e, &m)
			if UID(e, m) == want {
				t.Fatal("distinct change or scope shared the original UID")
			}
		})
	}
}

func TestUIDRetryIgnoresReceiptDetailsAndCanonicalisesTimeAndObjects(t *testing.T) {
	decode := func(body string) privileges.Event {
		t.Helper()
		e, err := privileges.Decode([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	a := decode(`{"event":"corp.sap.privileges.granted","user":"alice","timestamp":"2026-10-25T12:00:00.100Z","custom_data":{"b":2,"a":{"x":1}}}`)
	b := decode(`{"custom_data":{"a":{"x":1},"b":2},"timestamp":"2026-10-25T13:00:00.1+01:00","user":"alice","event":"corp.sap.privileges.granted","delayed":true}`)
	first := Meta{Via: ViaWebhook, ReceivedAt: a.At, ProductVersion: "0.1.0", URLSecretName: "london"}
	retry := first
	retry.ReceivedAt = a.At.Add(time.Hour)
	retry.ProductVersion = "0.2.0"
	if UID(a, first) != UID(b, retry) {
		t.Fatal("a delayed/reordered retry changed UID")
	}
	// The emitted form stays a UUID string. Sentinel's EventUid and CEF's externalId
	// carry this exact value, independently of the SIEM's millisecond event time.
	r := FromPrivileges(a, first)
	encoded, err := json.Marshal(r)
	if err != nil || len(Str(r, "metadata", "uid")) != 36 || len(encoded) == 0 {
		t.Fatalf("invalid emitted identifier or record: %v", err)
	}
	if !strings.Contains(CEF(r), "externalId="+UID(a, first)) {
		t.Fatal("CEF changed the event identifier")
	}
}

func TestUIDUsesUnambiguousFields(t *testing.T) {
	a := privileges.Event{Machine: "mac|alice", User: "bob", At: time.Unix(1, 0)}
	b := a
	b.Machine, b.User = "mac", "alice|bob"
	if UID(a, Meta{}) == UID(b, Meta{}) {
		t.Fatal("delimiter-bearing source fields shared an identity")
	}
}

func TestUIDRetainsAcceptedPrecisionBeyondNanoseconds(t *testing.T) {
	decode := func(timestamp, expiry string) privileges.Event {
		t.Helper()
		body, err := json.Marshal(map[string]string{
			"event": "corp.sap.privileges.granted", "user": "alice", "timestamp": timestamp, "expires": expiry,
		})
		if err != nil {
			t.Fatal(err)
		}
		e, err := privileges.Decode(body)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	a := decode("2026-10-25T12:00:00.1000000001Z", "2026-10-25T12:05:00.1000000001Z")
	b := decode("2026-10-25T13:00:00.100000000100+01:00", "2026-10-25T13:05:00.100000000100+01:00")
	if UID(a, Meta{}) != UID(b, Meta{}) {
		t.Fatal("equivalent full-precision timestamps changed retry UID")
	}
	for _, e := range []privileges.Event{
		decode("2026-10-25T12:00:00.1000000002Z", "2026-10-25T12:05:00.1000000001Z"),
		decode("2026-10-25T12:00:00.1000000001Z", "2026-10-25T12:05:00.1000000002Z"),
	} {
		if UID(a, Meta{}) == UID(e, Meta{}) {
			t.Fatal("accepted fractional digits beyond nanoseconds were lost")
		}
	}
	// Go's RFC 3339 parser also accepts a single-digit hour and a comma fraction.
	c := decode("2026-10-25T1:00:00,1000000001Z", "")
	d := decode("2026-10-25T01:00:00.100000000100Z", "")
	if UID(c, Meta{}) != UID(d, Meta{}) {
		t.Fatal("equivalent accepted hour/fraction spellings changed UID")
	}
	d = decode("2026-10-25T1:00:00.1000000002Z", "")
	if UID(c, Meta{}) == UID(d, Meta{}) {
		t.Fatal("single-digit hour lost accepted fractional precision")
	}
}
