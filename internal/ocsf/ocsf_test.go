package ocsf_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/privileges"
	"github.com/Altiward/altiward-forwarder/internal/testmod"
)

// go test ./internal/ocsf -run GoldenRecords -update rewrites testdata/ocsf, the forwarder's
// OCSF output that altiward-siem copies as fixtures.
var update = flag.Bool("update", false, "rewrite testdata/ocsf from testdata/privileges-2.6")

const (
	fixtures  = "../../testdata/privileges-2.6"
	goldenDir = "../../testdata/ocsf"
)

func event(t *testing.T, name string) privileges.Event {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := privileges.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

var webhook = ocsf.Meta{Via: ocsf.ViaWebhook, ReceivedAt: time.Date(2026, 10, 20, 9, 0, 1, 0, time.UTC), ProductVersion: "0.1.0"}

// asJSON round-trips a record so assertions see what a SIEM sees.
func asJSON(t *testing.T, r ocsf.Record) map[string]any {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func get(m map[string]any, path string) any {
	var v any = m
	for _, k := range strings.Split(path, ".") {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}

// paths lists every leaf key path in m.
func paths(m map[string]any, prefix string) []string {
	var out []string
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			out = append(out, paths(sub, prefix+k+".")...)
			continue
		}
		out = append(out, prefix+k)
	}
	sort.Strings(out)
	return out
}

func TestUIDStable(t *testing.T) {
	a, b := event(t, "grant-with-reason"), event(t, "grant-with-reason")
	if ocsf.UID(a) != ocsf.UID(b) {
		t.Fatal("the same event gave two UIDs")
	}
	b.User = "someone"
	if ocsf.UID(a) == ocsf.UID(b) {
		t.Fatal("a different user gave the same UID")
	}
	if got := get(asJSON(t, ocsf.FromPrivileges(a, webhook)), "metadata.uid"); got != ocsf.UID(a) {
		t.Fatalf("metadata.uid %v", got)
	}
}

func TestGrantRecord(t *testing.T) {
	r := asJSON(t, ocsf.FromPrivileges(event(t, "grant-with-reason"), webhook))
	want := map[string]any{
		"class_uid": 3005.0, "category_uid": 3.0, "activity_id": 1.0, "type_uid": 300501.0,
		"activity_name": "Assign Privileges", "type_name": "User Access Management: Assign Privileges",
		"severity_id": 1.0, "severity": "Informational", "status_id": 1.0, "status": "Success",
		"time":                               float64(time.Date(2026, 10, 20, 14, 26, 23, 0, time.UTC).UnixMilli()),
		"metadata.version":                   "1.9.0",
		"metadata.logged_time":               float64(webhook.ReceivedAt.UnixMilli()),
		"metadata.product.name":              "Altiward Forwarder",
		"metadata.product.vendor_name":       "Altiward",
		"metadata.product.version":           "0.1.0",
		"device.uid":                         "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D",
		"device.os.type_id":                  300.0,
		"user.name":                          "jdoe",
		"message":                            "jdoe was granted admin rights on 8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D via SAP Privileges: Installing a printer driver",
		"unmapped.altiward.event_type":       "elevation.granted",
		"unmapped.altiward.source":           "privileges",
		"unmapped.altiward.reported_by":      "privileges_webhook",
		"unmapped.altiward.verified":         false,
		"unmapped.altiward.reason":           "Installing a printer driver",
		"unmapped.altiward.expires_time":     float64(time.Date(2026, 10, 20, 14, 31, 23, 0, time.UTC).UnixMilli()),
		"unmapped.altiward.custom_data.site": "lab",
	}
	for path, w := range want {
		if got := get(r, path); got != w {
			t.Errorf("%s = %v, want %v", path, got, w)
		}
	}
	if !reflect.DeepEqual(r["privileges"], []any{"admin"}) {
		t.Errorf("privileges %v", r["privileges"])
	}
	for _, absent := range []string{"metadata.tenant_uid", "metadata.labels", "device.hw_info", "device.hostname"} {
		if get(r, absent) != nil {
			t.Errorf("%s should be absent", absent)
		}
	}
}

func TestRevokeRecord(t *testing.T) {
	r := asJSON(t, ocsf.FromPrivileges(event(t, "revoke-manual"), webhook))
	want := map[string]any{
		"activity_id": 2.0, "type_uid": 300502.0, "activity_name": "Revoke Privileges",
		"unmapped.altiward.event_type":  "elevation.revoked",
		"unmapped.altiward.source":      "privileges",
		"unmapped.altiward.reported_by": "privileges_webhook",
		"message":                       "jdoe's admin rights on 8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D were revoked via SAP Privileges: requested by user",
	}
	for path, w := range want {
		if got := get(r, path); got != w {
			t.Errorf("%s = %v, want %v", path, got, w)
		}
	}
	if get(r, "unmapped.altiward.expires_time") != nil {
		t.Error("a revoke has no expiry")
	}
}

func TestEmptyFieldsOmitted(t *testing.T) {
	e := event(t, "grant-with-reason")
	e.Machine, e.Reason, e.Expires, e.Custom = "", "", nil, nil
	r := asJSON(t, ocsf.FromPrivileges(e, ocsf.Meta{Via: ocsf.ViaWebhook, ReceivedAt: webhook.ReceivedAt, TenantUID: "acme"}))
	for _, absent := range []string{"device.uid", "unmapped.altiward.expires_time", "unmapped.altiward.reason", "unmapped.altiward.custom_data"} {
		if get(r, absent) != nil {
			t.Errorf("%s should be absent", absent)
		}
	}
	if msg, _ := r["message"].(string); msg != "jdoe was granted admin rights on an unknown Mac via SAP Privileges" {
		t.Errorf("message %q", msg)
	}
	if get(r, "metadata.tenant_uid") != "acme" {
		t.Error("tenant_uid missing")
	}
}

func TestDelayedLabel(t *testing.T) {
	r := asJSON(t, ocsf.FromPrivileges(event(t, "grant-delayed"), webhook))
	if !reflect.DeepEqual(get(r, "metadata.labels"), []any{"delayed"}) {
		t.Fatalf("labels %v", get(r, "metadata.labels"))
	}
	// time stays when the change happened, not when it arrived.
	if get(r, "time") != float64(time.Date(2026, 10, 20, 14, 23, 7, 0, time.UTC).UnixMilli()) {
		t.Fatalf("time %v", get(r, "time"))
	}
}

func TestHookFieldsInDevice(t *testing.T) {
	e := event(t, "grant-with-reason")
	e.Serial, e.Hostname, e.OSVersion = "C02XK0AAJGH5", "lab-mac", "26.1.0"
	r := asJSON(t, ocsf.FromPrivileges(e, ocsf.Meta{Via: ocsf.ViaHook, ReceivedAt: webhook.ReceivedAt}))
	want := map[string]any{
		"device.hw_info.serial_number":  "C02XK0AAJGH5",
		"device.hostname":               "lab-mac",
		"device.os.version":             "26.1.0",
		"unmapped.altiward.reported_by": "privileges_hook",
		"message":                       "jdoe was granted admin rights on C02XK0AAJGH5 via SAP Privileges: Installing a printer driver",
	}
	for path, w := range want {
		if got := get(r, path); got != w {
			t.Errorf("%s = %v, want %v", path, got, w)
		}
	}
}

// TestMatchesAltiwardShape holds the forwarder to the server's own OCSF output for the same
// change (integrations/ocsf-examples, written by the server's TestGoldenExamples), so
// detections, the Sentinel table and the dashboards work for both.
func TestMatchesAltiwardShape(t *testing.T) {
	same := []string{
		"class_uid", "class_name", "category_uid", "category_name", "activity_id", "activity_name",
		"type_uid", "type_name", "time", "severity_id", "severity", "status_id", "status",
		"metadata.version", "device.uid", "device.os.name", "device.os.type", "device.os.type_id",
		"user.name", "unmapped.altiward.event_type", "unmapped.altiward.source",
		"unmapped.altiward.reason", "unmapped.altiward.expires_time",
	}
	ours := []string{"unmapped.altiward.reported_by", "unmapped.altiward.verified", "unmapped.altiward.custom_data", "device.hostname"}

	for _, name := range []string{"elevation-granted", "elevation-revoked"} {
		t.Run(name, func(t *testing.T) {
			b, err := os.ReadFile(testmod.IntegrationsFile(t, "ocsf-examples/"+name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var records []map[string]any
			if err := json.Unmarshal(b, &records); err != nil || len(records) != 1 {
				t.Fatalf("want one record, got %d (%v)", len(records), err)
			}
			golden := records[0]

			// The same change, as Privileges would report it.
			e := privileges.Event{
				Granted: get(golden, "activity_id") == 1.0,
				User:    get(golden, "user.name").(string),
				Machine: get(golden, "device.uid").(string),
				At:      time.UnixMilli(int64(get(golden, "time").(float64))).UTC(),
				Delayed: slices.Contains(asStrings(get(golden, "metadata.labels")), "delayed"),
			}
			if s, ok := get(golden, "unmapped.altiward.reason").(string); ok {
				e.Reason = s
			}
			if ms, ok := get(golden, "unmapped.altiward.expires_time").(float64); ok {
				exp := time.UnixMilli(int64(ms)).UTC()
				e.Expires = &exp
			}
			for _, via := range []ocsf.Via{ocsf.ViaWebhook, ocsf.ViaHook} {
				e := e
				if via == ocsf.ViaHook {
					e.Serial, e.Hostname, e.OSVersion = "C02XK0AAJGH5", "lab-mac", "26.1.0"
				}
				r := asJSON(t, ocsf.FromPrivileges(e, ocsf.Meta{Via: via, ReceivedAt: e.At, ProductVersion: "0.1.0", TenantUID: "acme"}))
				for _, p := range same {
					if !reflect.DeepEqual(get(r, p), get(golden, p)) {
						t.Errorf("%s: %s = %v, the server has %v", via, p, get(r, p), get(golden, p))
					}
				}
				if !reflect.DeepEqual(r["privileges"], golden["privileges"]) {
					t.Errorf("%s: privileges %v, the server has %v", via, r["privileges"], golden["privileges"])
				}
				for _, p := range paths(r, "") {
					if get(golden, p) == nil && !slices.ContainsFunc(ours, func(o string) bool { return p == o || strings.HasPrefix(p, o+".") }) {
						t.Errorf("%s: %s isn't in the server's record", via, p)
					}
				}
			}
		})
	}
}

func asStrings(v any) []string {
	var out []string
	if l, ok := v.([]any); ok {
		for _, s := range l {
			if s, ok := s.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func TestCEFOneLine(t *testing.T) {
	e := event(t, "grant-with-reason")
	e.Reason = "a\nb|c=d é"
	line := ocsf.CEF(ocsf.FromPrivileges(e, webhook))
	if strings.ContainsAny(line, "\r\n") {
		t.Fatalf("line break in %q", line)
	}
	if !strings.HasPrefix(line, "CEF:0|Altiward|Altiward Forwarder|0.1.0|elevation.granted|User Access Management: Assign Privileges|1|") {
		t.Errorf("header in %q", line)
	}
	for _, want := range []string{`cs3=a\nb|c\=d é`, "cs4=privileges", "cs6=elevation.granted", "duser=jdoe", "deviceExternalId=8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D", "rt=1792506383000"} {
		if !strings.Contains(line, want) {
			t.Errorf("no %q in %q", want, line)
		}
	}
}

func TestCEFRecordsFromJSON(t *testing.T) {
	// The relay renders records it read back from its spool, where numbers are json.Number.
	var r ocsf.Record
	b, _ := json.Marshal(ocsf.FromPrivileges(event(t, "revoke-manual"), webhook))
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	if got, want := ocsf.CEF(r), ocsf.CEF(ocsf.FromPrivileges(event(t, "revoke-manual"), webhook)); got != want {
		t.Fatalf("from JSON:\n%s\nfrom the event:\n%s", got, want)
	}
	if ocsf.Int(r, "class_uid") != 3005 || ocsf.Str(r, "user", "name") != "jdoe" {
		t.Fatal("Int/Str can't read a decoded record")
	}
}

// TestGoldenRecords keeps testdata/ocsf: one file per webhook fixture, plus a grant reported
// by the hook, each a JSON array holding one record (the format of the server's
// integrations/ocsf-examples).
func TestGoldenRecords(t *testing.T) {
	type golden struct {
		name string
		e    privileges.Event
		via  ocsf.Via
	}
	var want []golden
	files, _ := filepath.Glob(filepath.Join(fixtures, "*.json"))
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		want = append(want, golden{name, event(t, name), ocsf.ViaWebhook})
	}
	hook := event(t, "grant-with-reason")
	hook.Serial, hook.Hostname, hook.OSVersion = "C02XK0AAJGH5", "lab-mac", "26.1.0"
	want = append(want, golden{"hook-grant-with-reason", hook, ocsf.ViaHook})

	keep := map[string]bool{}
	for _, g := range want {
		keep[g.name+".json"] = true
		rec := ocsf.FromPrivileges(g.e, ocsf.Meta{Via: g.via, ReceivedAt: g.e.At, ProductVersion: "0.0.0-test"})
		b, err := json.MarshalIndent([]ocsf.Record{rec}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		b = append(b, '\n')
		path := filepath.Join(goldenDir, g.name+".json")
		if *update {
			if err := os.MkdirAll(goldenDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, b, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, b) {
			t.Errorf("%s is missing or out of date: run go test ./internal/ocsf -run GoldenRecords -update", path)
		}
	}
	stale, _ := filepath.Glob(filepath.Join(goldenDir, "*.json"))
	for _, f := range stale {
		if keep[filepath.Base(f)] {
			continue
		}
		if *update {
			os.Remove(f)
			continue
		}
		t.Errorf("%s has no fixture: run go test ./internal/ocsf -run GoldenRecords -update", f)
	}
}
