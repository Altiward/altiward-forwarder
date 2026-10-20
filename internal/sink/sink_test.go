package sink_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward/integrations/sentinel"
	"github.com/Altiward/altiward/integrations/splunk"
	"github.com/Altiward/altiward/integrations/syslog"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/privileges"
	"github.com/Altiward/altiward-forwarder/internal/sink"
)

// spooled is a grant as a sink sees it: read back from the spool, numbers as json.Number.
func spooled(t *testing.T, serial string) ocsf.Record {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../testdata/privileges-2.6", "grant-with-reason.json"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := privileges.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	e.Serial = serial
	j, _ := json.Marshal(ocsf.FromPrivileges(e, ocsf.Meta{Via: ocsf.ViaWebhook, ReceivedAt: e.At, ProductVersion: "0.1.0", TenantUID: "acme"}))
	dec := json.NewDecoder(bytes.NewReader(j))
	dec.UseNumber()
	var r ocsf.Record
	if err := dec.Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

const grantMillis = 1792506383000 // 2026-10-20T14:26:23Z, the fixture's timestamp

func TestSplunkEnvelope(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		for {
			var ev map[string]any
			if err := dec.Decode(&ev); err != nil {
				break
			}
			got = append(got, ev)
		}
		io.WriteString(w, `{"text":"Success","code":0}`)
	}))
	defer srv.Close()

	s := &sink.Splunk{Client: &splunk.Client{URL: srv.URL, Token: "t"}, Index: "mac"}
	if err := s.Send(context.Background(), []ocsf.Record{spooled(t, ""), spooled(t, "C02XK0AAJGH5")}); err != nil {
		t.Fatal(err)
	}
	if s.Name() != "splunk" || len(got) != 2 {
		t.Fatalf("name %q, %d events", s.Name(), len(got))
	}
	for i, wantHost := range []string{"8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D", "C02XK0AAJGH5"} {
		ev := got[i]
		if ev["sourcetype"] != "altiward:ocsf" || ev["source"] != "altiward-forwarder" || ev["index"] != "mac" || ev["host"] != wantHost {
			t.Errorf("envelope %v", ev)
		}
		if ev["time"] != float64(grantMillis)/1000 {
			t.Errorf("time %v", ev["time"])
		}
		if ev["event"].(map[string]any)["class_uid"] != 3005.0 {
			t.Errorf("event %v", ev["event"])
		}
	}
}

func TestSentinelRowFields(t *testing.T) {
	var rows []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		json.NewDecoder(zr).Decode(&rows)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := &sink.Sentinel{Client: &sentinel.Client{Endpoint: srv.URL, RuleID: "dcr-1", Stream: "Custom-AltiwardOCSF", Tokens: token{}}}
	if err := s.Send(context.Background(), []ocsf.Record{spooled(t, "C02XK0AAJGH5")}); err != nil {
		t.Fatal(err)
	}
	if s.Name() != "sentinel" || len(rows) != 1 {
		t.Fatalf("name %q, %d rows", s.Name(), len(rows))
	}
	row := rows[0]
	var keys, columns []string
	for k := range row {
		keys = append(keys, k)
	}
	for _, c := range strings.Fields(sentinel.Columns) {
		columns = append(columns, strings.Split(c, ":")[0])
	}
	sort.Strings(keys)
	sort.Strings(columns)
	if strings.Join(keys, " ") != strings.Join(columns, " ") {
		t.Errorf("row keys %v, table columns %v", keys, columns)
	}
	want := map[string]any{
		"ClassUid": 3005.0, "ActivityId": 1.0, "SeverityId": 1.0, "TenantUid": "acme", "SessionUid": "",
		"DeviceSerial": "C02XK0AAJGH5", "UserName": "jdoe", "TimeGenerated": "2026-10-20T14:26:23Z",
	}
	for k, v := range want {
		if row[k] != v {
			t.Errorf("%s = %v, want %v", k, row[k], v)
		}
	}
	if !strings.HasPrefix(row["Message"].(string), "jdoe was granted admin rights") || row["EventUid"] == "" {
		t.Errorf("row %v", row)
	}
}

type token struct{}

func (token) Token(context.Context) (string, error) { return "t", nil }

func TestSyslogCEFAndJSON(t *testing.T) {
	for _, format := range []string{"cef", "json"} {
		t.Run(format, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			lines := make(chan string, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				lines <- line
			}()

			s := &sink.Syslog{Client: &syslog.Client{Addr: ln.Addr().String(), Framing: syslog.Newline, Timeout: 5 * time.Second}, Format: format}
			if err := s.Send(context.Background(), []ocsf.Record{spooled(t, "")}); err != nil {
				t.Fatal(err)
			}
			var line string
			select {
			case line = <-lines:
			case <-time.After(5 * time.Second):
				t.Fatal("nothing reached the syslog listener")
			}
			line = strings.TrimSuffix(line, "\n")
			// <PRI>1 TIMESTAMP HOST APP PROCID MSGID SD BODY; PRI = authpriv(10)*8 + info(6)
			prefix := "<86>1 2026-10-20T14:26:23.000Z altiward-forwarder altiward-forwarder - elevation.granted - "
			if !strings.HasPrefix(line, prefix) {
				t.Fatalf("line %q", line)
			}
			body := strings.TrimPrefix(line, prefix)
			if format == "cef" && !strings.HasPrefix(body, "CEF:0|Altiward|Altiward Forwarder|") {
				t.Errorf("body %q", body)
			}
			if format == "json" {
				var r map[string]any
				if err := json.Unmarshal([]byte(body), &r); err != nil || r["class_uid"] != 3005.0 {
					t.Errorf("body %q (%v)", body, err)
				}
			}
		})
	}
}

func TestStdoutOneLinePerRecord(t *testing.T) {
	var buf bytes.Buffer
	s := &sink.Stdout{W: &buf}
	if err := s.Send(context.Background(), []ocsf.Record{spooled(t, ""), spooled(t, "")}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if s.Name() != "stdout" || len(lines) != 2 {
		t.Fatalf("name %q, lines %q", s.Name(), lines)
	}
	for _, l := range lines {
		var r map[string]any
		if err := json.Unmarshal([]byte(l), &r); err != nil || r["class_uid"] != 3005.0 {
			t.Errorf("line %q (%v)", l, err)
		}
	}
}
