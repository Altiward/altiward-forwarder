package privileges_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/privileges"
)

const fixtures = "../../testdata/privileges-2.6"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func at(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDecodeFixtures(t *testing.T) {
	type want struct {
		granted, delayed bool
		reason, at       string
		expires          string // "" for none
	}
	cases := map[string]want{
		"grant-with-reason": {granted: true, reason: "Installing a printer driver", at: "2026-10-20T14:26:23Z", expires: "2026-10-20T14:31:23Z"},
		"revoke-manual":     {reason: "requested by user", at: "2026-10-20T14:26:18Z"},
		"revoke-expired":    {reason: "privileges expired", at: "2026-10-20T14:31:24Z"},
		"grant-delayed":     {granted: true, delayed: true, reason: "Updating the VPN client", at: "2026-10-20T14:23:07Z", expires: "2026-10-20T14:28:07Z"},
	}
	files, _ := filepath.Glob(filepath.Join(fixtures, "*.json"))
	if len(files) != len(cases) {
		t.Fatalf("%d fixture files, %d cases: give every fixture a case", len(files), len(cases))
	}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			e, err := privileges.Decode(fixture(t, name))
			if err != nil {
				t.Fatal(err)
			}
			if e.Granted != w.granted || e.Delayed != w.delayed || e.User != "jdoe" || e.Reason != w.reason {
				t.Errorf("got %+v", e)
			}
			if e.Machine != "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D" {
				t.Errorf("machine %q", e.Machine)
			}
			if !e.At.Equal(at(t, w.at)) {
				t.Errorf("at %v, want %s", e.At, w.at)
			}
			switch {
			case w.expires == "" && e.Expires != nil:
				t.Errorf("expires %v, want none", e.Expires)
			case w.expires != "" && (e.Expires == nil || !e.Expires.Equal(at(t, w.expires))):
				t.Errorf("expires %v, want %s", e.Expires, w.expires)
			}
		})
	}
	e, _ := privileges.Decode(fixture(t, "grant-with-reason"))
	if e.Custom["site"] != "lab" {
		t.Errorf("custom %v", e.Custom)
	}
}

func TestDecodeIgnoresUnknown(t *testing.T) {
	body := strings.Replace(string(fixture(t, "grant-with-reason")), `"admin":true`, `"admin":true,"new_field":{"x":1}`, 1)
	if _, err := privileges.Decode([]byte(body)); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeEmptyStrings(t *testing.T) {
	e, err := privileges.Decode([]byte(`{"admin":true,"delayed":false,"event":"corp.sap.privileges.granted","expires":"","machine":"","reason":"","timestamp":"2026-10-20T09:00:00Z","user":"jdoe"}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.Expires != nil || e.Machine != "" || e.Reason != "" || e.Custom != nil {
		t.Errorf("got %+v", e)
	}
}

func TestDecodeIgnoresCustomDataThatIsNotAnObject(t *testing.T) {
	body := strings.Replace(string(fixture(t, "grant-with-reason")), `{"site":"lab"}`, `"lab"`, 1)
	e, err := privileges.Decode([]byte(body))
	if err != nil || e.Custom != nil {
		t.Fatalf("custom %v, err %v", e.Custom, err)
	}
}

func TestDecodeRejectsMissing(t *testing.T) {
	good := string(fixture(t, "revoke-manual"))
	cases := map[string]string{
		"event":     strings.Replace(good, `"event":"corp.sap.privileges.revoked",`, ``, 1),
		"user":      strings.Replace(good, `,"user":"jdoe"`, ``, 1),
		"timestamp": strings.Replace(good, `"timestamp":"2026-10-20T14:26:18Z",`, ``, 1),
	}
	cases["event "] = strings.Replace(good, `corp.sap.privileges.revoked`, `corp.sap.privileges.other`, 1)
	cases["user "] = strings.Replace(good, `"user":"jdoe"`, `"user":""`, 1)
	for field, body := range cases {
		if body == good {
			t.Fatalf("%s: the case didn't change the body", field)
		}
		_, err := privileges.Decode([]byte(body))
		if err == nil || !strings.Contains(err.Error(), strings.TrimSpace(field)) {
			t.Errorf("%s: err %v, want one naming the field", field, err)
		}
	}
}

func TestDecodeRejectsDisagreement(t *testing.T) {
	body := strings.Replace(string(fixture(t, "grant-with-reason")), `"admin":true`, `"admin":false`, 1)
	if _, err := privileges.Decode([]byte(body)); err == nil {
		t.Fatal("admin false with a grant: want an error")
	}
}

func TestDecodeTooLarge(t *testing.T) {
	body := make([]byte, privileges.MaxBody+1)
	if _, err := privileges.Decode(body); !errors.Is(err, privileges.ErrTooLarge) {
		t.Fatalf("err %v, want ErrTooLarge", err)
	}
}

func TestDecodeKeepsLargeNumbersInCustomData(t *testing.T) {
	body := strings.Replace(string(fixture(t, "grant-with-reason")), `{"site":"lab"}`, `{"asset":12345678901234567890}`, 1)
	e, err := privileges.Decode([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(e.Custom)
	if string(b) != `{"asset":12345678901234567890}` {
		t.Fatalf("custom_data became %s", b)
	}
}
