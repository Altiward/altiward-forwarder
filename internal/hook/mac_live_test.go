//go:build darwin

package hook

import (
	"os/user"
	"regexp"
	"testing"
)

// TestLiveMac runs the real commands the hook uses, on the Mac running the tests.
func TestLiveMac(t *testing.T) {
	f, err := machineFacts()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$`).MatchString(f.HardwareUUID) {
		t.Errorf("hardware UUID %q", f.HardwareUUID)
	}
	if f.OSVersion == "" || f.Hostname == "" {
		t.Errorf("facts %+v", f)
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkAdmin(u.Username); err != nil {
		t.Errorf("admin check for %s: %v", u.Username, err)
	}
	if _, err := readSettings(); err != nil {
		t.Errorf("settings: %v", err)
	}
}
