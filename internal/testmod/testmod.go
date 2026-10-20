// Package testmod finds files in the Altiward integrations module for contract tests: the
// server's golden OCSF output and the Sentinel table definition. It works with a go.work
// pointing at a checkout and with the module cache.
package testmod

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// IntegrationsFile returns the path of rel inside github.com/Altiward/altiward/integrations.
func IntegrationsFile(t testing.TB, rel string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/Altiward/altiward/integrations").Output()
	if err != nil {
		t.Fatalf("find the integrations module: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		t.Fatal("the integrations module isn't downloaded: run go mod download")
	}
	return filepath.Join(dir, filepath.FromSlash(rel))
}
