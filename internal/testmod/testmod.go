// Package testmod finds files in the Altiward integrations module for contract tests: the
// server's golden OCSF output and the Sentinel table definition. It works with a go.work
// pointing at a checkout and with the module cache.
package testmod

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// IntegrationsFile returns the path of rel inside github.com/Altiward/altiward/integrations.
func IntegrationsFile(t testing.TB, rel string) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/Altiward/altiward/integrations").Output()
	dir := strings.TrimSpace(string(out))
	if err == nil && dir != "" {
		return filepath.Join(dir, filepath.FromSlash(rel))
	}
	// A standalone release uses the reviewed vendored clients and their pinned contract
	// fixtures. Find the module root from any package test directory.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		candidate := filepath.Join(dir, "vendor/github.com/Altiward/altiward/integrations", filepath.FromSlash(rel))
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	t.Fatal("integrations contract fixture is absent from the workspace and vendor directory")
	return ""

}
