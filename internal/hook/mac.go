package hook

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Altiward/altiward/integrations/sentinel"
	"github.com/Altiward/altiward/integrations/splunk"

	"github.com/Altiward/altiward-forwarder/internal/sink"
	"github.com/Altiward/altiward-forwarder/internal/sink/webhook"
)

// SettingsFile is where an MDM profile's com.altiward.forwarder payload lands.
const SettingsFile = "/Library/Managed Preferences/com.altiward.forwarder.plist"

// LiveEnv is the real Mac. The caller sets Version.
func LiveEnv() Env {
	home, _ := os.UserHomeDir()
	name := os.Getenv("USER")
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return Env{
		Settings: readSettings,
		IsAdmin:  checkAdmin,
		Machine:  machineFacts,
		Sinks:    SinksFor,
		Now:      time.Now,
		Sleep:    time.Sleep,
		StateDir: filepath.Join(home, "Library", "Application Support", "com.altiward.forwarder"),
		User:     name,
		Stdout:   os.Stdout,
		Stderr:   os.Stderr,
	}
}

// readSettings converts the managed preferences with plutil, so no plist library is needed.
// With no profile installed there are no settings, which isn't an error.
func readSettings() (Settings, error) {
	if _, err := os.Stat(SettingsFile); errors.Is(err, fs.ErrNotExist) {
		return parseSettings([]byte("{}"))
	}
	out, err := command(time.Second, "/usr/bin/plutil", "-convert", "json", "-o", "-", SettingsFile)
	if err != nil {
		return Settings{}, fmt.Errorf("plutil %s: %w", SettingsFile, err)
	}
	return parseSettings(out)
}

func parseSettings(b []byte) (Settings, error) {
	var s Settings
	if err := json.Unmarshal(b, &s); err != nil {
		return Settings{}, err
	}
	if s.QueueMax <= 0 {
		s.QueueMax = 500
	}
	if s.SentinelStream == "" {
		s.SentinelStream = "Custom-AltiwardOCSF"
	}
	return s, nil
}

// SinksFor builds the destinations the settings name, in a fixed order. On a Mac, Sentinel
// signs in with an app registration's client secret; give it only the Monitoring Metrics
// Publisher role on the one data collection rule.
func SinksFor(s Settings) ([]sink.Sink, error) {
	httpClient := &http.Client{Timeout: 10 * time.Second}
	if s.TrustedCAs != "" {
		// On top of the system's roots: Go's own check doesn't follow every trust setting
		// macOS has, so a private CA is named here rather than relied on from the keychain.
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(s.TrustedCAs)) {
			return nil, errors.New("TrustedCAs holds no PEM certificates")
		}
		httpClient.Transport = &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}
	}
	var sinks []sink.Sink
	if s.SplunkHECURL != "" {
		if s.SplunkHECToken == "" {
			return nil, errors.New("SplunkHECToken is required with SplunkHECURL")
		}
		sinks = append(sinks, &sink.Splunk{Client: &splunk.Client{URL: s.SplunkHECURL, Token: s.SplunkHECToken, HTTP: httpClient}})
	}
	if s.SentinelEndpoint != "" {
		if s.SentinelDCRID == "" || s.SentinelTenantID == "" || s.SentinelClientID == "" || s.SentinelClientSecret == "" {
			return nil, errors.New("SentinelDCRID, SentinelTenantID, SentinelClientID and SentinelClientSecret are required with SentinelEndpoint")
		}
		stream := s.SentinelStream
		if stream == "" {
			stream = "Custom-AltiwardOCSF"
		}
		sinks = append(sinks, &sink.Sentinel{Client: &sentinel.Client{
			Endpoint: s.SentinelEndpoint, RuleID: s.SentinelDCRID, Stream: stream, HTTP: httpClient,
			Tokens: &sentinel.ClientCredentials{TenantID: s.SentinelTenantID, ClientID: s.SentinelClientID, ClientSecret: s.SentinelClientSecret, HTTP: httpClient},
		}})
	}
	if s.WebhookURL != "" {
		u, err := url.Parse(s.WebhookURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("WebhookURL must be an https URL, got %q", s.WebhookURL)
		}
		sinks = append(sinks, webhook.Client{URL: s.WebhookURL, Headers: s.WebhookHeaders, HTTP: httpClient})
	}
	return sinks, nil
}

// checkAdmin asks Directory Services whether user is in the admin group.
func checkAdmin(user string) (bool, error) {
	// dseditgroup exits 67 for "not a member", so its answer is read from what it prints.
	out, _ := command(time.Second, "/usr/sbin/dseditgroup", "-o", "checkmember", "-m", user, "admin")
	return parseCheckMember(string(out))
}

func parseCheckMember(out string) (bool, error) {
	out = strings.TrimSpace(out)
	switch {
	case strings.HasPrefix(out, "yes "):
		return true, nil
	case strings.HasPrefix(out, "no "):
		return false, nil
	}
	return false, fmt.Errorf("dseditgroup: %q", out)
}

// machineFacts names the Mac as the webhook does (the hardware UUID), plus what the hook can
// add: serial, host name and macOS version.
func machineFacts() (MachineFacts, error) {
	out, err := command(time.Second, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	if err != nil {
		return MachineFacts{}, fmt.Errorf("ioreg: %w", err)
	}
	var f MachineFacts
	f.HardwareUUID, f.Serial = parseIoreg(string(out))
	if b, err := command(500*time.Millisecond, "/usr/sbin/scutil", "--get", "LocalHostName"); err == nil {
		f.Hostname = strings.TrimSpace(string(b))
	} else if h, err := os.Hostname(); err == nil {
		f.Hostname = h
	}
	if b, err := command(500*time.Millisecond, "/usr/bin/sw_vers", "-productVersion"); err == nil {
		f.OSVersion = strings.TrimSpace(string(b))
	}
	return f, nil
}

// command runs a system tool with a time limit: the hook has a few seconds in all, and a
// directory lookup on a Mac bound to an unreachable server can hang.
func command(limit time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

var (
	ioregUUID   = regexp.MustCompile(`"IOPlatformUUID" = "([^"]+)"`)
	ioregSerial = regexp.MustCompile(`"IOPlatformSerialNumber" = "([^"]+)"`)
)

func parseIoreg(out string) (uuid, serial string) {
	if m := ioregUUID.FindStringSubmatch(out); m != nil {
		uuid = m[1]
	}
	if m := ioregSerial.FindStringSubmatch(out); m != nil {
		serial = m[1]
	}
	return uuid, serial
}
