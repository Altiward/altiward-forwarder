// altiward-forwarder is the relay: it takes SAP Privileges' webhook and forwards each event
// to Splunk, Microsoft Sentinel, syslog or stdout as OCSF. Settings come from FORWARDER_*
// environment variables; see docs/configuration.md.
//
//	altiward-forwarder            run the relay
//	altiward-forwarder health     check a running relay (for a container health check)
//	altiward-forwarder version    print the version
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/config"
	"github.com/Altiward/altiward-forwarder/internal/deliver"
	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/server"
	"github.com/Altiward/altiward-forwarder/internal/spool"
)

var version = "dev" // set with -ldflags "-X main.version=…"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			return
		case "health":
			os.Exit(health())
		default:
			fmt.Fprintf(os.Stderr, "usage: altiward-forwarder [health|version]\n")
			os.Exit(2)
		}
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.FromEnv(os.Getenv)
	if err != nil {
		return err
	}
	sinks, err := cfg.Sinks()
	if err != nil {
		return err
	}
	var cas *x509.CertPool
	if cfg.ClientCAFile != "" {
		pem, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return fmt.Errorf("FORWARDER_CLIENT_CA_FILE: %w", err)
		}
		cas = x509.NewCertPool()
		if !cas.AppendCertsFromPEM(pem) {
			return fmt.Errorf("FORWARDER_CLIENT_CA_FILE %s: no PEM certificates", cfg.ClientCAFile)
		}
	}
	if cfg.AllowUnauthenticated {
		log.Warn("FORWARDER_ALLOW_UNAUTHENTICATED is set: anyone who can reach the relay can send events. Use it only to evaluate.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var spools []*spool.Spool
	var deliverers []*deliver.Deliverer
	for _, s := range sinks {
		name := s.Name()
		sp := &spool.Spool{Dir: filepath.Join(cfg.SpoolDir, name), Max: cfg.SpoolMax,
			SetAside: func(uid string, err error) {
				log.Error("set aside a spooled event that couldn't be read back; it won't be sent",
					"sink", name, "uid", uid, "file", uid+".json.corrupt", "error", err)
			}}
		if err := sp.Init(); err != nil {
			return fmt.Errorf("FORWARDER_SPOOL_DIR: %w", err)
		}
		d := &deliver.Deliverer{Sink: s, Spool: sp, Log: log}
		spools, deliverers = append(spools, sp), append(deliverers, d)
		go d.Run(ctx)
	}
	wake := func() {
		for _, d := range deliverers {
			d.Wake()
		}
	}

	// The relay terminates TLS itself in direct mode, and in URL-secret mode when given a
	// certificate; config.FromEnv refuses a certificate in the other modes.
	ownTLS := cfg.TLSCertFile != ""
	var tlsConfig *tls.Config
	if ownTLS {
		if tlsConfig, err = server.TLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile, cas); err != nil {
			return fmt.Errorf("FORWARDER_TLS_CERT_FILE/FORWARDER_TLS_KEY_FILE: %w", err)
		}
	}
	secrets := map[string]string{}
	for _, s := range cfg.URLSecrets {
		secrets[s.Name] = s.Secret
	}
	api := server.NewServer(cfg.Listen, server.Handler(server.Options{
		Spools: spools, Wake: wake, Log: log,
		Meta:        ocsf.Meta{Via: ocsf.ViaWebhook, ProductVersion: version, TenantUID: cfg.TenantUID},
		CertHeader:  cfg.ClientCertHeader,
		ClientCAs:   cas,
		URLSecrets:  secrets,
		RejectedDir: filepath.Join(cfg.SpoolDir, "rejected"),
	}), tlsConfig, log)
	healthSrv := &http.Server{Addr: cfg.HealthAddr, Handler: server.Health(deliverers), ReadHeaderTimeout: 5 * time.Second}

	errs := make(chan error, 2)
	go func() {
		var err error
		if ownTLS {
			err = api.ListenAndServeTLS("", "")
		} else {
			err = api.ListenAndServe()
		}
		errs <- err
	}()
	go func() { errs <- healthSrv.ListenAndServe() }()
	var mode string
	switch {
	case len(cfg.URLSecrets) > 0:
		mode = fmt.Sprintf("URL secret (%d), %s", len(cfg.URLSecrets), map[bool]string{true: "TLS", false: "plain HTTP behind a proxy"}[ownTLS])
	case cfg.ClientCertHeader != "":
		mode = "client certificate from " + cfg.ClientCertHeader
	case cfg.AllowUnauthenticated:
		mode = "none (plain HTTP)"
	default:
		mode = "direct mTLS"
	}
	log.Info("relay started", "version", version, "listen", cfg.Listen, "health", cfg.HealthAddr,
		"auth", mode, "sinks", len(sinks), "spool", cfg.SpoolDir)

	select {
	case <-ctx.Done():
		log.Info("stopping; queued events stay in the spool")
	case err := <-errs:
		if !errors.Is(err, http.ErrServerClosed) {
			stop()
			return err
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	api.Shutdown(shutdown)
	healthSrv.Shutdown(shutdown)
	return nil
}

// health asks the running relay's health listener, for a container HEALTHCHECK.
func health() int {
	addr := os.Getenv("FORWARDER_HEALTH_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(probeURL(addr))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "health:", resp.Status)
		return 1
	}
	return 0
}

// probeURL turns the health listener's address into a URL to call from the same host: a
// wildcard host becomes 127.0.0.1.
func probeURL(healthAddr string) string {
	host, port, err := net.SplitHostPort(healthAddr)
	if err != nil {
		return "http://" + healthAddr + "/healthz"
	}
	if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz"
}
