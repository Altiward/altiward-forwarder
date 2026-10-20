// Package server takes Privileges' webhook. It answers 202 only after the event is stored
// in every sink's spool, and never answers at all when it can't store it: Privileges treats
// any HTTP answer, even a 503, as delivered, and keeps an event queued only when the
// connection fails.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/deliver"
	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/privileges"
	"github.com/Altiward/altiward-forwarder/internal/spool"
)

// maxRejected caps the bodies kept in RejectedDir, so a misbehaving sender can't fill the disk.
const maxRejected = 1000

type Options struct {
	Spools      []*spool.Spool // one per sink
	Wake        func()         // tells the deliverers a record is waiting
	Meta        ocsf.Meta      // ReceivedAt is set per request
	Now         func() time.Time
	CertHeader  string            // header mode: the proxy's client certificate header
	ClientCAs   *x509.CertPool    // header mode: the CA Macs' certificates must chain to
	URLSecrets  map[string]string // URL-secret mode: name → secret
	RejectedDir string            // where bodies that won't decode are kept
	Log         *slog.Logger
}

// Handler serves POST /v1/privileges, or in URL-secret mode POST /v1/privileges/<secret>.
func Handler(o Options) http.Handler {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	secrets := map[string][sha256.Size]byte{}
	for name, secret := range o.URLSecrets {
		secrets[name] = sha256.Sum256([]byte(secret))
	}
	handle := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		var secretName string
		if len(secrets) > 0 {
			got, ok := strings.CutPrefix(r.URL.Path, "/v1/privileges/")
			if secretName = matchSecret(secrets, got); !ok || secretName == "" {
				// No answer, as with a bad certificate, so a Mac with a stale profile keeps
				// its events. The path isn't logged: it may hold a real secret, mistyped.
				o.Log.Warn("refused a request without a known URL secret; closing the connection", "remote", r.RemoteAddr)
				panic(http.ErrAbortHandler)
			}
		}
		if o.CertHeader != "" {
			err := errors.New("the client certificate header must appear exactly once")
			if values := r.Header.Values(o.CertHeader); len(values) == 1 {
				err = VerifyForwardedCert(values[0], o.ClientCAs)
			}
			if err != nil {
				// No answer, as in direct mode where the TLS handshake fails: an HTTP answer,
				// 401 included, would make Privileges delete the event.
				o.Log.Warn("refused a request without a valid client certificate; closing the connection",
					"remote", r.RemoteAddr, "error", err)
				panic(http.ErrAbortHandler)
			}
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, privileges.MaxBody))
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, privileges.ErrTooLarge.Error(), http.StatusRequestEntityTooLarge)
			return
		}
		if err != nil {
			panic(http.ErrAbortHandler) // the body didn't arrive; let Privileges retry
		}
		e, err := privileges.Decode(body)
		if err != nil {
			kept := keepRejected(o.RejectedDir, body)
			o.Log.Warn("rejected a body that isn't a Privileges event; Privileges won't resend it",
				"remote", r.RemoteAddr, "error", err, "kept", kept)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		meta := o.Meta
		meta.ReceivedAt, meta.URLSecretName = o.Now(), secretName
		rec := ocsf.FromPrivileges(e, meta)
		uid := ocsf.Str(rec, "metadata", "uid")
		for _, s := range o.Spools {
			if err := s.Put(uid, rec); err != nil {
				// No answer at all, so Privileges keeps the event and sends it again later.
				o.Log.Error("couldn't store an event; closing the connection so Privileges keeps it queued",
					"uid", uid, "spool", s.Dir, "error", err)
				panic(http.ErrAbortHandler)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"uid": uid})
		if o.Wake != nil {
			o.Wake()
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/privileges", handle)
	if len(secrets) > 0 {
		// Everything under /v1/privileges reaches the secret check, bypassing the mux's 404s
		// and its redirects for unclean paths: either would be an answer, and Privileges would
		// delete the event.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/v1/privileges") {
				handle(w, r)
				return
			}
			mux.ServeHTTP(w, r)
		})
	}
	return mux
}

// matchSecret returns the name of the URL secret got is, or "". It compares SHA-256 sums in
// constant time, so neither a secret's content nor its length shows in the timing.
func matchSecret(secrets map[string][sha256.Size]byte, got string) string {
	sum := sha256.Sum256([]byte(got))
	var name string
	for n, want := range secrets {
		if subtle.ConstantTimeCompare(sum[:], want[:]) == 1 {
			name = n
		}
	}
	return name
}

// keepRejected saves a body that didn't decode, named by its hash, unless the cap is reached.
// It returns the file's path, or "" when nothing was kept.
func keepRejected(dir string, body []byte) string {
	if dir == "" {
		return ""
	}
	if old, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(old) >= maxRejected {
		return ""
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return ""
	}
	sum := sha256.Sum256(body)
	path := filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return ""
	}
	return path
}

// Health serves GET /healthz: 200 while the process runs (so a SIEM outage doesn't get the
// relay restarted), with "status": "degraded" when a destination is failing or has records
// set aside, and each destination's queue and last error, so a problem shows up without
// reading logs.
func Health(ds []*deliver.Deliverer) http.Handler {
	type sinkStatus struct {
		Queued      int        `json:"queued"`
		SetAside    int        `json:"set_aside,omitempty"`
		LastError   string     `json:"last_error,omitempty"`
		LastSuccess *time.Time `json:"last_success,omitempty"`
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		status := "ok"
		sinks := map[string]sinkStatus{}
		for _, d := range ds {
			st := d.Status()
			s := sinkStatus{Queued: st.Queued, SetAside: st.SetAside, LastError: st.LastError}
			if !st.LastSuccess.IsZero() {
				s.LastSuccess = &st.LastSuccess
			}
			if st.LastError != "" || st.SetAside > 0 {
				status = "degraded"
			}
			sinks[d.Sink.Name()] = s
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": status, "sinks": sinks})
	})
	return mux
}

// TLSConfig is the relay's own TLS. In direct mode it requires a client certificate from cas
// in the handshake; Go lists cas' names in the certificate request, which is how Privileges
// chooses which identity to present. With cas nil (URL-secret mode) it asks for none.
func TLSConfig(certFile, keyFile string, cas *x509.CertPool) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	if cas != nil {
		cfg.ClientAuth, cfg.ClientCAs = tls.RequireAndVerifyClientCert, cas
	}
	return cfg, nil
}

// NewServer is the webhook listener: HTTP/1.1 only, so refusing an event closes the whole
// connection, which Privileges retries, rather than resetting one HTTP/2 stream.
func NewServer(addr string, h http.Handler, cfg *tls.Config, log *slog.Logger) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         cfg,
		Protocols:         protocols,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}
