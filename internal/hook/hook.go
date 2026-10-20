// Package hook is altiward-forwarder-hook: Privileges' post-change executable, sending each
// change straight from the Mac for teams with no relay to host.
//
// Privileges runs it as the logged-in user, doesn't wait for it and ignores its exit code,
// and anyone can run it by hand with any arguments. So it reports the user's real admin
// membership rather than what it was told, queues an event it can't send, and finishes within
// Privileges' time budget.
package hook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/privileges"
	"github.com/Altiward/altiward-forwarder/internal/sink"
	"github.com/Altiward/altiward-forwarder/internal/spool"
)

const (
	exitUsage  = 64 // EX_USAGE
	exitNoPerm = 77 // EX_NOPERM
	exitConfig = 78 // EX_CONFIG

	sendBudget    = 4 * time.Second // from the start of a run to the end of its one send attempt
	recheckWithin = time.Second     // a second admin check only if the first was this quick
	maxReason     = 2048
)

// Settings are the com.altiward.forwarder managed preferences.
type Settings struct {
	SplunkHECURL, SplunkHECToken string

	SentinelEndpoint, SentinelDCRID, SentinelStream          string
	SentinelTenantID, SentinelClientID, SentinelClientSecret string

	WebhookURL     string
	WebhookHeaders map[string]string

	// TrustedCAs is PEM text of CA certificates to trust, besides the system's, for every
	// destination: for a SIEM whose certificate a private CA issued.
	TrustedCAs string

	QueueMax int // events kept per destination while it can't be reached; default 500
}

// MachineFacts name the Mac in each event.
type MachineFacts struct{ HardwareUUID, Serial, Hostname, OSVersion string }

// Env is everything that touches the Mac, so tests can replace it.
type Env struct {
	Settings func() (Settings, error)
	IsAdmin  func(user string) (bool, error)
	Machine  func() (MachineFacts, error)
	Sinks    func(Settings) ([]sink.Sink, error)
	Now      func() time.Time
	Sleep    func(time.Duration)
	StateDir string // ~/Library/Application Support/com.altiward.forwarder
	User     string // the user running the hook, for --test
	Version  string // the hook's version, in metadata.product

	Stdout, Stderr io.Writer
}

// state is what the hook remembers between runs, in StateDir/state.json.
type state struct {
	Users   map[string]bool `json:"users"`   // the last membership recorded (sent or queued) per user
	Dropped map[string]int  `json:"dropped"` // per destination: events dropped from a full queue, not yet reported
}

// Run handles one call from Privileges: altiward-forwarder-hook <user> <admin|user> [reason].
func Run(args []string, env Env) int {
	start := env.Now()
	user, claimed, reason, ok := parseArgs(args)
	if !ok {
		fmt.Fprintln(env.Stderr, "usage: altiward-forwarder-hook <user> <admin|user> [reason]")
		return exitUsage
	}
	if env.User != "" && user != env.User {
		fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: called for %s but running as %s; Privileges names the user it runs the hook as, so nothing is sent\n", user, env.User)
		return exitNoPerm
	}
	settings, sinks, code := destinations(env)
	if sinks == nil {
		return code
	}

	// The Mac's details don't depend on the admin check, so read them meanwhile.
	factsc := make(chan MachineFacts, 1)
	go func() {
		facts, err := env.Machine()
		if err != nil {
			fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: couldn't read the Mac's details: %v\n", err)
		}
		factsc <- facts
	}()

	// Privileges can call the hook before the group change is visible, so check twice before
	// believing something other than what it said, if there's time to.
	actual, err := env.IsAdmin(user)
	if err == nil && actual != claimed && env.Now().Sub(start) < recheckWithin {
		env.Sleep(time.Second)
		actual, err = env.IsAdmin(user)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: couldn't check %s's admin membership (%v); reporting what Privileges said\n", user, err)
		actual = claimed
	}
	facts := <-factsc

	st := loadState(env)
	if last, ok := st.Users[user]; ok && last == actual {
		return 0 // already reported
	}
	e := privileges.Event{
		Granted: actual, User: user, Reason: reason, At: start,
		Machine: facts.HardwareUUID, Serial: facts.Serial, Hostname: facts.Hostname, OSVersion: facts.OSVersion,
	}
	rec := ocsf.FromPrivileges(e, ocsf.Meta{Via: ocsf.ViaHook, ReceivedAt: start, ProductVersion: env.Version})
	uid := ocsf.UID(e)

	// Queue first, and remove after a good send: if the hook is stopped mid-send, the event is
	// still there for --flush. A queue may briefly hold QueueMax+1; it's trimmed after a failure.
	// State changes are recorded as deltas, because --flush may update the state meanwhile.
	preDropped := map[string]int{}
	queues := make([]*spool.Spool, len(sinks))
	for i, s := range sinks {
		q := queue(env, s.Name(), settings.QueueMax+1)
		if n, _ := q.Len(); n >= q.Max {
			d, _ := q.DropOldest(n - settings.QueueMax)
			preDropped[s.Name()] += d
		}
		if err := q.Put(uid, rec); err != nil {
			fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: %s: couldn't queue the event: %v\n", s.Name(), err)
		}
		queues[i] = q
	}
	updateState(env, func(st *state) {
		st.Users[user] = actual
		for name, n := range preDropped {
			st.Dropped[name] += n
		}
	})

	budget := sendBudget - env.Now().Sub(start)
	if budget <= 0 {
		fmt.Fprintln(env.Stderr, "altiward-forwarder-hook: no time left to send; queued for later")
		budget = 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	dropped, reported := map[string]int{}, map[string]int{}
	for i, s := range sinks {
		if budget > 0 {
			n := st.Dropped[s.Name()] + preDropped[s.Name()]
			err := s.Send(ctx, []ocsf.Record{withDropped(rec, n)})
			if err == nil {
				reported[s.Name()] = n
				if err := queues[i].Delete(uid); err != nil {
					fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: %s: sent, but couldn't remove it from the queue: %v\n", s.Name(), err)
				}
				continue
			}
			fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: %s: %v; queued for later\n", s.Name(), err)
		}
		if n, _ := queues[i].Len(); n > settings.QueueMax {
			d, _ := queues[i].DropOldest(n - settings.QueueMax)
			dropped[s.Name()] += d
		}
	}
	updateState(env, func(st *state) {
		for name, n := range dropped {
			st.Dropped[name] += n
		}
		st.subtract(reported)
	})
	return 0
}

// Flush sends queued events, oldest first, deleting each only after its destination accepted
// it. For each destination it stops at the first failure, or at an event it sent but couldn't
// remove (it would only send it again). The LaunchAgent runs it every 5 minutes.
//
// It also refreshes the remembered admin state of the user running it, so a change made
// outside Privileges doesn't hide the next one made through it.
func Flush(env Env) int {
	settings, sinks, code := destinations(env)
	if sinks == nil {
		return code
	}
	if env.User != "" {
		if admin, err := env.IsAdmin(env.User); err == nil {
			updateState(env, func(st *state) {
				if _, known := st.Users[env.User]; known {
					st.Users[env.User] = admin
				}
			})
		}
	}
	st := loadState(env)
	reported := map[string]int{}
	code = 0
	for _, s := range sinks {
		q := queue(env, s.Name(), settings.QueueMax)
		for {
			items, err := q.Oldest(1)
			if err != nil || len(items) == 0 {
				break
			}
			n := 0
			if reported[s.Name()] == 0 {
				n = st.Dropped[s.Name()] // reported once, with the first event sent
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err = s.Send(ctx, []ocsf.Record{withDropped(items[0].Record, n)})
			cancel()
			if err != nil {
				fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: %s: %v; will try again\n", s.Name(), err)
				code = 1
				break
			}
			if n > 0 {
				reported[s.Name()] = n
			}
			if err := q.Delete(items[0].UID); err != nil {
				fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: %s: sent, but couldn't remove it from the queue (%v); stopping\n", s.Name(), err)
				code = 1
				break
			}
		}
	}
	updateState(env, func(st *state) { st.subtract(reported) })
	return code
}

// Test sends one event, marked unmapped.altiward.test, to every destination now, and prints
// what happened. It queues nothing.
func Test(env Env) int {
	_, sinks, code := destinations(env)
	if sinks == nil {
		fmt.Fprintln(env.Stdout, "no destination configured in com.altiward.forwarder")
		return 1
	}
	admin, _ := env.IsAdmin(env.User)
	facts, _ := env.Machine()
	now := env.Now()
	e := privileges.Event{
		Granted: admin, User: env.User, Reason: "Test event from altiward-forwarder-hook --test", At: now,
		Machine: facts.HardwareUUID, Serial: facts.Serial, Hostname: facts.Hostname, OSVersion: facts.OSVersion,
	}
	rec := ocsf.FromPrivileges(e, ocsf.Meta{Via: ocsf.ViaHook, ReceivedAt: now, ProductVersion: env.Version})
	rec["unmapped"].(map[string]any)["altiward"].(map[string]any)["test"] = true
	for _, s := range sinks {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := s.Send(ctx, []ocsf.Record{rec})
		cancel()
		if err != nil {
			fmt.Fprintf(env.Stdout, "%s: %v\n", s.Name(), err)
			code = 1
			continue
		}
		fmt.Fprintf(env.Stdout, "%s: sent\n", s.Name())
	}
	return code
}

// destinations reads the settings. It returns nil sinks, and the exit code to use, when
// there's nothing to send to.
func destinations(env Env) (Settings, []sink.Sink, int) {
	settings, err := env.Settings()
	if err != nil {
		fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: settings: %v\n", err)
		return settings, nil, exitConfig
	}
	sinks, err := env.Sinks(settings)
	if err != nil {
		fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: settings: %v\n", err)
		return settings, nil, exitConfig
	}
	if len(sinks) == 0 {
		fmt.Fprintln(env.Stderr, "altiward-forwarder-hook: no destination configured in com.altiward.forwarder; nothing sent")
		return settings, nil, 0
	}
	if settings.QueueMax <= 0 {
		settings.QueueMax = 500
	}
	return settings, sinks, 0
}

func parseArgs(args []string) (user string, admin bool, reason string, ok bool) {
	// Privileges passes user, state and an optional reason; anything a later version adds
	// after those is ignored.
	if len(args) < 2 {
		return "", false, "", false
	}
	user = args[0]
	if user == "" || len(user) > 255 || strings.ContainsAny(user, "/:") || strings.ContainsFunc(user, func(r rune) bool { return r < ' ' }) {
		return "", false, "", false
	}
	switch strings.ToLower(args[1]) {
	case "admin":
		admin = true
	case "user":
	default:
		return "", false, "", false
	}
	if len(args) >= 3 {
		reason = args[2]
		if r := []rune(reason); len(r) > maxReason {
			reason = string(r[:maxReason])
		}
	}
	return user, admin, reason, true
}

func queue(env Env, name string, max int) *spool.Spool {
	if max <= 0 {
		max = 500
	}
	return &spool.Spool{Dir: filepath.Join(env.StateDir, "queue", name), Max: max}
}

// withDropped adds unmapped.altiward.dropped_before to a copy of r when events were lost.
func withDropped(r ocsf.Record, n int) ocsf.Record {
	if n == 0 {
		return r
	}
	out := ocsf.Record{}
	for k, v := range r {
		out[k] = v
	}
	unmapped, _ := r["unmapped"].(map[string]any)
	altiward, _ := unmapped["altiward"].(map[string]any)
	a := map[string]any{"dropped_before": n}
	for k, v := range altiward {
		a[k] = v
	}
	a["dropped_before"] = n
	u := map[string]any{"altiward": a}
	for k, v := range unmapped {
		if k != "altiward" {
			u[k] = v
		}
	}
	out["unmapped"] = u
	return out
}

func loadState(env Env) state {
	st := state{Users: map[string]bool{}, Dropped: map[string]int{}}
	b, err := os.ReadFile(filepath.Join(env.StateDir, "state.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return st
	}
	if err == nil {
		err = json.Unmarshal(b, &st)
	}
	if err != nil {
		fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: state.json: %v; starting afresh\n", err)
		st = state{}
	}
	if st.Users == nil {
		st.Users = map[string]bool{}
	}
	if st.Dropped == nil {
		st.Dropped = map[string]int{}
	}
	return st
}

// updateState applies change to the latest saved state under a lock: --flush and Privileges'
// calls are separate processes, so each reads, changes and saves in one step rather than
// overwriting the other's changes.
func updateState(env Env, change func(*state)) {
	if err := os.MkdirAll(env.StateDir, 0o700); err != nil {
		fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: state: %v\n", err)
		return
	}
	unlock := lockState(env.StateDir)
	defer unlock()
	st := loadState(env)
	change(&st)
	if err := writeAtomic(filepath.Join(env.StateDir, "state.json"), st); err != nil {
		fmt.Fprintf(env.Stderr, "altiward-forwarder-hook: state.json: %v\n", err)
	}
}

// lockState takes an exclusive lock on StateDir/.lock, waiting up to a second; without it
// the update goes ahead unlocked rather than holding up the hook.
func lockState(dir string) (unlock func()) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}
	}
	for deadline := time.Now().Add(time.Second); ; {
		if syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil {
			return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }
		}
		if time.Now().After(deadline) {
			f.Close()
			return func() {}
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// subtract removes counts that were reported in sent events.
func (st *state) subtract(reported map[string]int) {
	for name, n := range reported {
		if st.Dropped[name] -= n; st.Dropped[name] <= 0 {
			delete(st.Dropped, name)
		}
	}
}

func writeAtomic(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
