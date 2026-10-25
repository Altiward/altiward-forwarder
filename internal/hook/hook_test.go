package hook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/hook"
	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/sink"
)

// fakeSink records what it accepted; calls listed in failOn (counted from 1) fail.
type fakeSink struct {
	name      string
	calls     int
	failOn    map[int]bool
	failAll   bool
	got       []ocsf.Record
	deadlines []time.Duration
	before    func() // runs at the start of each Send
	limit     int    // when set, calls after this many fail (keeps a looping bug from hanging a test)
}

func (f *fakeSink) Name() string { return f.name }

func (f *fakeSink) Send(ctx context.Context, records []ocsf.Record) error {
	f.calls++
	if f.before != nil {
		f.before()
	}
	if d, ok := ctx.Deadline(); ok {
		f.deadlines = append(f.deadlines, time.Until(d))
	}
	if f.failAll || f.failOn[f.calls] || f.limit > 0 && f.calls > f.limit {
		return errors.New("offline")
	}
	f.got = append(f.got, records...)
	return nil
}

// fake is a Mac: a clock that only moves when the hook sleeps, an admin group, settings.
type fake struct {
	now      time.Time
	slept    []time.Duration
	admin    []bool // answers to successive admin checks; the last one repeats
	checks   int
	settings hook.Settings
	sinks    []*fakeSink
	dir      string
	out, err bytes.Buffer
}

func newFake(t *testing.T, sinks ...*fakeSink) *fake {
	return &fake{now: time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC), dir: t.TempDir(), sinks: sinks, settings: hook.Settings{QueueMax: 500}}
}

func (f *fake) env() hook.Env {
	return hook.Env{
		Settings: func() (hook.Settings, error) { return f.settings, nil },
		IsAdmin: func(user string) (bool, error) {
			i := min(f.checks, len(f.admin)-1)
			f.checks++
			return f.admin[i], nil
		},
		Machine: func() (hook.MachineFacts, error) {
			return hook.MachineFacts{HardwareUUID: "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D", Serial: "C02XK0AAJGH5", Hostname: "lab-mac", OSVersion: "26.1.0"}, nil
		},
		Sinks: func(hook.Settings) ([]sink.Sink, error) {
			out := make([]sink.Sink, len(f.sinks))
			for i, s := range f.sinks {
				out[i] = s
			}
			return out, nil
		},
		Now:      func() time.Time { return f.now },
		Sleep:    func(d time.Duration) { f.slept = append(f.slept, d); f.now = f.now.Add(d) },
		StateDir: f.dir,
		User:     "jdoe",
		Version:  "0.1.0",
		Stdout:   &f.out,
		Stderr:   &f.err,
	}
}

func (f *fake) queued(t *testing.T, sinkName string) []string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(f.dir, "queue", sinkName, "*.json"))
	return files
}

func altiward(r ocsf.Record) map[string]any {
	return r["unmapped"].(map[string]any)["altiward"].(map[string]any)
}

func TestReportsActualMembership(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{false} // Privileges says admin, but the user isn't in the group
	if code := hook.Run([]string{"jdoe", "admin", "Installing a driver"}, f.env()); code != 0 {
		t.Fatalf("exit %d: %s", code, f.err.String())
	}
	if len(s.got) != 1 || ocsf.Int(s.got[0], "activity_id") != 2 {
		t.Fatalf("got %v, want one Revoke", s.got)
	}
}

func TestRetriesAdminCheckOnce(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{false, true} // the group change shows up a moment after Privileges calls
	hook.Run([]string{"jdoe", "admin"}, f.env())
	if len(f.slept) != 1 || f.slept[0] != time.Second || f.checks != 2 {
		t.Fatalf("slept %v, %d checks", f.slept, f.checks)
	}
	if len(s.got) != 1 || ocsf.Int(s.got[0], "activity_id") != 1 {
		t.Fatalf("got %v, want one Assign", s.got)
	}
}

func TestSkipsUnchangedState(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{true}
	hook.Run([]string{"jdoe", "admin"}, f.env())
	f.now = f.now.Add(time.Minute)
	hook.Run([]string{"jdoe", "admin"}, f.env())
	if len(s.got) != 1 {
		t.Fatalf("%d events, want 1", len(s.got))
	}
	f.admin = []bool{false}
	hook.Run([]string{"jdoe", "user"}, f.env())
	if len(s.got) != 2 {
		t.Fatalf("%d events after a real change, want 2", len(s.got))
	}
}

func TestQueuesWhenOffline(t *testing.T) {
	s := &fakeSink{name: "splunk", failAll: true}
	f := newFake(t, s)
	f.admin = []bool{true}
	start := f.now
	if code := hook.Run([]string{"jdoe", "admin"}, f.env()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if q := f.queued(t, "splunk"); len(q) != 1 {
		t.Fatalf("%d queued, want 1", len(q))
	}
	if f.now.Sub(start) >= 5*time.Second {
		t.Fatalf("took %v on the hook's clock", f.now.Sub(start))
	}
	if len(s.deadlines) != 1 || s.deadlines[0] > 4*time.Second {
		t.Fatalf("send deadlines %v, want one of at most 4s", s.deadlines)
	}
	// Queued, so the state is recorded: the same call again adds nothing.
	hook.Run([]string{"jdoe", "admin"}, f.env())
	if q := f.queued(t, "splunk"); len(q) != 1 {
		t.Fatalf("%d queued after a repeat, want 1", len(q))
	}
}

func TestFrozenClockTransitionsAreDistinctAndFlushKeepsTheirIDs(t *testing.T) {
	s := &fakeSink{name: "splunk", failAll: true}
	f := newFake(t, s)
	for _, admin := range []bool{true, false, true} {
		f.admin = []bool{admin}
		state := map[bool]string{true: "admin", false: "user"}[admin]
		if code := hook.Run([]string{"jdoe", state, "same reason"}, f.env()); code != 0 {
			t.Fatalf("exit %d: %s", code, f.err.String())
		}
	}
	queued := f.queued(t, "splunk")
	if len(queued) != 3 {
		t.Fatalf("%d queued at one timestamp, want 3", len(queued))
	}
	want := map[string]bool{}
	for _, path := range queued {
		want[strings.TrimSuffix(filepath.Base(path), ".json")] = true
	}
	s.failAll = false
	if code := hook.Flush(f.env()); code != 0 {
		t.Fatalf("flush exit %d: %s", code, f.err.String())
	}
	if len(s.got) != 3 {
		t.Fatalf("flushed %d events, want 3", len(s.got))
	}
	for _, rec := range s.got {
		uid := ocsf.Str(rec, "metadata", "uid")
		if !want[uid] {
			t.Fatalf("flush changed UID to %s", uid)
		}
		delete(want, uid)
	}
	if len(want) != 0 || len(f.queued(t, "splunk")) != 0 {
		t.Fatal("flush did not deliver all original queued identities")
	}
}

func TestQueueCapDropsOldest(t *testing.T) {
	s := &fakeSink{name: "splunk", failAll: true}
	f := newFake(t, s)
	f.settings.QueueMax = 2
	for i, admin := range []bool{true, false, true} {
		f.admin = []bool{admin}
		f.now = f.now.Add(time.Duration(i+1) * time.Minute)
		state := map[bool]string{true: "admin", false: "user"}[admin]
		hook.Run([]string{"jdoe", state}, f.env())
	}
	if q := f.queued(t, "splunk"); len(q) != 2 {
		t.Fatalf("%d queued, want 2", len(q))
	}
	s.failAll = false
	f.admin = []bool{false}
	f.now = f.now.Add(time.Minute)
	hook.Run([]string{"jdoe", "user"}, f.env())
	if len(s.got) != 1 || ocsf.Int(altiward(s.got[0]), "dropped_before") != 1 {
		t.Fatalf("got %v, want the next event to say 1 was dropped", s.got)
	}
	// Reported once: the event after that doesn't repeat it.
	f.admin = []bool{true}
	f.now = f.now.Add(time.Minute)
	hook.Run([]string{"jdoe", "admin"}, f.env())
	if _, ok := altiward(s.got[1])["dropped_before"]; ok {
		t.Fatal("dropped_before repeated")
	}
}

func TestFlushStopsAtFirstFailure(t *testing.T) {
	s := &fakeSink{name: "splunk", failAll: true}
	f := newFake(t, s)
	for i, admin := range []bool{true, false, true} {
		f.admin = []bool{admin}
		f.now = f.now.Add(time.Duration(i+1) * time.Minute)
		hook.Run([]string{"jdoe", map[bool]string{true: "admin", false: "user"}[admin]}, f.env())
	}
	queued := f.queued(t, "splunk")
	if len(queued) != 3 {
		t.Fatalf("%d queued, want 3", len(queued))
	}
	// Order the files as the spool does (oldest first) so the test knows which goes first.
	s.failAll, s.calls, s.failOn = false, 0, map[int]bool{2: true}
	hook.Flush(f.env())
	if len(s.got) != 1 {
		t.Fatalf("%d sent, want 1", len(s.got))
	}
	if q := f.queued(t, "splunk"); len(q) != 2 {
		t.Fatalf("%d left, want 2", len(q))
	}
	if ocsf.Int(s.got[0], "activity_id") != 1 {
		t.Fatalf("sent %v first, want the oldest (a grant)", s.got[0])
	}
}

func TestQueuesPerDestination(t *testing.T) {
	up, down := &fakeSink{name: "splunk"}, &fakeSink{name: "webhook", failAll: true}
	f := newFake(t, up, down)
	f.admin = []bool{true}
	hook.Run([]string{"jdoe", "admin"}, f.env())
	if len(up.got) != 1 || len(f.queued(t, "splunk")) != 0 || len(f.queued(t, "webhook")) != 1 {
		t.Fatalf("splunk got %d, queued splunk %d webhook %d", len(up.got), len(f.queued(t, "splunk")), len(f.queued(t, "webhook")))
	}
	down.failAll = false
	hook.Flush(f.env())
	if len(up.got) != 1 || len(down.got) != 1 {
		t.Fatalf("after flush: splunk %d, webhook %d; want 1 each (no resend to splunk)", len(up.got), len(down.got))
	}
}

func TestNoDestinationIsNotAnError(t *testing.T) {
	f := newFake(t)
	f.admin = []bool{true}
	if code := hook.Run([]string{"jdoe", "admin"}, f.env()); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "queue")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("something was queued with no destination")
	}
	if !strings.Contains(f.err.String(), "no destination") {
		t.Fatalf("stderr %q", f.err.String())
	}
}

func TestReasonWithNewlines(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{true}
	hook.Run([]string{"jdoe", "admin", "a\nb"}, f.env())
	if len(s.got) != 1 {
		t.Fatalf("%d events, want 1", len(s.got))
	}
	b, _ := json.Marshal(s.got[0])
	var r map[string]any
	json.Unmarshal(b, &r)
	if got := r["unmapped"].(map[string]any)["altiward"].(map[string]any)["reason"]; got != "a\nb" {
		t.Fatalf("reason %q", got)
	}
}

func TestHookRecordShape(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{true}
	hook.Run([]string{"jdoe", "admin", "Installing a driver"}, f.env())
	if len(s.got) != 1 {
		t.Fatalf("%d events, want 1", len(s.got))
	}
	r := s.got[0]
	a := altiward(r)
	if a["reported_by"] != "privileges_hook" || a["source"] != "privileges" || a["verified"] != false {
		t.Errorf("altiward %v", a)
	}
	if _, ok := a["expires_time"]; ok {
		t.Error("the hook can't know the expiry")
	}
	if ocsf.Str(r, "device", "hw_info", "serial_number") != "C02XK0AAJGH5" || ocsf.Str(r, "device", "uid") != "8A1B2C3D-4E5F-6A7B-8C9D-0E1F2A3B4C5D" {
		t.Errorf("device %v", r["device"])
	}
	if ocsf.Int(r, "time") != int(f.now.UnixMilli()) || ocsf.Str(r, "metadata", "product", "version") != "0.1.0" {
		t.Errorf("time %v, product %v", r["time"], r["metadata"])
	}
}

func TestBadArgumentsAreAUsageError(t *testing.T) {
	f := newFake(t, &fakeSink{name: "splunk"})
	f.admin = []bool{true}
	for _, args := range [][]string{nil, {"jdoe"}, {"jdoe", "root"}, {"", "admin"}, {"a/b", "admin"}} {
		if code := hook.Run(args, f.env()); code != 64 {
			t.Errorf("%q: exit %d, want 64", args, code)
		}
	}
}

func TestTestFlagSendsOne(t *testing.T) {
	ok, bad := &fakeSink{name: "splunk"}, &fakeSink{name: "webhook", failAll: true}
	f := newFake(t, ok, bad)
	f.admin = []bool{false}
	if code := hook.Test(f.env()); code != 1 {
		t.Fatalf("exit %d with one destination failing, want 1", code)
	}
	if len(ok.got) != 1 || altiward(ok.got[0])["test"] != true {
		t.Fatalf("got %v", ok.got)
	}
	out := f.out.String()
	if !strings.Contains(out, "splunk: sent") || !strings.Contains(out, "webhook: offline") {
		t.Fatalf("output %q", out)
	}
	if len(f.queued(t, "webhook")) != 0 {
		t.Fatal("a test event was queued")
	}
}

// TestQueuedBeforeSending: the event is in the queue before the send starts, so a hook stopped
// mid-send (Privileges' time budget, a watchdog) still has it for --flush.
func TestQueuedBeforeSending(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{true}
	seen := -1
	s.before = func() { seen = len(f.queued(t, "splunk")) }
	hook.Run([]string{"jdoe", "admin"}, f.env())
	if seen != 1 {
		t.Fatalf("%d queued while sending, want 1", seen)
	}
	if q := f.queued(t, "splunk"); len(q) != 0 || len(s.got) != 1 {
		t.Fatalf("after a good send: %d queued, %d sent", len(q), len(s.got))
	}
}

// TestNoTimeLeftLeavesItQueued: when the checks used up the time budget, the hook doesn't
// start a send it can't finish; the event waits for --flush.
func TestNoTimeLeftLeavesItQueued(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	env := f.env()
	env.IsAdmin = func(string) (bool, error) { f.now = f.now.Add(5 * time.Second); return true, nil }
	if code := hook.Run([]string{"jdoe", "admin"}, env); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if s.calls != 0 || len(f.queued(t, "splunk")) != 1 {
		t.Fatalf("%d sends, %d queued; want 0 and 1", s.calls, len(f.queued(t, "splunk")))
	}
}

// TestSlowAdminCheckSkipsRetry: a slow directory leaves no time to wait and ask again.
func TestSlowAdminCheckSkipsRetry(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	env := f.env()
	checks := 0
	env.IsAdmin = func(string) (bool, error) { checks++; f.now = f.now.Add(2 * time.Second); return false, nil }
	hook.Run([]string{"jdoe", "admin"}, env)
	if checks != 1 || len(f.slept) != 0 {
		t.Fatalf("%d checks, slept %v; want 1 and none", checks, f.slept)
	}
	if len(s.got) != 1 || ocsf.Int(s.got[0], "activity_id") != 2 {
		t.Fatalf("got %v, want the Revoke the check found", s.got)
	}
}

// TestRefusesAnotherUser: Privileges runs the hook as the user it names, so a call naming
// someone else was made by hand, and would put a false grant in the SIEM.
func TestRefusesAnotherUser(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{true}
	if code := hook.Run([]string{"ceo", "admin", "x"}, f.env()); code != 77 {
		t.Fatalf("exit %d, want 77", code)
	}
	if s.calls != 0 || len(f.queued(t, "splunk")) != 0 {
		t.Fatalf("%d sends, %d queued", s.calls, len(f.queued(t, "splunk")))
	}
}

func TestIgnoresExtraArguments(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{true}
	if code := hook.Run([]string{"jdoe", "admin", "a reason", "something new"}, f.env()); code != 0 || len(s.got) != 1 {
		t.Fatalf("exit %d, %d sent", code, len(s.got))
	}
	if r := altiward(s.got[0])["reason"]; r != "a reason" {
		t.Fatalf("reason %v", r)
	}
}

// TestFlushStopsWhenDeleteFails: an event that was sent but can't be removed isn't sent again
// and again in the same run.
func TestFlushStopsWhenDeleteFails(t *testing.T) {
	s := &fakeSink{name: "splunk", failAll: true}
	f := newFake(t, s)
	f.admin = []bool{true}
	hook.Run([]string{"jdoe", "admin"}, f.env())
	dir := filepath.Join(f.dir, "queue", "splunk")
	os.Chmod(dir, 0o500)
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	s.failAll, s.calls, s.limit = false, 0, 5
	if code := hook.Flush(f.env()); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if s.calls != 1 {
		t.Fatalf("sent %d times, want 1", s.calls)
	}
	if !strings.Contains(f.err.String(), "remove") {
		t.Fatalf("stderr %q", f.err.String())
	}
}

// TestDroppedCountSurvivesConcurrentUpdate: --flush and a Privileges call run as separate
// processes; a count another run added while this one was sending isn't lost.
func TestDroppedCountSurvivesConcurrentUpdate(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{true}
	statePath := filepath.Join(f.dir, "state.json")
	os.WriteFile(statePath, []byte(`{"users":{},"dropped":{"splunk":1}}`), 0o600)
	s.before = func() {
		// Another run drops one more event meanwhile.
		os.WriteFile(statePath, []byte(`{"users":{},"dropped":{"splunk":2}}`), 0o600)
	}
	hook.Run([]string{"jdoe", "admin"}, f.env())
	if len(s.got) != 1 || ocsf.Int(altiward(s.got[0]), "dropped_before") != 1 {
		t.Fatalf("got %v, want the event to report the 1 known when it was built", s.got)
	}
	b, _ := os.ReadFile(statePath)
	var st struct{ Dropped map[string]int }
	json.Unmarshal(b, &st)
	if st.Dropped["splunk"] != 1 {
		t.Fatalf("state %s: want 1 drop still to report (2 counted, 1 reported)", b)
	}
}

// TestFlushRefreshesRememberedState: after admin rights changed outside Privileges, the next
// grant through Privileges isn't mistaken for one already reported.
func TestFlushRefreshesRememberedState(t *testing.T) {
	s := &fakeSink{name: "splunk"}
	f := newFake(t, s)
	f.admin = []bool{true}
	hook.Run([]string{"jdoe", "admin"}, f.env()) // reported: admin
	f.admin = []bool{false}                      // removed outside Privileges
	hook.Flush(f.env())
	f.admin = []bool{true}
	f.now = f.now.Add(time.Minute)
	hook.Run([]string{"jdoe", "admin"}, f.env())
	if len(s.got) != 2 {
		t.Fatalf("%d events, want the second grant reported too", len(s.got))
	}
}
