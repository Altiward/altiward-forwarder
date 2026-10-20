package deliver_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/deliver"
	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/spool"
)

// fakeSink fails its first `failures` sends, then accepts.
type fakeSink struct {
	mu       sync.Mutex
	failures int
	got      []ocsf.Record
}

func (f *fakeSink) Name() string { return "fake" }

func (f *fakeSink) Send(_ context.Context, records []ocsf.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failures > 0 {
		f.failures--
		return errors.New("SIEM is down")
	}
	f.got = append(f.got, records...)
	return nil
}

func (f *fakeSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.got)
}

func filled(t *testing.T, n int) *spool.Spool {
	t.Helper()
	s := &spool.Spool{Dir: filepath.Join(t.TempDir(), "fake"), Max: 100}
	for i := 1; i <= n; i++ {
		if err := s.Put(fmt.Sprintf("00000000-0000-5000-8000-%012d", i), ocsf.Record{"n": i}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// waitFor polls until cond holds, or fails the test after 5 seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestDeliverDeletesAfterSuccess(t *testing.T) {
	s, sink := filled(t, 3), &fakeSink{}
	d := &deliver.Deliverer{Sink: sink, Spool: s, Batch: 2, Log: quiet}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	waitFor(t, "3 records", func() bool { return sink.count() == 3 })
	waitFor(t, "an empty spool", func() bool { n, _ := s.Len(); return n == 0 })
	if st := d.Status(); st.Queued != 0 || st.LastError != "" || st.LastSuccess.IsZero() {
		t.Fatalf("status %+v", st)
	}
}

func TestDeliverRetriesWithBackoff(t *testing.T) {
	s, sink := filled(t, 2), &fakeSink{failures: 2}
	var mu sync.Mutex
	var slept []time.Duration
	d := &deliver.Deliverer{Sink: sink, Spool: s, Batch: 10, Log: quiet,
		Sleep: func(ctx context.Context, dur time.Duration) error {
			mu.Lock()
			slept = append(slept, dur)
			mu.Unlock()
			// While the sink is down, nothing has been removed from the spool.
			if n, _ := s.Len(); n != 2 {
				t.Errorf("%d queued during an outage, want 2", n)
			}
			return nil
		}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	waitFor(t, "delivery after the outage", func() bool { return sink.count() == 2 })
	waitFor(t, "an empty spool", func() bool { n, _ := s.Len(); return n == 0 })
	mu.Lock()
	defer mu.Unlock()
	if len(slept) != 2 || slept[0] != 30*time.Second || slept[1] != 60*time.Second {
		t.Fatalf("slept %v, want [30s 1m0s]", slept)
	}
}

func TestDeliverRecordsTheLastError(t *testing.T) {
	s, sink := filled(t, 1), &fakeSink{failures: 1000}
	block := make(chan struct{})
	d := &deliver.Deliverer{Sink: sink, Spool: s, Batch: 10, Log: quiet,
		Sleep: func(ctx context.Context, _ time.Duration) error {
			select {
			case <-block:
			case <-ctx.Done():
			}
			return ctx.Err()
		}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	waitFor(t, "the error in the status", func() bool { return d.Status().LastError == "SIEM is down" })
	if st := d.Status(); st.Queued != 1 {
		t.Fatalf("status %+v", st)
	}
}

func TestOneSinkDownOtherStillDelivers(t *testing.T) {
	up, down := &fakeSink{}, &fakeSink{failures: 1000}
	upSpool, downSpool := filled(t, 2), filled(t, 2)
	hold := func(ctx context.Context, _ time.Duration) error { <-ctx.Done(); return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&deliver.Deliverer{Sink: down, Spool: downSpool, Batch: 10, Log: quiet, Sleep: hold}).Run(ctx)
	go (&deliver.Deliverer{Sink: up, Spool: upSpool, Batch: 10, Log: quiet}).Run(ctx)
	waitFor(t, "the working sink", func() bool { return up.count() == 2 })
	if n, _ := downSpool.Len(); n != 2 {
		t.Fatalf("the failing sink's spool has %d, want 2 kept", n)
	}
}

func TestWakeDeliversWithoutWaiting(t *testing.T) {
	s, sink := filled(t, 0), &fakeSink{}
	d := &deliver.Deliverer{Sink: sink, Spool: s, Batch: 10, Log: quiet}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go d.Run(ctx)
	time.Sleep(20 * time.Millisecond) // let it find the spool empty and wait
	s.Put("00000000-0000-5000-8000-000000000009", ocsf.Record{"n": 9})
	start := time.Now()
	d.Wake()
	waitFor(t, "the woken delivery", func() bool { return sink.count() == 1 })
	if time.Since(start) > 500*time.Millisecond {
		t.Fatalf("took %v after Wake", time.Since(start))
	}
}

func TestBackoffCap(t *testing.T) {
	cases := map[int]time.Duration{0: 30 * time.Second, 1: time.Minute, 2: 2 * time.Minute, 7: time.Hour, 8: time.Hour, 200: time.Hour}
	for n, want := range cases {
		if got := deliver.Backoff(n); got != want {
			t.Errorf("Backoff(%d) = %v, want %v", n, got, want)
		}
	}
}

// TestDeleteFailureBacksOff: when a delivered record can't be removed from the spool, the
// deliverer must not resend it in a tight loop.
func TestDeleteFailureBacksOff(t *testing.T) {
	s, sink := filled(t, 1), &fakeSink{}
	if err := os.Chmod(s.Dir, 0o500); err != nil { // files can't be removed
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(s.Dir, 0o700) })
	var mu sync.Mutex
	var slept []time.Duration
	d := &deliver.Deliverer{Sink: sink, Spool: s, Batch: 10, Log: quiet,
		Sleep: func(ctx context.Context, dur time.Duration) error {
			mu.Lock()
			slept = append(slept, dur)
			mu.Unlock()
			<-ctx.Done() // hold the backoff until the test ends
			return ctx.Err()
		}}
	ctx, cancel := context.WithCancel(context.Background())
	go d.Run(ctx)
	waitFor(t, "a backoff", func() bool { mu.Lock(); defer mu.Unlock(); return len(slept) > 0 })
	time.Sleep(50 * time.Millisecond)
	if n := sink.count(); n != 1 {
		t.Errorf("sent %d times, want 1 before backing off", n)
	}
	if st := d.Status(); !strings.Contains(st.LastError, "remove") {
		t.Errorf("status %+v, want the delete failure reported", st)
	}
	cancel()
}
