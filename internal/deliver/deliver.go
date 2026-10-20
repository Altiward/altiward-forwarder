// Package deliver drains one sink's spool: it sends the oldest records, deletes each only
// after the sink accepted it, and backs off while the sink is failing. Each sink has its own
// deliverer and spool, so one SIEM being down never holds up another.
package deliver

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/sink"
	"github.com/Altiward/altiward-forwarder/internal/spool"
)

// Backoff is the wait after the nth consecutive failure (from 0): 30 s, doubling, capped at
// an hour, as the Altiward server's export does.
func Backoff(n int) time.Duration {
	const max = time.Hour
	d := 30 * time.Second
	for range n {
		d *= 2
		if d >= max {
			return max
		}
	}
	return d
}

// Status is what /healthz reports for a sink.
type Status struct {
	Queued      int
	SetAside    int // records that couldn't be read back, kept as <uid>.json.corrupt
	LastError   string
	LastSuccess time.Time
}

type Deliverer struct {
	Sink  sink.Sink
	Spool *spool.Spool
	Batch int                                        // records per send, default 100
	Sleep func(context.Context, time.Duration) error // waits out a backoff; tests replace it
	Log   *slog.Logger

	once        sync.Once
	wake        chan struct{}
	mu          sync.Mutex
	lastError   string
	lastSuccess time.Time
}

func (d *Deliverer) init() {
	d.once.Do(func() { d.wake = make(chan struct{}, 1) })
}

// Wake tells Run a new record is waiting, so it sends now instead of at its next look.
func (d *Deliverer) Wake() {
	d.init()
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run delivers until ctx ends. Records it hasn't delivered stay in the spool.
func (d *Deliverer) Run(ctx context.Context) {
	d.init()
	batch := d.Batch
	if batch <= 0 {
		batch = 100
	}
	sleep := d.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	log := d.Log
	if log == nil {
		log = slog.Default()
	}
	log = log.With("sink", d.Sink.Name())

	failures := 0
	for ctx.Err() == nil {
		items, err := d.Spool.Oldest(batch)
		if err == nil && len(items) == 0 {
			select {
			case <-ctx.Done():
			case <-d.wake:
			case <-time.After(time.Second):
			}
			continue
		}
		if err == nil {
			records := make([]ocsf.Record, len(items))
			for i, it := range items {
				records[i] = it.Record
			}
			err = d.Sink.Send(ctx, records)
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			wait := Backoff(failures)
			failures++
			d.setError(err.Error())
			log.Warn("delivery failed; records stay queued", "error", err, "retry_in", wait)
			if sleep(ctx, wait) != nil {
				return
			}
			continue
		}
		var deleteErr error
		for _, it := range items {
			if err := d.Spool.Delete(it.UID); err != nil {
				deleteErr = err
			}
		}
		if deleteErr != nil {
			// The records stay and will be sent again, so wait as for a failed send rather than
			// resending them in a tight loop.
			wait := Backoff(failures)
			failures++
			d.setError("delivered but couldn't remove records from the spool: " + deleteErr.Error())
			log.Error("delivered but couldn't remove records from the spool; they will be sent again", "error", deleteErr, "retry_in", wait)
			if sleep(ctx, wait) != nil {
				return
			}
			continue
		}
		failures = 0
		d.setSuccess(len(items), log)
	}
}

func (d *Deliverer) setError(msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lastError = msg
}

func (d *Deliverer) setSuccess(n int, log *slog.Logger) {
	d.mu.Lock()
	recovered := d.lastError != ""
	d.lastError, d.lastSuccess = "", time.Now()
	d.mu.Unlock()
	if recovered {
		log.Info("delivering again", "records", n)
	}
}

// Status reports the queue and the last outcome.
func (d *Deliverer) Status() Status {
	n, _ := d.Spool.Len()
	d.mu.Lock()
	defer d.mu.Unlock()
	return Status{Queued: n, SetAside: d.Spool.Corrupt(), LastError: d.lastError, LastSuccess: d.lastSuccess}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
