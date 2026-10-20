// Package spool keeps OCSF records on disk until a sink has accepted them: one file per
// record, named by its metadata.uid, so a resend of the same change is stored once.
//
// A record is acknowledged to Privileges only after Put returns, and Put returns only after
// the file and its directory entry are synced, so an acknowledged event survives a crash.
package spool

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
)

// ErrFull means the spool holds Max records, so a new one isn't taken.
var ErrFull = errors.New("spool: full")

// Item is one queued record.
type Item struct {
	UID    string
	Record ocsf.Record
}

// Spool is a directory of queued records. The directory is created on the first Put.
type Spool struct {
	Dir string
	Max int

	// SetAside, when set, hears about each record that couldn't be read back and was renamed
	// <uid>.json.corrupt, so a person can be told.
	SetAside func(uid string, err error)

	mu sync.Mutex
}

// Init creates the folder, syncs its entry in the parent so the folder itself survives a
// crash, and checks that a file can be written in it. Run it at startup, so a spool that
// can't be written stops the relay rather than every event being refused later.
func (s *Spool) Init() error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(s.Dir)); err != nil {
		return err
	}
	probe, err := os.CreateTemp(s.Dir, ".tmp-probe-*")
	if err != nil {
		return fmt.Errorf("spool %s isn't writable: %w", s.Dir, err)
	}
	probe.Close()
	return os.Remove(probe.Name())
}

// Corrupt counts the records set aside as unreadable.
func (s *Spool) Corrupt() int {
	files, _ := filepath.Glob(filepath.Join(s.Dir, "*.json.corrupt"))
	return len(files)
}

var validUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (s *Spool) path(uid string) (string, error) {
	if !validUID.MatchString(uid) {
		return "", fmt.Errorf("spool: bad uid %q", uid)
	}
	return filepath.Join(s.Dir, uid+".json"), nil
}

// Put stores r under uid. A uid already queued is left as it is and returns nil.
func (s *Spool) Put(uid string, r ocsf.Record) error {
	path, err := s.path(uid)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := os.Stat(path); err == nil {
		return nil
	}
	n, err := s.count()
	if err != nil {
		return err
	}
	if n >= s.Max {
		return ErrFull
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("spool: encode %s: %w", uid, err)
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.Dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncDir(s.Dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

type entry struct {
	uid string
	mod time.Time
}

// entries lists queued records, oldest first, then by name.
func (s *Spool) entries() ([]entry, error) {
	des, err := os.ReadDir(s.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []entry
	for _, de := range des {
		uid, ok := strings.CutSuffix(de.Name(), ".json")
		if !ok || !validUID.MatchString(uid) || !de.Type().IsRegular() {
			continue
		}
		info, err := de.Info()
		if err != nil {
			continue // deleted since ReadDir
		}
		out = append(out, entry{uid, info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].mod.Equal(out[j].mod) {
			return out[i].mod.Before(out[j].mod)
		}
		return out[i].uid < out[j].uid
	})
	return out, nil
}

func (s *Spool) count() (int, error) {
	es, err := s.entries()
	return len(es), err
}

// Oldest returns up to n records, oldest first. Numbers decode as json.Number. A file that
// won't decode is renamed to <uid>.json.corrupt, so it no longer blocks the queue but is
// still there for a person to look at.
func (s *Spool) Oldest(n int) ([]Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	es, err := s.entries()
	if err != nil {
		return nil, err
	}
	var items []Item
	for _, e := range es {
		if len(items) == n {
			break
		}
		path := filepath.Join(s.Dir, e.uid+".json")
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return items, err
		}
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.UseNumber()
		var r ocsf.Record
		if err := dec.Decode(&r); err != nil {
			if err := os.Rename(path, path+".corrupt"); err != nil {
				return items, err
			}
			if s.SetAside != nil {
				s.SetAside(e.uid, err)
			}
			continue
		}
		items = append(items, Item{UID: e.uid, Record: r})
	}
	return items, nil
}

// Delete removes a record once its sink has accepted it. Deleting one that isn't there is
// not an error.
func (s *Spool) Delete(uid string) error {
	path, err := s.path(uid)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Len counts the queued records.
func (s *Spool) Len() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count()
}

// DropOldest removes up to n of the oldest records and says how many it removed. Only the
// on-Mac hook uses it, to keep its queue within QueueMax.
func (s *Spool) DropOldest(n int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	es, err := s.entries()
	if err != nil {
		return 0, err
	}
	dropped := 0
	for _, e := range es {
		if dropped == n {
			break
		}
		if err := os.Remove(filepath.Join(s.Dir, e.uid+".json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return dropped, err
		}
		dropped++
	}
	return dropped, nil
}
