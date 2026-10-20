package spool_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Altiward/altiward-forwarder/internal/ocsf"
	"github.com/Altiward/altiward-forwarder/internal/spool"
)

func uid(n int) string { return fmt.Sprintf("00000000-0000-5000-8000-%012d", n) }

func rec(n int) ocsf.Record { return ocsf.Record{"class_uid": 3005, "n": n} }

func newSpool(t *testing.T, max int) *spool.Spool {
	return &spool.Spool{Dir: filepath.Join(t.TempDir(), "splunk"), Max: max}
}

func mustPut(t *testing.T, s *spool.Spool, n int) {
	t.Helper()
	if err := s.Put(uid(n), rec(n)); err != nil {
		t.Fatal(err)
	}
}

// age sets a file's mtime so order doesn't depend on the clock's resolution.
func age(t *testing.T, s *spool.Spool, n int, at time.Time) {
	t.Helper()
	if err := os.Chtimes(filepath.Join(s.Dir, uid(n)+".json"), at, at); err != nil {
		t.Fatal(err)
	}
}

func uids(items []spool.Item) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.UID)
	}
	return out
}

func TestPutOldestDelete(t *testing.T) {
	s := newSpool(t, 10)
	mustPut(t, s, 1)
	items, err := s.Oldest(10)
	if err != nil || len(items) != 1 || items[0].UID != uid(1) {
		t.Fatalf("items %v, err %v", uids(items), err)
	}
	if ocsf.Int(items[0].Record, "class_uid") != 3005 || ocsf.Int(items[0].Record, "n") != 1 {
		t.Fatalf("record %v", items[0].Record)
	}
	if err := s.Delete(uid(1)); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Len(); n != 0 {
		t.Fatalf("len %d after delete", n)
	}
	if err := s.Delete(uid(1)); err != nil {
		t.Fatalf("deleting twice: %v", err)
	}
}

func TestPutDedupes(t *testing.T) {
	s := newSpool(t, 10)
	mustPut(t, s, 1)
	if err := s.Put(uid(1), ocsf.Record{"n": 99}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.Len(); n != 1 {
		t.Fatalf("len %d, want 1", n)
	}
	items, _ := s.Oldest(1)
	if ocsf.Int(items[0].Record, "n") != 1 {
		t.Fatal("the second Put replaced the first")
	}
}

func TestFull(t *testing.T) {
	s := newSpool(t, 2)
	mustPut(t, s, 1)
	mustPut(t, s, 2)
	if err := s.Put(uid(3), rec(3)); !errors.Is(err, spool.ErrFull) {
		t.Fatalf("err %v, want ErrFull", err)
	}
	// A resend of something already queued isn't new, so it isn't refused.
	if err := s.Put(uid(2), rec(2)); err != nil {
		t.Fatalf("resend when full: %v", err)
	}
}

func TestSpoolSurvivesReopen(t *testing.T) {
	s := newSpool(t, 10)
	mustPut(t, s, 1)
	mustPut(t, s, 2)
	again := &spool.Spool{Dir: s.Dir, Max: 10}
	if n, err := again.Len(); n != 2 || err != nil {
		t.Fatalf("len %d, err %v", n, err)
	}
}

func TestOldestOrder(t *testing.T) {
	s := newSpool(t, 10)
	base := time.Now().Add(-time.Hour)
	for _, n := range []int{3, 1, 2} {
		mustPut(t, s, n)
	}
	age(t, s, 3, base)
	age(t, s, 1, base.Add(time.Minute))
	age(t, s, 2, base.Add(time.Minute)) // same time as 1: name breaks the tie
	items, err := s.Oldest(2)
	if err != nil {
		t.Fatal(err)
	}
	if got := uids(items); len(got) != 2 || got[0] != uid(3) || got[1] != uid(1) {
		t.Fatalf("order %v", got)
	}
}

func TestDropOldest(t *testing.T) {
	s := newSpool(t, 10)
	base := time.Now().Add(-time.Hour)
	for n := 1; n <= 3; n++ {
		mustPut(t, s, n)
		age(t, s, n, base.Add(time.Duration(n)*time.Minute))
	}
	dropped, err := s.DropOldest(2)
	if err != nil || dropped != 2 {
		t.Fatalf("dropped %d, err %v", dropped, err)
	}
	items, _ := s.Oldest(10)
	if got := uids(items); len(got) != 1 || got[0] != uid(3) {
		t.Fatalf("left %v", got)
	}
}

func TestRejectsBadUID(t *testing.T) {
	s := newSpool(t, 10)
	for _, bad := range []string{"../x", "", "00000000-0000-5000-8000-00000000000G", "a/b"} {
		if err := s.Put(bad, rec(1)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := s.Delete("../x"); err == nil {
		t.Error("Delete accepted ../x")
	}
}

func TestIgnoresTempFiles(t *testing.T) {
	s := newSpool(t, 10)
	mustPut(t, s, 1)
	// What a crash between create and rename leaves behind.
	if err := os.WriteFile(filepath.Join(s.Dir, ".tmp-123"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	items, err := s.Oldest(10)
	if err != nil || len(items) != 1 {
		t.Fatalf("items %v, err %v", uids(items), err)
	}
	if n, _ := s.Len(); n != 1 {
		t.Fatalf("len %d", n)
	}
}

func TestCorruptFileSetAside(t *testing.T) {
	s := newSpool(t, 10)
	mustPut(t, s, 2)
	if err := os.WriteFile(filepath.Join(s.Dir, uid(1)+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	age(t, s, 1, time.Now().Add(-time.Hour))
	items, err := s.Oldest(10)
	if err != nil || len(items) != 1 || items[0].UID != uid(2) {
		t.Fatalf("items %v, err %v", uids(items), err)
	}
	// Kept for a person to look at, but no longer blocking the queue.
	if _, err := os.Stat(filepath.Join(s.Dir, uid(1)+".json.corrupt")); err != nil {
		t.Fatal(err)
	}
}

func TestEmptySpoolHasNoDirectoryYet(t *testing.T) {
	s := newSpool(t, 10)
	if n, err := s.Len(); n != 0 || err != nil {
		t.Fatalf("len %d, err %v", n, err)
	}
	if items, err := s.Oldest(5); len(items) != 0 || err != nil {
		t.Fatalf("items %v, err %v", uids(items), err)
	}
}

func TestInitMakesAWritableFolder(t *testing.T) {
	s := newSpool(t, 10)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(s.Dir); err != nil || !info.IsDir() {
		t.Fatalf("no folder: %v", err)
	}
	if n, _ := s.Len(); n != 0 {
		t.Fatalf("Init left %d records", n)
	}
}

func TestInitFailsWhenNotWritable(t *testing.T) {
	s := newSpool(t, 10)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	os.Chmod(s.Dir, 0o500)
	t.Cleanup(func() { os.Chmod(s.Dir, 0o700) })
	if err := s.Init(); err == nil {
		t.Fatal("Init passed on a read-only folder")
	}
}

func TestCorruptFileReportedAndCounted(t *testing.T) {
	s := newSpool(t, 10)
	var reported []string
	s.SetAside = func(uid string, err error) { reported = append(reported, uid) }
	mustPut(t, s, 2)
	os.WriteFile(filepath.Join(s.Dir, uid(1)+".json"), []byte("{not json"), 0o600)
	s.Oldest(10)
	if len(reported) != 1 || reported[0] != uid(1) {
		t.Fatalf("reported %v", reported)
	}
	if n := s.Corrupt(); n != 1 {
		t.Fatalf("Corrupt() = %d, want 1", n)
	}
}
