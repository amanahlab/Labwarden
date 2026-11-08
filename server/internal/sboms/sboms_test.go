package sboms

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPutExtractRoundTrip(t *testing.T) {
	f, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	body := `{"artifacts":[],"source":{"type":"image"}}`
	sha, size, err := f.Put(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	if sha != hex.EncodeToString(sum[:]) || size != int64(len(body)) {
		t.Fatalf("sha=%s size=%d", sha, size)
	}
	path, err := f.Extract(sha)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	got, _ := os.ReadFile(path)
	if string(got) != body {
		t.Fatalf("extracted %q", got)
	}
}

func TestPutRejectsEmpty(t *testing.T) {
	f, _ := New(t.TempDir())
	if _, _, err := f.Put(strings.NewReader("")); err == nil {
		t.Fatal("empty sbom accepted")
	}
	if entries, _ := os.ReadDir(f.dir); len(entries) != 0 {
		t.Fatalf("left %d files behind", len(entries))
	}
}

func TestExtractRejectsPathTricks(t *testing.T) {
	f, _ := New(t.TempDir())
	if _, err := f.Extract("../../etc/passwd"); err == nil {
		t.Fatal("accepted a path as sbom id")
	}
}

func TestGCKeepsReferencedAndRecentFiles(t *testing.T) {
	f, _ := New(t.TempDir())
	kept, _, _ := f.Put(strings.NewReader("kept"))
	recent, _, _ := f.Put(strings.NewReader("recent, maybe still queued"))
	old, _, _ := f.Put(strings.NewReader("old and unreferenced"))
	past := time.Now().Add(-48 * time.Hour)
	for _, sha := range []string{kept, old} {
		p, _ := f.path(sha)
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatal(err)
		}
	}
	n, err := f.GC(map[string]bool{kept: true}, 24*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("deleted %d, err %v; want 1", n, err)
	}
	for sha, want := range map[string]bool{kept: true, recent: true, old: false} {
		p, _ := f.path(sha)
		if _, err := os.Stat(p); (err == nil) != want {
			t.Errorf("%s exists=%v, want %v", filepath.Base(p), err == nil, want)
		}
	}
}
