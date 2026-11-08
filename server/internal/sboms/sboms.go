// Package sboms keeps uploaded SBOMs on disk, gzipped and named by the
// SHA-256 of their content, so the server can match them again whenever the
// vulnerability DB changes. The store's target_sboms table says which file
// is the latest for each target.
package sboms

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Files struct{ dir string }

func New(dir string) (*Files, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Files{dir: dir}, nil
}

func (f *Files) path(sha string) (string, error) {
	if !shaRe.MatchString(sha) {
		return "", fmt.Errorf("invalid sbom id %q", sha)
	}
	return filepath.Join(f.dir, sha+".json.gz"), nil
}

// Put streams r to disk without holding it in memory and returns its
// SHA-256 and uncompressed size. Storing the same content again refreshes
// the file's time, which the garbage collector goes by.
func (f *Files) Put(r io.Reader) (sha string, size int64, err error) {
	tmp, err := os.CreateTemp(f.dir, ".upload-*")
	if err != nil {
		return "", 0, err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	h := sha256.New()
	gz, _ := gzip.NewWriterLevel(tmp, gzip.BestSpeed)
	if size, err = io.Copy(io.MultiWriter(gz, h), r); err != nil {
		return "", 0, err
	}
	if size == 0 {
		return "", 0, errors.New("empty sbom")
	}
	if err = gz.Close(); err != nil {
		return "", 0, err
	}
	if err = tmp.Close(); err != nil {
		return "", 0, err
	}
	sha = hex.EncodeToString(h.Sum(nil))
	dst, _ := f.path(sha)
	if err = os.Rename(tmp.Name(), dst); err != nil {
		return "", 0, err
	}
	return sha, size, nil
}

// Extract writes the SBOM to a temporary file for grype; the caller removes it.
func (f *Files) Extract(sha string) (string, error) {
	src, err := f.path(sha)
	if err != nil {
		return "", err
	}
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return "", err
	}
	out, err := os.CreateTemp("", "labwarden-sbom-*.json")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, gz); err != nil {
		out.Close()
		os.Remove(out.Name())
		return "", err
	}
	return out.Name(), out.Close()
}

// GC deletes files not in keep that are older than grace, so a file whose
// job has not run yet is never removed. It returns how many it deleted.
func (f *Files) GC(keep map[string]bool, grace time.Duration) (int, error) {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return 0, err
	}
	var n int
	for _, e := range entries {
		sha, ok := strings.CutSuffix(e.Name(), ".json.gz")
		if !ok && !strings.HasPrefix(e.Name(), ".upload-") {
			continue
		}
		if keep[sha] {
			continue
		}
		info, err := e.Info()
		if err != nil || time.Since(info.ModTime()) < grace {
			continue
		}
		if err := os.Remove(filepath.Join(f.dir, e.Name())); err == nil {
			n++
		}
	}
	return n, nil
}
