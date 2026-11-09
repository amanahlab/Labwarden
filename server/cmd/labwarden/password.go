package main

import (
	"crypto/rand"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/amanahlab/labwarden/server/internal/api"
)

// adminPasswordFile holds the generated admin password, in the data directory.
const adminPasswordFile = "admin-password"

// resolveAdminPassword picks the admin password. LABWARDEN_ADMIN_PASSWORD
// wins, and a generated file left from before is deleted, so no stale
// plaintext stays in the volume or its backups. Without it the password is
// read from <dataDir>/admin-password, or generated there on first start (mode
// 0600, written to a temp file and renamed, so a crash leaves no short file).
// fromFile tells the caller to point the admin at that file. With
// authentication off the file is never read or created; envPw comes back as
// it is, so api.CheckAuthConfig still refuses both being set.
func resolveAdminPassword(dataDir, envPw string, authOff bool) (pw string, fromFile bool, err error) {
	p := filepath.Join(dataDir, adminPasswordFile)
	if authOff {
		return envPw, false, nil
	}
	if envPw != "" {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", false, err
		}
		return envPw, false, nil
	}
	b, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", false, err // e.g. unreadable: fail rather than overwrite it
	}
	if got := strings.TrimSpace(string(b)); err == nil && api.CheckAuthConfig(got, false) == nil {
		return got, true, nil
	}
	pw = rand.Text()
	for api.CheckAuthConfig(pw, false) != nil {
		pw = rand.Text()
	}
	tmp := p + ".tmp"
	if err := writeSynced(tmp, []byte(pw+"\n")); err != nil {
		_ = os.Remove(tmp)
		return "", false, err
	}
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return "", false, err
	}
	return pw, true, nil
}

// writeSynced writes b to a new mode-0600 file at path and flushes it to disk.
func writeSynced(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
