package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/amanahlab/labwarden/server/internal/api"
)

const envPassword = "set-in-the-environment"

func readPasswordFile(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, adminPasswordFile))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func assertNoPasswordFile(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(dir, adminPasswordFile)); !os.IsNotExist(err) {
		t.Fatalf("admin-password file exists (stat err %v), want none", err)
	}
}

func TestAdminPasswordGeneratedOnceAndKept(t *testing.T) {
	dir := t.TempDir()
	pw, fromFile, err := resolveAdminPassword(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !fromFile {
		t.Fatal("fromFile = false for a generated password")
	}
	if err := api.CheckAuthConfig(pw, false); err != nil {
		t.Fatalf("generated password fails the auth check: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, adminPasswordFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
	}
	if got := readPasswordFile(t, dir); got != pw+"\n" {
		t.Fatal("file does not hold the returned password")
	}
	if _, err := os.Stat(filepath.Join(dir, adminPasswordFile+".tmp")); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}

	again, fromFile, err := resolveAdminPassword(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if again != pw || !fromFile {
		t.Fatal("second start did not return the stored password")
	}
}

func TestAdminPasswordFile(t *testing.T) {
	const kept = "a-password-I-typed-myself"
	for _, tc := range []struct {
		name    string
		content string
		want    string // "" means: a new password is generated
	}{
		{"trailing newline", kept + "\n", kept},
		{"edit whitespace", "  " + kept + " \r\n\n", kept},
		{"too short", "short\n", ""},
		{"placeholder", "change-me-please\n", ""},
		{"empty", "", ""},
		{"only whitespace", " \n\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, adminPasswordFile)
			if err := os.WriteFile(p, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			pw, fromFile, err := resolveAdminPassword(dir, "", false)
			if err != nil {
				t.Fatal(err)
			}
			if !fromFile {
				t.Fatal("fromFile = false")
			}
			if tc.want != "" {
				if pw != tc.want {
					t.Fatal("stored password not returned as written")
				}
				if readPasswordFile(t, dir) != tc.content {
					t.Fatal("a valid file was rewritten")
				}
				return
			}
			if err := api.CheckAuthConfig(pw, false); err != nil {
				t.Fatalf("regenerated password fails the auth check: %v", err)
			}
			if readPasswordFile(t, dir) != pw+"\n" {
				t.Fatal("bad file was not replaced by the new password")
			}
		})
	}
}

func TestAdminPasswordFromEnvironment(t *testing.T) {
	for _, existing := range []bool{false, true} {
		dir := t.TempDir()
		if existing {
			if _, _, err := resolveAdminPassword(dir, "", false); err != nil {
				t.Fatal(err)
			}
		}
		pw, fromFile, err := resolveAdminPassword(dir, envPassword, false)
		if err != nil {
			t.Fatal(err)
		}
		if pw != envPassword || fromFile {
			t.Fatalf("existing file %v: got the wrong password or fromFile=%v", existing, fromFile)
		}
		assertNoPasswordFile(t, dir)
	}
}

func TestAdminPasswordAuthDisabled(t *testing.T) {
	dir := t.TempDir()
	pw, fromFile, err := resolveAdminPassword(dir, "", true)
	if err != nil || pw != "" || fromFile {
		t.Fatalf("got pw %q, fromFile %v, err %v; want nothing", pw, fromFile, err)
	}
	assertNoPasswordFile(t, dir)

	// A file left from before is neither read nor removed.
	if err := os.WriteFile(filepath.Join(dir, adminPasswordFile), []byte("a-stored-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pw, fromFile, err = resolveAdminPassword(dir, "", true)
	if err != nil || pw != "" || fromFile {
		t.Fatalf("got pw %q, fromFile %v, err %v; want the file ignored", pw, fromFile, err)
	}
	if err := api.CheckAuthConfig(pw, true); err != nil {
		t.Fatalf("auth off with a stored file: %v", err)
	}
	if readPasswordFile(t, dir) != "a-stored-password\n" {
		t.Fatal("file changed with auth off")
	}

	// Both set is still refused.
	pw, _, err = resolveAdminPassword(dir, envPassword, true)
	if err != nil {
		t.Fatal(err)
	}
	if api.CheckAuthConfig(pw, true) == nil {
		t.Fatal("LABWARDEN_AUTH_DISABLED with a password was accepted")
	}
}

func TestAdminPasswordUnreadableFileFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, adminPasswordFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAdminPassword(dir, "", false); err == nil {
		t.Fatal("a directory at the password path was accepted")
	}
	if fi, err := os.Stat(filepath.Join(dir, adminPasswordFile)); err != nil || !fi.IsDir() {
		t.Fatal("the directory was replaced")
	}
}
