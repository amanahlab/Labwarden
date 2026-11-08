package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEnrollOncePerHost(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	_, tok, err := s.CreateToken(ctx, "lab", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.Enroll(ctx, tok, "vm-1", "10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if host, err := s.VerifyCredential(ctx, cred, "10.0.0.5"); err != nil || host != "vm-1" {
		t.Fatalf("credential = %q, %v; want vm-1", host, err)
	}
	if _, err := s.VerifyCredential(ctx, tok, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("enrollment token used as a credential: %v, want ErrUnauthorized", err)
	}
	if _, err := s.Enroll(ctx, tok, "vm-1", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("second enrollment: %v, want ErrConflict", err)
	}

	// Once the credential is reset, the host can enroll again; the old one is dead.
	if err := s.RevokeCredential(ctx, "vm-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyCredential(ctx, cred, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked credential: %v, want ErrUnauthorized", err)
	}
	if _, err := s.Enroll(ctx, tok, "vm-1", ""); err != nil {
		t.Fatalf("enroll after reset: %v", err)
	}
	if err := s.RevokeCredential(ctx, "no-such-host"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke without a credential: %v, want ErrNotFound", err)
	}
	creds, err := s.ListCredentials(ctx)
	if err != nil || len(creds) != 1 || creds[0].Host != "vm-1" || creds[0].EnrolledBy != "lab" {
		t.Fatalf("credentials = %+v, %v", creds, err)
	}
}

func TestEnrollmentTokenLimits(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)

	_, once, _ := s.CreateToken(ctx, "once", 0, 1)
	if _, err := s.Enroll(ctx, once, "a", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(ctx, once, "b", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("used-up token: %v, want ErrUnauthorized", err)
	}

	expired, expiredPlain, _ := s.CreateToken(ctx, "expired", time.Hour, 0)
	if _, err := s.w.ExecContext(ctx, `UPDATE tokens SET expires_at=? WHERE id=?`, stamp(time.Now().Add(-time.Minute)), expired.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(ctx, expiredPlain, "c", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired token: %v, want ErrUnauthorized", err)
	}

	revoked, revokedPlain, _ := s.CreateToken(ctx, "revoked", 0, 0)
	if err := s.RevokeToken(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(ctx, revokedPlain, "d", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked token: %v, want ErrUnauthorized", err)
	}
	if _, err := s.Enroll(ctx, "vxe_unknown", "e", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown token: %v, want ErrUnauthorized", err)
	}
}

// Revoking the bootstrap token must survive the restart that imports it again.
func TestRevokedBootstrapTokenStaysRevoked(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	const boot = "vxe_bootstrap_token_0123456789"
	if err := s.ImportToken(ctx, "bootstrap", boot); err != nil {
		t.Fatal(err)
	}
	toks, _ := s.ListTokens(ctx)
	if err := s.RevokeToken(ctx, toks[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ImportToken(ctx, "bootstrap", boot); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(ctx, boot, "vm-1", ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked bootstrap token after re-import: %v, want ErrUnauthorized", err)
	}
}

func TestCentralHostCannotEnroll(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	if _, err := s.Heartbeat(ctx, IngestMeta{Host: "registry", Kind: "central"}); err != nil {
		t.Fatal(err)
	}
	_, tok, _ := s.CreateToken(ctx, "lab", 0, 0)
	if _, err := s.Enroll(ctx, tok, "registry", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("enroll central host: %v, want ErrConflict", err)
	}
}

func TestDeleteHostEndsCredential(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	_, tok, _ := s.CreateToken(ctx, "lab", 0, 0)
	cred, err := s.Enroll(ctx, tok, "vm-1", "")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.Heartbeat(ctx, IngestMeta{Host: "vm-1", Kind: "vm"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteHost(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyCredential(ctx, cred, ""); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("credential of a deleted host: %v, want ErrUnauthorized", err)
	}
}
