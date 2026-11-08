package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a fresh self-signed certificate for cn and its key.
func writePair(t *testing.T, certFile, keyFile, cn string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func servedCN(t *testing.T, r *certReloader) string {
	t.Helper()
	c, err := r.getCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestCertReloaderPicksUpRenewedPair(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePair(t, certFile, keyFile, "old")
	r, err := newCertReloader(certFile, keyFile, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if cfg := tlsConfig(r); cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x", cfg.MinVersion)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.watch(ctx, 10*time.Millisecond)

	// A broken pair is ignored; the old certificate keeps being served.
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if cn := servedCN(t, r); cn != "old" {
		t.Fatalf("after a broken write, serving %q", cn)
	}

	writePair(t, certFile, keyFile, "new")
	deadline := time.Now().Add(2 * time.Second)
	for servedCN(t, r) != "new" {
		if time.Now().After(deadline) {
			t.Fatal("renewed certificate not picked up")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCertReloaderRejectsMissingFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := newCertReloader(filepath.Join(dir, "c"), filepath.Join(dir, "k"), slog.Default()); err == nil {
		t.Fatal("missing files accepted")
	}
}
