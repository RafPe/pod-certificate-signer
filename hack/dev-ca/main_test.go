package main

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"
)

// run writes a loadable CA key pair, valid for the requested number of days,
// into a directory it creates if needed - which is all `make dev-ca` relies on.
func TestRunWritesLoadableCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "ca")

	if err := run(dir, "dev-ca-test", 7); err != nil {
		t.Fatalf("run: %v", err)
	}

	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatalf("the written files must load as a key pair: %v", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Error("the development CA must assert cA:TRUE")
	}
	if cert.Subject.CommonName != "dev-ca-test" {
		t.Errorf("CommonName = %q, want dev-ca-test", cert.Subject.CommonName)
	}
	if remaining := time.Until(cert.NotAfter); remaining < 6*24*time.Hour || remaining > 7*24*time.Hour {
		t.Errorf("NotAfter is %v away, want about 7 days", remaining)
	}
	if !cert.NotBefore.Before(time.Now()) {
		t.Error("NotBefore must be in the past so the CA is usable immediately")
	}
}
