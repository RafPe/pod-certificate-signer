package testutil

import (
	"crypto/tls"
	"testing"
	"time"
)

// NewCA yields a certificate the authority package will accept as a signing
// CA, with the validity window it was asked for, and WriteFiles lays it out
// as a mounted kubernetes.io/tls secret would.
func TestNewCAIsUsableSigningCA(t *testing.T) {
	kp, err := NewCA("test-ca", 2*time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if !kp.Cert.IsCA || !kp.Cert.BasicConstraintsValid {
		t.Error("NewCA must produce a CA certificate")
	}
	if kp.Cert.Subject.CommonName != "test-ca" {
		t.Errorf("CommonName = %q, want test-ca", kp.Cert.Subject.CommonName)
	}
	if lifetime := kp.Cert.NotAfter.Sub(kp.Cert.NotBefore); lifetime < 2*time.Hour {
		t.Errorf("lifetime = %v, want at least the requested 2h", lifetime)
	}

	certPath, keyPath, err := kp.WriteFiles(t.TempDir())
	if err != nil {
		t.Fatalf("WriteFiles: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("the written files must load as a key pair: %v", err)
	}
}

// NewNonCA is the negative fixture: everything about it is a certificate
// except the CA capability the authority rejects.
func TestNewNonCAIsNotACA(t *testing.T) {
	kp, err := NewNonCA("leaf", time.Hour)
	if err != nil {
		t.Fatalf("NewNonCA: %v", err)
	}
	if kp.Cert.IsCA {
		t.Error("NewNonCA must not produce a CA certificate")
	}
}

// NewCAWithValidity honours the explicit window, which is how the not-yet-valid
// and expired-CA fixtures are built.
func TestNewCAWithValidityHonoursWindow(t *testing.T) {
	notBefore := time.Now().Add(time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(24 * time.Hour)
	kp, err := NewCAWithValidity("future", notBefore, notAfter)
	if err != nil {
		t.Fatalf("NewCAWithValidity: %v", err)
	}
	if !kp.Cert.NotBefore.Equal(notBefore) || !kp.Cert.NotAfter.Equal(notAfter) {
		t.Errorf("validity = [%v, %v], want [%v, %v]", kp.Cert.NotBefore, kp.Cert.NotAfter, notBefore, notAfter)
	}
}
