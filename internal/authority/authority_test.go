package authority

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// writeCA generates a self-signed CA and writes it into dir as tls.crt/tls.key.
func writeCA(t *testing.T, dir, commonName string, lifetime time.Duration) *testutil.KeyPair {
	t.Helper()
	kp, err := testutil.NewCA(commonName, lifetime)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	if _, _, err := kp.WriteFiles(dir); err != nil {
		t.Fatalf("write CA files: %v", err)
	}
	return kp
}

// parseChain decodes all CERTIFICATE PEM blocks from a bundle.
func parseChain(t *testing.T, data []byte) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("unexpected PEM block type %q", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse certificate: %v", err)
		}
		certs = append(certs, cert)
	}
	return certs
}

func TestNewValidatesInput(t *testing.T) {
	if _, err := New("", "key.pem"); err == nil {
		t.Error("want error for empty certificate path")
	}
	if _, err := New("cert.pem", ""); err == nil {
		t.Error("want error for empty key path")
	}
	if _, err := New("/does/not/exist.crt", "/does/not/exist.key"); err == nil {
		t.Error("want error for nonexistent files")
	}
}

func TestNewRejectsNonCACertificate(t *testing.T) {
	dir := t.TempDir()
	kp, err := testutil.NewNonCA("not-a-ca.example.org", time.Hour)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	certPath, keyPath, err := kp.WriteFiles(dir)
	if err != nil {
		t.Fatalf("write files: %v", err)
	}

	if _, err := New(certPath, keyPath); err == nil {
		t.Fatal("want error for a non-CA certificate")
	}
}

func TestNewRejectsExpiredCertificate(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "expired-ca.example.org", -30*time.Minute)

	_, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("err = %v, want expired CA error", err)
	}
}

func TestNewRejectsNotYetValidCertificate(t *testing.T) {
	dir := t.TempDir()
	kp, err := testutil.NewCAWithValidity("future-ca.example.org",
		time.Now().Add(time.Hour), time.Now().Add(25*time.Hour))
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	certPath, keyPath, err := kp.WriteFiles(dir)
	if err != nil {
		t.Fatalf("write CA files: %v", err)
	}

	_, err = New(certPath, keyPath)
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("err = %v, want not-yet-valid CA error", err)
	}
}

func TestValidateCACertificate(t *testing.T) {
	// The tolerance is asserted as a literal rather than by referencing the
	// production constant, so a change to the contract fails a test instead of
	// silently rewriting what this test proves.
	const tolerance = 5 * time.Minute
	now := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		mutate  func(cert *x509.Certificate)
		wantErr string
	}{
		{
			name:   "usable CA",
			mutate: func(cert *x509.Certificate) {},
		},
		{
			name:    "basic constraints not asserted",
			mutate:  func(cert *x509.Certificate) { cert.BasicConstraintsValid = false },
			wantErr: "not a valid CA certificate",
		},
		{
			name:    "not a CA",
			mutate:  func(cert *x509.Certificate) { cert.IsCA = false },
			wantErr: "not a valid CA certificate",
		},
		{
			name:    "cannot sign certificates",
			mutate:  func(cert *x509.Certificate) { cert.KeyUsage = x509.KeyUsageDigitalSignature },
			wantErr: "cannot sign certificates",
		},
		{
			name:    "expired",
			mutate:  func(cert *x509.Certificate) { cert.NotAfter = now.Add(-time.Minute) },
			wantErr: "has expired",
		},
		{
			name:    "not yet valid beyond the skew tolerance",
			mutate:  func(cert *x509.Certificate) { cert.NotBefore = now.Add(tolerance + time.Second) },
			wantErr: "not yet valid",
		},
		{
			name:   "not yet valid within the skew tolerance",
			mutate: func(cert *x509.Certificate) { cert.NotBefore = now.Add(tolerance - time.Second) },
		},
		{
			name:   "NotBefore exactly at the tolerance boundary",
			mutate: func(cert *x509.Certificate) { cert.NotBefore = now.Add(tolerance) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// validateCACertificate reads fields only, so a struct literal is
			// enough - no key material is needed.
			cert := &x509.Certificate{
				BasicConstraintsValid: true,
				IsCA:                  true,
				KeyUsage:              x509.KeyUsageCertSign,
				NotBefore:             now.Add(-time.Hour),
				NotAfter:              now.Add(time.Hour),
			}
			tt.mutate(cert)

			err := validateCACertificate(cert, now)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateCACertificate(%s) = %v, want nil", tt.name, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateCACertificate(%s) = %v, want error containing %q", tt.name, err, tt.wantErr)
			}
		})
	}
}

// TrustBundlePEM must publish the current CA first, followed by previous CAs
// within the configured rolling window, without duplicates.
func TestTrustBundleRotation(t *testing.T) {
	dir := t.TempDir()
	ca1 := writeCA(t, dir, "ca-1.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key", WithMaxPreviousCAs(2))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertBundle := func(want ...*testutil.KeyPair) {
		t.Helper()
		got := parseChain(t, ca.TrustBundlePEM())
		if len(got) != len(want) {
			t.Fatalf("bundle has %d certificates, want %d", len(got), len(want))
		}
		for i := range want {
			if !got[i].Equal(want[i].Cert) {
				t.Fatalf("bundle[%d] is not the expected certificate %q", i, want[i].Cert.Subject.CommonName)
			}
		}
	}

	assertBundle(ca1)

	// Reloading the same CA must not create history entries.
	if _, err := ca.load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	assertBundle(ca1)

	ca2 := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
	if _, err := ca.load(); err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	assertBundle(ca2, ca1)

	ca3 := writeCA(t, dir, "ca-3.example.org", 24*time.Hour)
	if _, err := ca.load(); err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	assertBundle(ca3, ca1, ca2)

	// A fourth CA must evict the oldest previous certificate (window of 2).
	ca4 := writeCA(t, dir, "ca-4.example.org", 24*time.Hour)
	if _, err := ca.load(); err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	assertBundle(ca4, ca2, ca3)
}

// WithPreviousCABundle must seed the trust bundle with externally known CAs,
// e.g. read back from an existing ClusterTrustBundle on startup.
func TestWithPreviousCABundleSeedsBundle(t *testing.T) {
	previous, err := testutil.NewCA("old-ca.example.org", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate previous CA: %v", err)
	}

	dir := t.TempDir()
	current := writeCA(t, dir, "current-ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key",
		WithPreviousCAs([]*x509.Certificate{previous.Cert}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bundle := parseChain(t, ca.TrustBundlePEM())
	if len(bundle) != 2 {
		t.Fatalf("bundle has %d certificates, want 2", len(bundle))
	}
	if !bundle[0].Equal(current.Cert) || !bundle[1].Equal(previous.Cert) {
		t.Fatal("bundle must contain the current CA first, then the seeded previous CA")
	}
}

// Seeding the previous bundle with the current CA must not produce duplicates.
func TestWithPreviousCABundleDeduplicatesCurrent(t *testing.T) {
	dir := t.TempDir()
	current := writeCA(t, dir, "current-ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key",
		WithPreviousCAs([]*x509.Certificate{current.Cert}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bundle := parseChain(t, ca.TrustBundlePEM())
	if len(bundle) != 1 {
		t.Fatalf("bundle has %d certificates, want 1 (no duplicate of the current CA)", len(bundle))
	}
}

func TestWithMaxPreviousCAsRejectsNegative(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", time.Hour)

	if _, err := New(dir+"/tls.crt", dir+"/tls.key", WithMaxPreviousCAs(-1)); err == nil {
		t.Fatal("want error for negative max previous certificates")
	}
}
