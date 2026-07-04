package authority

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
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

func testConfig(t *testing.T) *podcertificate.PodCertificateConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	return &podcertificate.PodCertificateConfig{
		CommonName:         "mypod",
		DNSNames:           []string{"mypod.myns.svc.cluster.local"},
		Duration:           time.Hour,
		RefreshBefore:      15 * time.Minute,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		PublicKey:          &key.PublicKey,
		PublicKeyAlgorithm: x509.ECDSA,
	}
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

func TestSignIssuesCertificateChain(t *testing.T) {
	dir := t.TempDir()
	caPair := writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	config := testConfig(t)
	pc, err := ca.Sign(config)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	chain := parseChain(t, []byte(pc.CertificateChain()))
	if len(chain) != 2 {
		t.Fatalf("chain has %d certificates, want leaf + CA", len(chain))
	}
	leaf, chainCA := chain[0], chain[1]

	if !chainCA.Equal(caPair.Cert) {
		t.Error("second chain entry must be the CA certificate")
	}
	if err := leaf.CheckSignatureFrom(caPair.Cert); err != nil {
		t.Errorf("leaf is not signed by the CA: %v", err)
	}
	if leaf.Subject.CommonName != config.CommonName {
		t.Errorf("common name = %q, want %q", leaf.Subject.CommonName, config.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != config.DNSNames[0] {
		t.Errorf("DNS names = %v, want %v", leaf.DNSNames, config.DNSNames)
	}
	if leaf.IsCA {
		t.Error("issued certificate must not be a CA")
	}

	// x509 encodes validity with one-second resolution, so compare truncated.
	if !pc.NotBefore().Truncate(time.Second).Equal(leaf.NotBefore) ||
		!pc.NotAfter().Truncate(time.Second).Equal(leaf.NotAfter) {
		t.Error("PodCertificate validity must match the leaf certificate")
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got != config.Duration {
		t.Errorf("lifetime = %v, want %v", got, config.Duration)
	}
	if !pc.IsValid() {
		t.Error("freshly issued certificate must be valid")
	}
}

func TestSignRejectsDurationBeyondCA(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "short-ca.example.org", time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	config := testConfig(t)
	config.Duration = 48 * time.Hour

	if _, err := ca.Sign(config); err == nil {
		t.Fatal("want error when certificate would outlive the CA")
	}
}

// TrustBundlePEM must publish the current CA first, followed by previous CAs
// within the configured rolling window, without duplicates.
func TestTrustBundleRotation(t *testing.T) {
	dir := t.TempDir()
	ca1 := writeCA(t, dir, "ca-1.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key", WithMaxPreviousCertificates(2))
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
	if err := ca.load(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	assertBundle(ca1)

	ca2 := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
	if err := ca.load(); err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	assertBundle(ca2, ca1)

	ca3 := writeCA(t, dir, "ca-3.example.org", 24*time.Hour)
	if err := ca.load(); err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}
	assertBundle(ca3, ca1, ca2)

	// A fourth CA must evict the oldest previous certificate (window of 2).
	ca4 := writeCA(t, dir, "ca-4.example.org", 24*time.Hour)
	if err := ca.load(); err != nil {
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
		WithPreviousCABundle([]*x509.Certificate{previous.Cert}),
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
		WithPreviousCABundle([]*x509.Certificate{current.Cert}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bundle := parseChain(t, ca.TrustBundlePEM())
	if len(bundle) != 1 {
		t.Fatalf("bundle has %d certificates, want 1 (no duplicate of the current CA)", len(bundle))
	}
}

func TestWithMaxPreviousCertificatesRejectsNegative(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", time.Hour)

	if _, err := New(dir+"/tls.crt", dir+"/tls.key", WithMaxPreviousCertificates(-1)); err == nil {
		t.Fatal("want error for negative max previous certificates")
	}
}

// Watch must reload the CA when the files change and notify the caller.
func TestWatchReloadsCA(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca-1.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notify := make(chan struct{}, 1)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- ca.Watch(ctx, notify)
	}()

	// Give the watcher a moment to register the directory watch before
	// rotating the files.
	time.Sleep(300 * time.Millisecond)
	rotated := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)

	select {
	case <-notify:
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the CA reload notification")
	}

	bundle := parseChain(t, ca.TrustBundlePEM())
	if !bundle[0].Equal(rotated.Cert) {
		t.Fatal("current CA must be the rotated certificate after reload")
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
	}
}
