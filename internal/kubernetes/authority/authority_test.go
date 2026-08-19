package authority

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"slices"
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

// basicConstraintsOID is id-ce-basicConstraints (RFC 5280 4.2.1.9).
var basicConstraintsOID = asn1.ObjectIdentifier{2, 5, 29, 19}

// Every issued leaf must assert basicConstraints with cA:FALSE and without a
// pathLenConstraint (ADR-0003). The assertions run against the certificate
// parsed back from DER rather than against the template, so they prove what
// was emitted rather than what was requested.
func TestSignAssertsBasicConstraintsCAFalse(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pc, err := ca.Sign(testConfig(t))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	leaf, err := x509.ParseCertificate(pc.Certificate())
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}

	if !leaf.BasicConstraintsValid {
		t.Error("issued leaf must carry the basicConstraints extension")
	}
	if leaf.IsCA {
		t.Error("issued leaf must assert cA:FALSE")
	}
	if leaf.MaxPathLen != -1 || leaf.MaxPathLenZero {
		t.Errorf("pathLenConstraint must be absent: MaxPathLen = %d, MaxPathLenZero = %t",
			leaf.MaxPathLen, leaf.MaxPathLenZero)
	}

	// x509.Certificate exposes no typed field for the criticality of
	// basicConstraints, so read it off the raw extension. The value is an empty
	// SEQUENCE because DER omits a field encoded at its DEFAULT and cA is
	// BOOLEAN DEFAULT FALSE - which pins cA:FALSE and the absent
	// pathLenConstraint in the bytes themselves, where no parser sentinel can
	// blur them.
	idx := slices.IndexFunc(leaf.Extensions, func(ext pkix.Extension) bool {
		return ext.Id.Equal(basicConstraintsOID)
	})
	if idx < 0 {
		t.Fatalf("no extension with OID %s in the issued leaf", basicConstraintsOID)
	}
	ext := leaf.Extensions[idx]
	if !ext.Critical {
		t.Error("basicConstraints must be emitted critical, as crypto/x509 does")
	}
	if want := []byte{0x30, 0x00}; !bytes.Equal(ext.Value, want) {
		t.Errorf("basicConstraints value = % x, want % x (empty SEQUENCE: cA:FALSE, no pathLenConstraint)",
			ext.Value, want)
	}
}

// IP SANs from the configuration must be embedded in the issued certificate.
func TestSignIncludesIPAddresses(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	config := testConfig(t)
	config.IPAddresses = []net.IP{net.ParseIP("10.9.8.7")}

	pc, err := ca.Sign(config)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	leaf := parseChain(t, []byte(pc.CertificateChain()))[0]
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(config.IPAddresses[0]) {
		t.Errorf("leaf IPAddresses = %v, want %v", leaf.IPAddresses, config.IPAddresses)
	}
}

// A restricted ExtKeyUsage from the configuration must be embedded verbatim.
func TestSignHonorsExtKeyUsage(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	config := testConfig(t)
	config.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	pc, err := ca.Sign(config)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	leaf := parseChain(t, []byte(pc.CertificateChain()))[0]
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("leaf ExtKeyUsage = %v, want [ClientAuth] only", leaf.ExtKeyUsage)
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

	_, err = ca.Sign(config)
	if err == nil {
		t.Fatal("want error when certificate would outlive the CA")
	}
	// The error must carry ErrCASignerUnusable so the reconciler classifies it
	// as transient (a CA rotation can let the same request succeed) rather than
	// recording a terminal Failed outcome.
	if !errors.Is(err, ErrCASignerUnusable) {
		t.Errorf("Sign() err = %v, want it to wrap ErrCASignerUnusable", err)
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
