package authority

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
)

func testConfig(t *testing.T) *podcertificate.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	return &podcertificate.Config{
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

	chain := parseChain(t, []byte(pc.CertificateChain))
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
	if !pc.NotBefore.Truncate(time.Second).Equal(leaf.NotBefore) ||
		!pc.NotAfter.Truncate(time.Second).Equal(leaf.NotAfter) {
		t.Error("PodCertificate validity must match the leaf certificate")
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got != config.Duration {
		t.Errorf("lifetime = %v, want %v", got, config.Duration)
	}
	now := time.Now()
	if !now.After(pc.NotBefore) || !now.Before(pc.NotAfter) {
		t.Errorf("freshly issued certificate validity [%v, %v] must include now", pc.NotBefore, pc.NotAfter)
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

	leaf := parseChain(t, []byte(pc.CertificateChain))[0]

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
	leaf := parseChain(t, []byte(pc.CertificateChain))[0]
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
	leaf := parseChain(t, []byte(pc.CertificateChain))[0]
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
