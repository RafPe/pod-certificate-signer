package signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"
)

// buildCSR creates a DER-encoded PKCS#10 CSR carrying the given SANs.
func buildCSR(t *testing.T, dnsNames []string, ipAddresses []net.IP) []byte {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{},
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der
}

// ParseCSR must classify the public key and pass through requested SANs.
func TestParseCSRExtractsSANs(t *testing.T) {
	dns := []string{"svc.example.org", "alt.example.org"}
	ips := []net.IP{net.ParseIP("10.0.0.7")}

	info, err := ParseCSR(buildCSR(t, dns, ips))
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}

	if info.PublicKeyAlgorithm != x509.Ed25519 {
		t.Errorf("PublicKeyAlgorithm = %v, want Ed25519", info.PublicKeyAlgorithm)
	}
	if info.PublicKey == nil {
		t.Error("PublicKey must be set")
	}
	if len(info.DNSNames) != 2 || info.DNSNames[0] != dns[0] || info.DNSNames[1] != dns[1] {
		t.Errorf("DNSNames = %v, want %v", info.DNSNames, dns)
	}
	if len(info.IPAddresses) != 1 || !info.IPAddresses[0].Equal(ips[0]) {
		t.Errorf("IPAddresses = %v, want %v", info.IPAddresses, ips)
	}
}

// A kubelet-generated CSR is completely empty today: no SANs come back.
func TestParseCSREmptyCSR(t *testing.T) {
	info, err := ParseCSR(buildCSR(t, nil, nil))
	if err != nil {
		t.Fatalf("ParseCSR: %v", err)
	}
	if len(info.DNSNames) != 0 || len(info.IPAddresses) != 0 {
		t.Errorf("empty CSR must yield no SANs, got DNS=%v IP=%v", info.DNSNames, info.IPAddresses)
	}
}
