package signer

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // an unsupported key type is the point
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
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

// Every supported key type must be classified, and anything else rejected.
// Since certificates.k8s.io/v1 dropped spec.pkixPublicKey, the CSR is the only
// path to this classification, so it is the only thing standing between an
// unsignable key and the signing code.
func TestClassifyPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	edKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	for _, tc := range []struct {
		name string
		key  crypto.PublicKey
		want x509.PublicKeyAlgorithm
	}{
		{"rsa", &rsaKey.PublicKey, x509.RSA},
		{"ecdsa", &ecKey.PublicKey, x509.ECDSA},
		{"ed25519", edKey, x509.Ed25519},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, algorithm, err := classifyPublicKey(tc.key)
			if err != nil {
				t.Fatalf("classifyPublicKey: %v", err)
			}
			if algorithm != tc.want {
				t.Errorf("algorithm = %v, want %v", algorithm, tc.want)
			}
			if got == nil {
				t.Error("public key must be returned")
			}
		})
	}

	t.Run("unsupported", func(t *testing.T) {
		// A DSA key parses out of DER but can never be signed against.
		_, _, err := classifyPublicKey(&dsa.PublicKey{})
		if err == nil {
			t.Fatal("expected an unsupported key type to be rejected")
		}
	})
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
