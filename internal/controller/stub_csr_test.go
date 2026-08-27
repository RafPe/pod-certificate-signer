package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

// newStubCSR returns a DER-encoded PKCS#10 request of the shape kubelet
// attaches to a PodCertificateRequest, along with the key that signed it.
//
// Since certificates.k8s.io/v1 dropped spec.pkixPublicKey, this stub is the
// only way a request carries its subject public key, so every test that needs
// a signable request builds one here.
func newStubCSR(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create stub PKCS#10 request: %v", err)
	}

	return csr, key
}
