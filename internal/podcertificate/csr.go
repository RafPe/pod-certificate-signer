package podcertificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// ParseCSR extracts and classifies the public key of a DER-encoded PKCS#10
// certificate request, along with any SANs requested in it. The CSR signature
// is already verified by the kube-apiserver during admission.
func ParseCSR(csrDER []byte) (*CSR, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#10 CSR: %w", err)
	}

	publicKey, publicKeyAlgorithm, err := classifyPublicKey(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	return &CSR{
		PublicKey:          publicKey,
		PublicKeyAlgorithm: publicKeyAlgorithm,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
	}, nil
}

func classifyPublicKey(publicKey crypto.PublicKey) (crypto.PublicKey, x509.PublicKeyAlgorithm, error) {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return publicKey, x509.RSA, nil
	case *ecdsa.PublicKey:
		return publicKey, x509.ECDSA, nil
	case ed25519.PublicKey:
		return publicKey, x509.Ed25519, nil
	default:
		return nil, 0, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}
