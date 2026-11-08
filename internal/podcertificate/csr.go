package podcertificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
)

// CSR holds the values extracted from a kubelet-generated PKCS#10 certificate
// request: the subject public key, and any requested subject alternative
// names.
//
// Today kubelet generates completely empty CSRs, so the SAN slices are always
// empty - the KEP plans for pod authors to request DNS and IP SANs which
// kubelet will embed in the CSR, and carrying them now keeps the signer ready
// for that.
type CSR struct {
	PublicKey          crypto.PublicKey
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	DNSNames           []string
	IPAddresses        []net.IP
}

// ParseCSR extracts and classifies the public key of a DER-encoded PKCS#10
// certificate request, along with any SANs requested in it. The CSR signature
// is already verified by the kube-apiserver during admission.
func ParseCSR(csrDER []byte) (*CSR, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#10 CSR: %w", err)
	}

	algorithm, err := publicKeyAlgorithm(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	return &CSR{
		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: algorithm,
		DNSNames:           csr.DNSNames,
		IPAddresses:        csr.IPAddresses,
	}, nil
}

// publicKeyAlgorithm names the algorithm of a key the signer can issue for, or
// fails for any other key type.
func publicKeyAlgorithm(publicKey crypto.PublicKey) (x509.PublicKeyAlgorithm, error) {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		return x509.RSA, nil
	case *ecdsa.PublicKey:
		return x509.ECDSA, nil
	case ed25519.PublicKey:
		return x509.Ed25519, nil
	default:
		return 0, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}
