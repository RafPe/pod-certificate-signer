package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"

	authority "github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	podcertificate "github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

type Signer struct {
	certificateAuthority *authority.CertificateAuthority
	signerName           string
}

func NewSigner(caFile, caKeyFile, signerName string) (*Signer, error) {
	caAuthority, err := authority.New(caFile, caKeyFile)
	if err != nil {
		return nil, err
	}

	ret := &Signer{
		certificateAuthority: caAuthority,
		signerName:           signerName,
	}

	return ret, nil
}

// Our main signing method. At this stage the configuration should have already been verified before ending up here.
func (s *Signer) SignPodCertificate(pcrConfig *podcertificate.PodCertificateConfig) (*podcertificate.PodCertificate, error) {
	pCertificate, err := s.certificateAuthority.Sign(pcrConfig)
	if err != nil {
		return nil, err
	}

	return pCertificate, nil
}

// Helper check to see if our signer matches the one for the request received.
func (s *Signer) IsSignerNameMatching(signerName string) bool {
	return s.signerName == signerName
}

func (s *Signer) GetSignerName() string {
	return s.signerName
}

func (s *Signer) ValidatePodCertificateConfig(config *podcertificate.PodCertificateConfig) error {

	// TODO: Validations should come here - like duration , before refresh etc
	if config.CommonName == "" {
		return fmt.Errorf("common name is required")
	}

	if config.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}

	return nil
}

func (s *Signer) ParsePkixPublicKey(pkixPublicKey []byte) (crypto.PublicKey, x509.PublicKeyAlgorithm, error) {
	publicKey, err := x509.ParsePKIXPublicKey(pkixPublicKey)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to parse public key: %v", err)
	}

	return classifyPublicKey(publicKey)
}

func (s *Signer) ParseCSRPublicKey(csrDER []byte) (crypto.PublicKey, x509.PublicKeyAlgorithm, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to parse PKCS#10 CSR: %v", err)
	}

	return classifyPublicKey(csr.PublicKey)
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
