package signer

import (

	//capiv1alpha1 "k8s.io/api/certificates/v1alpha1"

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
	caAuthority, err := authority.NewCertificateAuthority(caFile, caKeyFile)
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

	//TODO: Validations should come here - like duration , before refresh etc
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

	// Determine the algorithm based on the key type
	var publicKeyAlgorithm x509.PublicKeyAlgorithm
	switch publicKey.(type) {
	case *rsa.PublicKey:
		publicKeyAlgorithm = x509.RSA
	case *ecdsa.PublicKey:
		publicKeyAlgorithm = x509.ECDSA
	case ed25519.PublicKey:
		publicKeyAlgorithm = x509.Ed25519
	default:
		return nil, 0, fmt.Errorf("unsupported public key type: %T", publicKey)
	}

	return publicKey, publicKeyAlgorithm, nil
}
