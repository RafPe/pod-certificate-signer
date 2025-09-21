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

// // ------------------------------------------------ LEGACY CODE ------------------------------------------------

// func (ca *CA) IssueCertificateForPublicKey(publicKeyBytes []byte, pcg *PodCertificateConfig) (*PodCertificate, error) {

// 	//TODO: We already been parsing this - should simplify this
// 	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)

// 	// Create certificate template
// 	notBefore := time.Now()
// 	notAfter := notBefore.Add(pcg.Duration)

// 	template := x509.Certificate{
// 		SerialNumber: big.NewInt(time.Now().Unix()),
// 		Subject: pkix.Name{
// 			CommonName: pcg.CommonName,
// 		},
// 		DNSNames:    pcg.DNSNames,
// 		NotBefore:   notBefore,
// 		NotAfter:    notAfter,
// 		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
// 		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
// 	}

// 	// CRITICAL: Use the parsed public key from the request, not a generated one
// 	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, publicKey, ca.PrivateKey)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create certificate for public key type %T: %w", publicKey, err)
// 	}
// 	// Create PEM blocks
// 	issuedCertPEM := pem.EncodeToMemory(&pem.Block{
// 		Type:  "CERTIFICATE",
// 		Bytes: certDER,
// 	})

// 	// Certificate chain: issued cert + CA cert
// 	certificateChain := string(issuedCertPEM) + string(ca.CertPEM)

// 	return &PodCertificate{
// 		Certificate:      certDER,
// 		CertificateChain: certificateChain,
// 		Config:           pcg,
// 		NotBefore:        notBefore,
// 		NotAfter:         notAfter,
// 	}, nil
// }
