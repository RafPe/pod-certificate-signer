package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	authority "github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	podcertificate "github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

type Signer struct {
	certificateAuthority *authority.CertificateAuthority
	signerName           string
}

// New creates a new [Signer] with the given name, and uses CA for signing pod
// certificate requests.
func New(signerName string, ca *authority.CertificateAuthority) (*Signer, error) {
	if signerName == "" {
		return nil, errors.New("invalid signer name specified")
	}

	if ca == nil {
		return nil, errors.New("invalid CA specified")
	}

	ret := &Signer{
		certificateAuthority: ca,
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

// ClusterTrustBundle returns a [certificatesv1beta1.ClusterTrustBundle] derived
// from the [Signer] and the [authority.CertificateAuthority] used by it for
// signing certificates.
func (s *Signer) ClusterTrustBundle() *certificatesv1beta1.ClusterTrustBundle {
	// Name of the resource should follow the
	// <domain>:<signerName>:<arbitrary-name> convention.
	//
	// https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles
	normalizedName := strings.ReplaceAll(s.signerName, "/", ":")
	bundleName := fmt.Sprintf("%s:bundle", normalizedName)

	data := s.certificateAuthority.CertificateToPEM()
	bundle := &certificatesv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: bundleName,
		},
		Spec: certificatesv1beta1.ClusterTrustBundleSpec{
			TrustBundle: string(data),
			SignerName:  s.signerName,
		},
	}

	return bundle
}
