package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

// Signer signs pod certificate requests for a single signer name using a
// [authority.CertificateAuthority].
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

// SignPodCertificate signs a certificate for the given configuration. The
// configuration should have already been validated before ending up here.
func (s *Signer) SignPodCertificate(pcrConfig *podcertificate.PodCertificateConfig) (*podcertificate.PodCertificate, error) {
	return s.certificateAuthority.Sign(pcrConfig)
}

// IsSignerNameMatching reports whether the given signer name matches the one
// this [Signer] is responsible for.
func (s *Signer) IsSignerNameMatching(signerName string) bool {
	return s.signerName == signerName
}

// Name returns the signer name.
func (s *Signer) Name() string {
	return s.signerName
}

// ParsePKIXPublicKey parses a DER-encoded PKIX public key and classifies it.
func ParsePKIXPublicKey(pkixPublicKey []byte) (crypto.PublicKey, x509.PublicKeyAlgorithm, error) {
	publicKey, err := x509.ParsePKIXPublicKey(pkixPublicKey)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to parse public key: %w", err)
	}

	return classifyPublicKey(publicKey)
}

// CSRInfo holds the values extracted from a kubelet-generated PKCS#10
// certificate request: the subject public key, and any requested subject
// alternative names.
//
// Today kubelet generates completely empty CSRs, so the SAN slices are
// always empty - the KEP plans for pod authors to request DNS and IP SANs
// which kubelet will embed in the CSR, and extracting them now keeps the
// signer ready for that.
type CSRInfo struct {
	PublicKey          crypto.PublicKey
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	DNSNames           []string
	IPAddresses        []net.IP
}

// ParseCSR extracts and classifies the public key of a DER-encoded PKCS#10
// certificate request, along with any SANs requested in it. The CSR signature
// is already verified by the kube-apiserver during admission.
func ParseCSR(csrDER []byte) (*CSRInfo, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("unable to parse PKCS#10 CSR: %w", err)
	}

	publicKey, publicKeyAlgorithm, err := classifyPublicKey(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	return &CSRInfo{
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

// ClusterTrustBundleName returns the name of the ClusterTrustBundle resource
// for the given signer name, following the <domain>:<signerName>:<arbitrary-name>
// convention.
//
// https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles
func ClusterTrustBundleName(signerName string) string {
	return strings.ReplaceAll(signerName, "/", ":") + ":bundle"
}

// ClusterTrustBundle returns a [certificatesv1beta1.ClusterTrustBundle] derived
// from the [Signer] and the [authority.CertificateAuthority] used by it for
// signing certificates.
func (s *Signer) ClusterTrustBundle() *certificatesv1beta1.ClusterTrustBundle {
	bundle := &certificatesv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name: ClusterTrustBundleName(s.signerName),
		},
		Spec: certificatesv1beta1.ClusterTrustBundleSpec{
			TrustBundle: string(s.certificateAuthority.TrustBundlePEM()),
			SignerName:  s.signerName,
		},
	}

	return bundle
}
