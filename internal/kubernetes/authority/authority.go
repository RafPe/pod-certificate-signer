package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	// "k8s.io/client-go/util/cert"
	// "k8s.io/client-go/util/keyutil"

	podcertificate "github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

// Well-known key sizes for Kubernetes 1.34 PodCertificateRequest compliance
const (
	// RSA key sizes (in bits)
	RSAKeySize3072 = 3072
	RSAKeySize4096 = 4096

	// ECDSA curve sizes (in bits)
	ECDSAKeySizeP256 = 256 // P-256 curve
	ECDSAKeySizeP384 = 384 // P-384 curve
)

// Well-known key type identifiers
const (
	KeyTypeRSA   = "RSA"
	KeyTypeECDSA = "ECDSA"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	Now         func() time.Time
	Backdate    time.Duration
}

func NewCertificateAuthority(caFile, caKeyFile string) (*CertificateAuthority, error) {
	caCert, err := tls.LoadX509KeyPair(caFile, caKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair: %w", err)
	}

	caX509Cert, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Validate: CA
	if !caX509Cert.BasicConstraintsValid || !caX509Cert.IsCA {
		return nil, fmt.Errorf("certificate is not a valid CA certificate")
	}

	// Validate: key usage
	if (caX509Cert.KeyUsage & x509.KeyUsageCertSign) == 0 {
		return nil, fmt.Errorf("CA certificate cannot sign certificates")
	}

	// Validate: not expired
	if time.Now().After(caX509Cert.NotAfter) {
		return nil, fmt.Errorf("CA certificate has expired")
	}

	return &CertificateAuthority{
		Certificate: caX509Cert,
		PrivateKey:  caCert.PrivateKey.(crypto.Signer),
		Backdate:    1 * time.Minute, //TODO: Make CA Backdate configurable
	}, nil
}

// Main method responsible for signing our certificate request configureation
func (ca *CertificateAuthority) Sign(pcConfig *podcertificate.PodCertificateConfig) (*podcertificate.PodCertificate, error) {

	now := time.Now()
	if ca.Now != nil {
		now = ca.Now()
	}

	nbf := now.Add(-ca.Backdate)
	if !nbf.Before(ca.Certificate.NotAfter) {
		return nil, fmt.Errorf("the signer has expired: NotAfter=%v", ca.Certificate.NotAfter)
	}

	naf := nbf.Add(pcConfig.Duration)
	if naf.After(ca.Certificate.NotAfter) {
		return nil, fmt.Errorf("certificate validity period exceeds the signer CA validity: notAfter=%v, caNotAfter=%v", naf, ca.Certificate.NotAfter)
	}
	if naf.Before(now) {
		return nil, fmt.Errorf("certificate not after is in the past: %v", naf)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("unable to generate a serial number for %s: %v", pcConfig.CommonName, err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: pcConfig.CommonName,
		},
		DNSNames:           pcConfig.DNSNames,
		URIs:               pcConfig.URIs,
		PublicKeyAlgorithm: pcConfig.PublicKeyAlgorithm,
		PublicKey:          pcConfig.PublicKey,
		KeyUsage:           pcConfig.KeyUsage,
		ExtKeyUsage:        pcConfig.ExtKeyUsage,
		NotBefore:          nbf,
		NotAfter:           naf,
	}

	issuedCertificate, err := x509.CreateCertificate(rand.Reader, template, ca.Certificate, pcConfig.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate for public key type %T: %w", pcConfig.PublicKey, err)
	}

	issuedCertificatePem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuedCertificate,
	})

	// Certificate chain: issued cert + CA cert
	certificateChain := string(issuedCertificatePem) + string(ca.CertificateToPEM())

	return podcertificate.NewPodCertificate(
		issuedCertificate,
		certificateChain,
		pcConfig,
		nbf,
		naf,
	), nil

}

func (ca *CertificateAuthority) CertificateToPEM() []byte {
	return ca.Certificate.Raw
}
