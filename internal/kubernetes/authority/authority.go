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

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// Option is a function which configures the [CertificateAuthority].
type Option func(c *CertificateAuthority) error

// CertificateAuthority is a CA which signs Pod Certificate Requests.
type CertificateAuthority struct {
	certificate *x509.Certificate
	privateKey  crypto.Signer
	now         func() time.Time
	backDate    time.Duration
}

// New creates a new [CertificateAuthority].
func New(caFile, caKeyFile string) (*CertificateAuthority, error) {
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
		certificate: caX509Cert,
		privateKey:  caCert.PrivateKey.(crypto.Signer),
		backDate:    1 * time.Minute, // TODO: Make CA Backdate configurable
	}, nil
}

// Main method responsible for signing our certificate request configureation
func (ca *CertificateAuthority) Sign(pcConfig *podcertificate.PodCertificateConfig) (*podcertificate.PodCertificate, error) {

	now := time.Now()
	if ca.now != nil {
		now = ca.now()
	}

	nbf := now.Add(-ca.backDate)
	if !nbf.Before(ca.certificate.NotAfter) {
		return nil, fmt.Errorf("the signer has expired: NotAfter=%v", ca.certificate.NotAfter)
	}

	naf := nbf.Add(pcConfig.Duration)
	if naf.After(ca.certificate.NotAfter) {
		return nil, fmt.Errorf("certificate validity period exceeds the signer CA validity: notAfter=%v, caNotAfter=%v", naf, ca.certificate.NotAfter)
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

	issuedCertificate, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, pcConfig.PublicKey, ca.privateKey)
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
	return ca.certificate.Raw
}
