package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// Option is a function which configures the [CertificateAuthority].
type Option func(ca *CertificateAuthority) error

// CertificateAuthority is a CA which signs Pod Certificate Requests.
type CertificateAuthority struct {
	certFile    string
	privKeyFile string
	certificate *x509.Certificate
	signer      crypto.Signer
	nowFunc     func() time.Time
	backDate    time.Duration
	mu          sync.Mutex
}

// WithBackDate is an [Option], which configures the [CertificateAuthority] to
// use the given backdate when signing certificate requests.
func WithBackDate(val time.Duration) Option {
	opt := func(ca *CertificateAuthority) error {
		ca.backDate = val

		return nil
	}

	return opt
}

// New creates a new [CertificateAuthority].
func New(caFile, caKeyFile string, opts ...Option) (*CertificateAuthority, error) {
	ca := &CertificateAuthority{
		certFile:    caFile,
		privKeyFile: caKeyFile,
		backDate:    1 * time.Minute,
		nowFunc:     time.Now,
	}

	// Additional configuration of the CA with the given options.
	for _, opt := range opts {
		if err := opt(ca); err != nil {
			return nil, err
		}
	}

	if err := ca.load(); err != nil {
		return nil, err
	}

	return ca, nil
}

// load loads the certificate and key for the [CertificateAuthority].
func (ca *CertificateAuthority) load() error {
	caCert, err := tls.LoadX509KeyPair(ca.certFile, ca.privKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load key pair: %w", err)
	}

	caX509Cert, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Validate: CA
	if !caX509Cert.BasicConstraintsValid || !caX509Cert.IsCA {
		return errors.New("certificate is not a valid CA certificate")
	}

	// Validate: key usage
	if (caX509Cert.KeyUsage & x509.KeyUsageCertSign) == 0 {
		return errors.New("CA certificate cannot sign certificates")
	}

	// Validate: not expired
	if time.Now().After(caX509Cert.NotAfter) {
		return errors.New("CA certificate has expired")
	}

	signer, ok := caCert.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("private key does not implement crypto.Signer interface")
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.certificate = caX509Cert
	ca.signer = signer

	return nil
}

// Sign is responsible for signing our certificate request configuration.
func (ca *CertificateAuthority) Sign(pcConfig *podcertificate.PodCertificateConfig) (*podcertificate.PodCertificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	now := time.Now()
	if ca.nowFunc != nil {
		now = ca.nowFunc()
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

	issuedCertificate, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, pcConfig.PublicKey, ca.signer)
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
	ca.mu.Lock()
	defer ca.mu.Unlock()

	return ca.certificate.Raw
}
