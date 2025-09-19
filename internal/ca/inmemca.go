// pkg/ca/ca.go
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
}
type PodCertificate struct {
	Certificate         []byte
	CertificateChain    string
	Config              *PodCertificateConfig
	NotBefore, NotAfter time.Time
}
type PodCertificateConfig struct {
	CommonName    string
	DNSNames      []string
	Duration      time.Duration
	RefreshBefore time.Duration
}

func GenerateCA() (*CA, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create CA certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"PodCertificate CA"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour), // 1 hour
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	return &CA{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

func (ca *CA) IssueCertificateForPublicKey(publicKeyBytes []byte, pcg *PodCertificateConfig) (*PodCertificate, error) {

	//TODO: We already been parsing this - should simplify this
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)

	// Create certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(pcg.Duration)

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: pcg.CommonName,
		},
		DNSNames:    pcg.DNSNames,
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// CRITICAL: Use the parsed public key from the request, not a generated one
	certDER, err := x509.CreateCertificate(rand.Reader, &template, ca.Certificate, publicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate for public key type %T: %w", publicKey, err)
	}
	// Create PEM blocks
	issuedCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Certificate chain: issued cert + CA cert
	certificateChain := string(issuedCertPEM) + string(ca.CertPEM)

	return &PodCertificate{
		Certificate:      certDER,
		CertificateChain: certificateChain,
		Config:           pcg,
		NotBefore:        notBefore,
		NotAfter:         notAfter,
	}, nil
}
