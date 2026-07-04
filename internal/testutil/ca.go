// Package testutil provides helpers for generating certificate authorities
// and key material in tests. It is imported by unit tests and by the e2e
// suite, and must not be used in production code.
package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// KeyPair is a self-signed certificate and its private key, in both parsed
// and PEM-encoded form.
type KeyPair struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
}

// NewCA returns a self-signed CA certificate. The certificate is valid from
// one hour in the past until now+lifetime, so a negative lifetime produces an
// already-expired certificate for negative tests.
func NewCA(commonName string, lifetime time.Duration) (*KeyPair, error) {
	return newSelfSigned(commonName, lifetime, true)
}

// NewNonCA returns a self-signed certificate without CA capabilities, for
// negative tests around CA validation.
func NewNonCA(commonName string, lifetime time.Duration) (*KeyPair, error) {
	return newSelfSigned(commonName, lifetime, false)
}

func newSelfSigned(commonName string, lifetime time.Duration, isCA bool) (*KeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	keyUsage := x509.KeyUsageDigitalSignature
	if isCA {
		keyUsage |= x509.KeyUsageCertSign
	}
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(lifetime),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		KeyUsage:              keyUsage,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}

	return &KeyPair{
		Cert:    cert,
		Key:     key,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// WriteFiles writes the PEM-encoded certificate and key into dir as tls.crt
// and tls.key (the layout of a mounted kubernetes.io/tls secret) and returns
// their paths.
func (kp *KeyPair) WriteFiles(dir string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, "tls.crt")
	keyPath = filepath.Join(dir, "tls.key")

	if err := os.WriteFile(certPath, kp.CertPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(keyPath, kp.KeyPEM, 0o600); err != nil {
		return "", "", fmt.Errorf("write key: %w", err)
	}

	return certPath, keyPath, nil
}
