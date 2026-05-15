package authority

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// Option is a function which configures the [CertificateAuthority].
type Option func(ca *CertificateAuthority) error

// CertificateAuthority is a CA which signs Pod Certificate Requests.
type CertificateAuthority struct {
	certFile             string
	privKeyFile          string
	certificate          *x509.Certificate
	signer               crypto.Signer
	previousCertificates []*x509.Certificate
	maxPreviousCerts     int
	nowFunc              func() time.Time
	backDate             time.Duration
	mu                   sync.Mutex
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

// WithPreviousCABundle is an [Option], which seeds the [CertificateAuthority]
// with previously known CA certificates. This is useful for bootstrapping the
// trust bundle from an external source (e.g. an existing ClusterTrustBundle)
// so that previous CAs are retained across process restarts.
func WithPreviousCABundle(certs []*x509.Certificate) Option {
	opt := func(ca *CertificateAuthority) error {
		ca.previousCertificates = certs

		return nil
	}

	return opt
}

// WithMaxPreviousCertificates is an [Option], which configures how many
// previous CA certificates to retain in the rolling window. Defaults to 1.
func WithMaxPreviousCertificates(n int) Option {
	opt := func(ca *CertificateAuthority) error {
		if n < 0 {
			return errors.New("max previous certificates must be non-negative")
		}
		ca.maxPreviousCerts = n

		return nil
	}

	return opt
}

// New creates a new [CertificateAuthority].
func New(caFile, caKeyFile string, opts ...Option) (*CertificateAuthority, error) {
	if caFile == "" {
		return nil, errors.New("invalid CA certificate path specified")
	}
	if caKeyFile == "" {
		return nil, errors.New("invalid CA private key path specified")
	}

	ca := &CertificateAuthority{
		certFile:             caFile,
		privKeyFile:          caKeyFile,
		backDate:             1 * time.Minute,
		nowFunc:              time.Now,
		maxPreviousCerts:     1,
		previousCertificates: make([]*x509.Certificate, 0),
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

	// Rotate: push current certificate into the history if it changed
	if ca.certificate != nil && !ca.certificate.Equal(caX509Cert) {
		if !slices.ContainsFunc(ca.previousCertificates, func(item *x509.Certificate) bool {
			return item.Equal(ca.certificate)
		}) {
			ca.previousCertificates = append(ca.previousCertificates, ca.certificate)
		}
		if len(ca.previousCertificates) > ca.maxPreviousCerts {
			ca.previousCertificates = ca.previousCertificates[len(ca.previousCertificates)-ca.maxPreviousCerts:]
		}
	}

	// Set new cert and signer
	ca.certificate = caX509Cert
	ca.signer = signer

	// Remove the current cert from the previous CA certs, in order to avoid
	// duplicate entries in the trust bundle.
	ca.previousCertificates = slices.DeleteFunc(ca.previousCertificates, func(item *x509.Certificate) bool {
		return item.Equal(ca.certificate)
	})

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

	caCertPEM := ca.certificateToPEM()
	issuedCertificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: issuedCertificate,
	})

	// Certificate chain: issued cert + CA cert
	certificateChain := string(issuedCertificatePEM) + string(caCertPEM)

	return podcertificate.NewPodCertificate(
		issuedCertificate,
		certificateChain,
		pcConfig,
		nbf,
		naf,
	), nil
}

// certificateToPEM returns the CA certificate in PEM format. This method is not
// safe to be called concurrently. Callers should ensure to acquire the lock
// before calling this method.
func (ca *CertificateAuthority) certificateToPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.certificate.Raw,
	})
}

// CertificateToPEM returns the CA certificate in PEM format.
func (ca *CertificateAuthority) CertificateToPEM() []byte {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	return ca.certificateToPEM()
}

// TrustBundlePEM returns the current CA certificate followed by any previous
// CA certificates as a concatenated PEM bundle. This is suitable for use in a
// ClusterTrustBundle where clients need to trust both the current and recently
// rotated CAs.
func (ca *CertificateAuthority) TrustBundlePEM() []byte {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	var bundle []byte
	bundle = append(bundle, ca.certificateToPEM()...)
	for _, prevBundle := range ca.previousCertificates {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: prevBundle.Raw,
		})...)
	}

	return bundle
}

// Watch starts a [fsnotify.Watcher], which reloads the CA cert and private key
// when the underlying files change.
//
// Callers will be notified whenever the CA changes via the provided channel.
// If notifications are not needed, callers must provide nil as the notification
// channel.
//
// This method blocks until the given [context.Context] is canceled.
func (ca *CertificateAuthority) Watch(ctx context.Context, notify chan<- struct{}) error {
	logger := log.FromContext(ctx).WithName("ca-watcher")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("ca-watcher: unable to create fsnotify.Watcher: %w", err)
	}
	defer watcher.Close() // nolint:errcheck

	paths := []string{
		filepath.Dir(ca.certFile),
		filepath.Dir(ca.privKeyFile),
	}

	slices.Sort(paths)
	for _, path := range slices.Compact(paths) {
		logger.Info("watching CA directory for changes", "path", path)
		if err := watcher.Add(path); err != nil {
			return fmt.Errorf("ca-watcher: unable to add watch directory %s: %w", path, err)
		}
	}

L:
	for {
		select {
		case <-ctx.Done():
			break L
		case event := <-watcher.Events:
			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) && !event.Has(fsnotify.Rename) {
				continue
			}

			// Drain the filesystem events channel in order to avoid
			// needless reloads in a short time window, as multiple
			// events will be triggered when the CA cert and key are
			// updated.
			draining := true
			drainTimer := time.NewTimer(500 * time.Millisecond)
			for draining {
				select {
				case <-ctx.Done():
					drainTimer.Stop()
					break L
				case e := <-watcher.Events:
					logger.V(1).Info("draining fsnotify event", "event", e.Op.String(), "name", e.Name)
					continue
				case <-drainTimer.C:
					draining = false
				}
			}

			logger.Info("reloading CA certificate")
			if err := ca.load(); err != nil {
				logger.Error(err, "failed to reload CA certificate")
				continue
			}

			// Don't block here, so that reloading the CA can
			// proceed as usual, even if we have slow consumers.
			logger.Info("CA certificate reloaded successfully")
			if notify != nil {
				select {
				case notify <- struct{}{}:
				default:
				}
			}
		case err := <-watcher.Errors:
			logger.Error(err, "error watching CA certificate")
		}
	}

	return nil
}
