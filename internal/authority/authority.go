// Package authority holds the signing CA: it loads the certificate and key
// from disk, hot-reloads them on change, retains previous CAs across a
// rotation, signs leaf certificates and exposes the resulting trust bundle.
package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
)

// The CA state the metrics collector reads at scrape time. Compile-time, so a
// renamed accessor is a build failure rather than a gauge that quietly stops
// being reported.
var _ metrics.CAState = (*CertificateAuthority)(nil)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// ErrCASignerUnusable marks signing failures caused by the state of the CA
// itself (expired signer, or a request whose lifetime cannot fit inside the
// remaining CA validity) rather than by the request. Such failures are
// transient from the request's perspective: a CA rotation can make an
// identical request succeed, so the reconciler requeues instead of recording
// a terminal outcome. Callers match it with errors.Is.
var ErrCASignerUnusable = errors.New("ca signer unusable")

// Option is a function which configures the [CertificateAuthority]. The CA is
// the one component with several independent, individually-optional settings
// (seed history, retention bound, logger), which is why it takes options where
// the rest of the codebase takes a flat struct.
type Option func(ca *CertificateAuthority) error

// CertificateAuthority is a CA which signs Pod Certificate Requests.
type CertificateAuthority struct {
	certFile    string
	privKeyFile string
	// certificate is the loaded CA certificate. New fails closed, so it is
	// non-nil once New has returned and load never clears it; the accessors
	// still guard it, because CertificateNotAfter runs on every metrics scrape
	// where a panic takes down the scrape rather than being recovered, and
	// one stance for all of them is easier to trust than a per-method one.
	certificate *x509.Certificate
	signer      crypto.Signer
	// previousCertificates is the retained history of CAs that were current
	// before the one loaded now. It is ordered by how recently each was
	// current, least recent first, and keyed by certificate identity: a
	// certificate appears at most once, and re-observing it moves it rather
	// than adding a second entry. Eviction therefore drops the CA least likely
	// to still have certificates in the field, instead of whichever entry
	// happened to be inserted first.
	previousCertificates []*x509.Certificate
	maxPreviousCerts     int
	backDate             time.Duration
	logger               logr.Logger
	// fingerprint is the SHA-256 of the loaded certificate's DER, used by load
	// to tell a reload that changed the material from one that did not. It is
	// content-based rather than file metadata, so a rotation that preserves
	// mtime is still seen. Guarded by mu, like the fields it describes.
	fingerprint [sha256.Size]byte
	mu          sync.Mutex

	// Watch/reload tuning. Set to sane defaults in New; overridable in tests.
	drainWindow    time.Duration // coalesce window for a burst of fs events
	reloadAttempts int           // bounded retries for a single reload
	reloadBackoff  time.Duration // base delay between reload attempts
	reloadInterval time.Duration // periodic reload, independent of events

	// health tracks the recent reload outcomes and whether the watcher has
	// exited unrecoverably. It is guarded by its own mutex (separate from mu)
	// so a readiness probe can poll HealthCheck without contending with a reload
	// in progress.
	healthMu         sync.Mutex
	lastReloadErr    error
	reloadFailures   int       // consecutive failed reload attempts
	firstFailureTime time.Time // when the current failure streak started
	lastSuccessTime  time.Time // when the CA was last read successfully
	watcherErr       error
}

// WithPreviousCABundle is an [Option], which seeds the [CertificateAuthority]
// with previously known CA certificates. This is useful for bootstrapping the
// trust bundle from an external source (e.g. an existing ClusterTrustBundle)
// so that previous CAs are retained across process restarts.
//
// The seed is not taken on trust: [New] normalizes it like any other history
// (see normalizePreviousCertificates), so entries that are not usable CA
// certificates, entries that have expired, duplicates and anything beyond
// WithMaxPreviousCertificates are dropped rather than adopted and republished.
// See docs/adr/0004-bootstrapped-previous-ca-history.md.
func WithPreviousCABundle(certs []*x509.Certificate) Option {
	opt := func(ca *CertificateAuthority) error {
		ca.previousCertificates = certs

		return nil
	}

	return opt
}

// WithLogger is an [Option], which gives the [CertificateAuthority] a logger for
// decisions it takes outside a request or a watch: today, the previous-CA
// history entries it declines to keep. Without it those drops are silent, which
// is exactly what makes a rewritten trust bundle hard to notice. Defaults to a
// discard logger.
func WithLogger(logger logr.Logger) Option {
	opt := func(ca *CertificateAuthority) error {
		ca.logger = logger

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
		maxPreviousCerts:     1,
		previousCertificates: make([]*x509.Certificate, 0),
		logger:               logr.Discard(),
		drainWindow:          500 * time.Millisecond,
		reloadAttempts:       5,
		reloadBackoff:        200 * time.Millisecond,
		reloadInterval:       caReloadInterval,
	}

	// Additional configuration of the CA with the given options.
	for _, opt := range opts {
		if err := opt(ca); err != nil {
			return nil, err
		}
	}

	if _, err := ca.load(); err != nil {
		return nil, err
	}
	// Seed the last-success clock from the load that just succeeded. Nothing
	// else records a success until the watch startup reconcile, which runs
	// after the manager starts and never at all if the watcher fails to
	// establish - so without this the "reloads have stopped" gauge would report
	// the epoch, and its alert would fire on every process start. Not counted
	// as a reload attempt: this is the bootstrap load, not the reload loop.
	ca.recordReloadResult(nil)

	return ca, nil
}

// load loads the certificate and key for the [CertificateAuthority]. It reports
// whether the material on disk differs from what was already loaded, so callers
// can gate downstream work - notifying consumers, republishing the trust bundle
// - on a real rotation rather than on every successful read. An unchanged read
// still counts as a successful reload: "the CA is readable" is the health
// signal, "the CA changed" is not.
func (ca *CertificateAuthority) load() (bool, error) {
	keyPair, err := tls.LoadX509KeyPair(ca.certFile, ca.privKeyFile)
	if err != nil {
		return false, fmt.Errorf("load key pair: %w", err)
	}

	caCert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return false, fmt.Errorf("parse certificate: %w", err)
	}

	if err := validateCACertificate(caCert, time.Now()); err != nil {
		return false, err
	}

	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return false, errors.New("private key does not implement crypto.Signer interface")
	}

	fingerprint := sha256.Sum256(keyPair.Certificate[0])

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Unchanged material: return before touching the certificate, the signer or
	// the history. The comparison belongs inside the critical section, since
	// ca.fingerprint is written below under the same lock.
	if ca.certificate != nil && ca.fingerprint == fingerprint {
		return false, nil
	}

	// Rotate: the outgoing certificate becomes the most recently active entry
	// in the history. The fingerprint check above already established that the
	// material differs, so there is no second case to test for. It is appended
	// unconditionally; normalization below collapses it onto any earlier
	// occurrence of the same certificate, so a CA that is rotated back in and
	// out again keeps one slot rather than accumulating one per flap.
	if ca.certificate != nil {
		ca.previousCertificates = append(ca.previousCertificates, ca.certificate)
	}

	ca.certificate = caCert
	ca.signer = signer
	ca.fingerprint = fingerprint

	// Runs on every load that changed the material, including the very first
	// one: that is what subjects a bootstrapped history to the same rules as
	// one this process built itself.
	ca.normalizePreviousCertificates()

	return true, nil
}

// clockSkewTolerance is how far ahead of the local clock a CA certificate's
// NotBefore may lie and still be accepted. A CA minted by an external PKI
// (a cert-manager sub-CA, AWS Private CA, Vault) carries validity from the
// issuer's clock, so a freshly rotated CA routinely opens a few seconds ahead
// of this node; refusing it would turn benign skew into a reload failure.
// Anything beyond this window is rejected, because verifiers check the
// validity of the whole chain: a not-yet-valid CA signs leaves nobody can
// verify while the signer itself reports healthy.
const clockSkewTolerance = 5 * time.Minute

// validateCACertificate reports whether cert can serve as a signing CA at the
// given time. The same checks decide whether the material on disk may become
// the current CA and whether a certificate offered as history is worth
// retaining, so they live in one place.
func validateCACertificate(cert *x509.Certificate, now time.Time) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return errors.New("certificate is not a valid CA certificate")
	}
	if (cert.KeyUsage & x509.KeyUsageCertSign) == 0 {
		return errors.New("CA certificate cannot sign certificates")
	}
	if now.Add(clockSkewTolerance).Before(cert.NotBefore) {
		return errors.New("CA certificate is not yet valid")
	}
	if now.After(cert.NotAfter) {
		return errors.New("CA certificate has expired")
	}

	return nil
}

// normalizePreviousCertificates enforces the invariants of the previous-CA
// history: every entry is a usable CA certificate, no entry is the current CA,
// no certificate appears twice, the order runs least-recently-active first, and
// there are never more than maxPreviousCerts of them. Callers must hold ca.mu.
//
// The order of the steps is the point. Dropping the current CA and the
// unusable entries *before* trimming means a rotation back into a certificate
// the history already holds, or an expired anchor nobody can verify against,
// cannot evict a previous CA whose certificates are still in the field. Trimming
// first - which is what the code did while the trim lived in the rotate branch -
// spends retention slots on certificates that are about to be discarded anyway.
//
// Certificates are compared by their DER bytes, the same identity the
// fingerprint expresses, so "the same CA" means the same certificate rather
// than the same position in a slice.
func (ca *CertificateAuthority) normalizePreviousCertificates() {
	now := time.Now()

	kept := make([]*x509.Certificate, 0, len(ca.previousCertificates))
	for i, cert := range ca.previousCertificates {
		switch {
		case cert == nil:
			continue
		case ca.certificate != nil && cert.Equal(ca.certificate):
			// The current CA is published from ca.certificate; holding it in
			// the history too would duplicate it in the trust bundle and spend
			// a retention slot on it.
			continue
		case slices.ContainsFunc(ca.previousCertificates[i+1:], cert.Equal):
			// A later occurrence is the more recent one; keep that instead.
			continue
		}
		if err := validateCACertificate(cert, now); err != nil {
			ca.logger.Info("dropping a previous CA certificate from the retained history",
				"reason", err.Error(), "subject", cert.Subject.String(), "notAfter", cert.NotAfter)

			continue
		}
		kept = append(kept, cert)
	}

	if len(kept) > ca.maxPreviousCerts {
		dropped := kept[:len(kept)-ca.maxPreviousCerts]
		for _, cert := range dropped {
			ca.logger.Info("dropping a previous CA certificate from the retained history",
				"reason", "history exceeds the configured maximum", "max", ca.maxPreviousCerts,
				"subject", cert.Subject.String(), "notAfter", cert.NotAfter)
		}
		kept = kept[len(dropped):]
	}

	ca.previousCertificates = kept
}

// Sign issues a certificate for pcConfig under the current CA and returns it
// together with the PEM chain (leaf, then CA).
//
// Failures caused by the CA itself - none loaded, an expired signer, or a
// pcConfig.Duration that does not fit inside the remaining CA validity - wrap
// [ErrCASignerUnusable] and are transient: a CA rotation can make an identical
// request succeed, so callers requeue rather than record a terminal outcome.
// Any other error is a fault of the request and is terminal.
func (ca *CertificateAuthority) Sign(pcConfig *podcertificate.PodCertificateConfig) (*podcertificate.PodCertificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// See the certificate field: guarded like every other accessor. Classified
	// as ErrCASignerUnusable: like an expired signer, a CA rotation can make an
	// identical request succeed, so callers requeue rather than record a
	// terminal outcome.
	if ca.certificate == nil {
		return nil, fmt.Errorf("no CA certificate loaded: %w", ErrCASignerUnusable)
	}

	now := time.Now()

	notBefore := now.Add(-ca.backDate)
	if !notBefore.Before(ca.certificate.NotAfter) {
		return nil, fmt.Errorf("the signer has expired: NotAfter=%v: %w", ca.certificate.NotAfter, ErrCASignerUnusable)
	}

	notAfter := notBefore.Add(pcConfig.Duration)
	if notAfter.After(ca.certificate.NotAfter) {
		return nil, fmt.Errorf("certificate validity period exceeds the signer CA validity: notAfter=%v, caNotAfter=%v: %w", notAfter, ca.certificate.NotAfter, ErrCASignerUnusable)
	}
	if notAfter.Before(now) {
		return nil, fmt.Errorf("certificate not after is in the past: %v", notAfter)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number for %s: %w", pcConfig.CommonName, err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: pcConfig.CommonName,
		},
		DNSNames:           pcConfig.DNSNames,
		IPAddresses:        pcConfig.IPAddresses,
		URIs:               pcConfig.URIs,
		PublicKeyAlgorithm: pcConfig.PublicKeyAlgorithm,
		PublicKey:          pcConfig.PublicKey,
		KeyUsage:           pcConfig.KeyUsage,
		ExtKeyUsage:        pcConfig.ExtKeyUsage,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		// BasicConstraintsValid is what makes Go emit the basicConstraints
		// extension at all; IsCA stays at its zero value, so the pair asserts
		// cA:FALSE on every leaf. DER omits a field at its DEFAULT, so the
		// encoded extension is an empty SEQUENCE - that is cA:FALSE, not a
		// missing value. No pathLenConstraint: it is meaningless with cA:FALSE.
		// crypto/x509 marks the extension critical, which is what we want: RFC
		// 5280 4.2.1.9 already requires it critical on CA certificates, so any
		// verifier that can validate a chain processes it. Why it is asserted
		// at all: ADR-0003.
		BasicConstraintsValid: true,
	}

	issuedCertificate, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, pcConfig.PublicKey, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("create certificate for public key type %T: %w", pcConfig.PublicKey, err)
	}

	return &podcertificate.PodCertificate{
		// Issued certificate first, then the CA that signed it.
		CertificateChain: string(certificatePEM(issuedCertificate)) + string(certificatePEM(ca.certificate.Raw)),
		Config:           pcConfig,
		NotBefore:        notBefore,
		NotAfter:         notAfter,
	}, nil
}

// certificatePEM encodes a DER certificate as a PEM CERTIFICATE block.
func certificatePEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TrustBundlePEM returns the current CA certificate followed by any previous
// CA certificates as a concatenated PEM bundle. This is suitable for use in a
// ClusterTrustBundle where clients need to trust both the current and recently
// rotated CAs.
func (ca *CertificateAuthority) TrustBundlePEM() []byte {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// See the certificate field: with no CA loaded there is nothing to
	// publish, so the bundle is empty rather than a panic.
	if ca.certificate == nil {
		return nil
	}

	bundle := certificatePEM(ca.certificate.Raw)
	for _, cert := range ca.previousCertificates {
		bundle = append(bundle, certificatePEM(cert.Raw)...)
	}

	return bundle
}
