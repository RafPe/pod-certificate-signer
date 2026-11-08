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

// Option is a function which configures the [CertificateAuthority]. The CA
// takes options where the rest of the codebase takes a flat struct because one
// of its settings has no usable zero value: a retention bound of 0 ("keep no
// previous CAs") is meaningful, so a zero-valued struct field could not also
// mean "use the default of 1". Each option states its own default.
type Option func(ca *CertificateAuthority) error

// CertificateAuthority is a CA which signs Pod Certificate Requests.
type CertificateAuthority struct {
	caCertFile string
	caKeyFile  string
	// certificate is the loaded CA certificate. New fails closed, so it is
	// non-nil once New has returned and load never clears it. Every accessor
	// still guards it, because CertificateNotAfter runs on every metrics scrape
	// where a panic takes down the scrape rather than being recovered, and one
	// stance for all of them is easier to trust than a per-method one.
	certificate *x509.Certificate
	signer      crypto.Signer
	// previousCAs is the retained history of CAs that were current before the
	// one loaded now. It is ordered by how recently each was current, least
	// recent first, and keyed by certificate identity: a certificate appears at
	// most once, and re-observing it moves it rather than adding a second
	// entry. Eviction therefore drops the CA least likely to still have
	// certificates in the field, instead of whichever entry happened to be
	// inserted first.
	previousCAs    []*x509.Certificate
	maxPreviousCAs int
	backDate       time.Duration
	logger         logr.Logger
	// fingerprint is the SHA-256 of the loaded certificate's DER, used by load
	// to tell a reload that changed the material from one that did not. It is
	// content-based rather than file metadata, so a rotation that preserves
	// mtime is still seen. Guarded by mu, like the fields it describes.
	fingerprint [sha256.Size]byte
	mu          sync.Mutex

	// Watch/reload tuning. Set to sane defaults in New; overridable in tests.
	drainWindow    time.Duration // coalesce window for a burst of fs events
	reloadAttempts int           // bounded retries for an event-driven reload
	reloadBackoff  time.Duration // base delay between reload attempts
	reloadInterval time.Duration // periodic reload, independent of events

	// health tracks the recent reload outcomes and whether the watcher has
	// exited unrecoverably, under its own lock (see reloadHealth).
	health reloadHealth
}

// WithPreviousCAs is an [Option], which seeds the [CertificateAuthority] with
// previously known CA certificates. This is useful for bootstrapping the trust
// bundle from an external source (e.g. an existing ClusterTrustBundle) so that
// previous CAs are retained across process restarts.
//
// The seed is not taken on trust: [New] normalizes it like any other history
// (see normalizePreviousCAs), so entries that are not usable CA certificates,
// entries that have expired, duplicates and anything beyond WithMaxPreviousCAs
// are dropped rather than adopted and republished.
// See docs/adr/0004-bootstrapped-previous-ca-history.md.
func WithPreviousCAs(certs []*x509.Certificate) Option {
	return func(ca *CertificateAuthority) error {
		ca.previousCAs = certs
		return nil
	}
}

// WithLogger is an [Option], which gives the [CertificateAuthority] a logger for
// decisions it takes outside a request or a watch: today, the previous-CA
// history entries it declines to keep. Without it those drops are silent, which
// is exactly what makes a rewritten trust bundle hard to notice. Defaults to a
// discard logger.
func WithLogger(logger logr.Logger) Option {
	return func(ca *CertificateAuthority) error {
		ca.logger = logger
		return nil
	}
}

// WithMaxPreviousCAs is an [Option], which configures how many previous CA
// certificates to retain in the rolling window. Defaults to 1; 0 keeps none.
func WithMaxPreviousCAs(n int) Option {
	return func(ca *CertificateAuthority) error {
		if n < 0 {
			return errors.New("max previous CAs must be non-negative")
		}
		ca.maxPreviousCAs = n
		return nil
	}
}

// New creates a [CertificateAuthority] from the CA certificate and key files
// and loads them; it fails if the material is not a usable signing CA.
func New(caCertFile, caKeyFile string, opts ...Option) (*CertificateAuthority, error) {
	if caCertFile == "" {
		return nil, errors.New("invalid CA certificate path specified")
	}
	if caKeyFile == "" {
		return nil, errors.New("invalid CA private key path specified")
	}

	ca := &CertificateAuthority{
		caCertFile:     caCertFile,
		caKeyFile:      caKeyFile,
		backDate:       1 * time.Minute,
		maxPreviousCAs: 1,
		previousCAs:    make([]*x509.Certificate, 0),
		logger:         logr.Discard(),
		drainWindow:    500 * time.Millisecond,
		reloadAttempts: 5,
		reloadBackoff:  200 * time.Millisecond,
		reloadInterval: caReloadInterval,
	}

	for _, opt := range opts {
		if err := opt(ca); err != nil {
			return nil, err
		}
	}

	if _, err := ca.load(); err != nil {
		return nil, err
	}
	// Seed the last-success clock from the load that just succeeded. Nothing
	// else records a success until the watch startup reload, which runs after
	// the manager starts and never at all if the watcher fails to establish -
	// so without this the "reloads have stopped" gauge would report the epoch,
	// and its alert would fire on every process start. Not counted as a reload
	// attempt: this is the bootstrap load, not the reload loop.
	ca.health.record(nil)

	return ca, nil
}

// load loads the certificate and key for the [CertificateAuthority]. It reports
// whether the material on disk differs from what was already loaded, so callers
// can gate downstream work - notifying consumers, republishing the trust bundle
// - on a real rotation rather than on every successful read. An unchanged read
// still counts as a successful reload: "the CA is readable" is the health
// signal, "the CA changed" is not.
func (ca *CertificateAuthority) load() (bool, error) {
	// Every failure names the files, so an operator can tell which mount is
	// wrong from the log line alone.
	wrap := func(err error) error {
		return fmt.Errorf("load CA from %s and %s: %w", ca.caCertFile, ca.caKeyFile, err)
	}

	keyPair, err := tls.LoadX509KeyPair(ca.caCertFile, ca.caKeyFile)
	if err != nil {
		return false, wrap(fmt.Errorf("load key pair: %w", err))
	}

	caCert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return false, wrap(fmt.Errorf("parse certificate: %w", err))
	}

	if err := validateCACertificate(caCert, time.Now()); err != nil {
		return false, wrap(err)
	}

	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return false, wrap(errors.New("private key does not implement crypto.Signer interface"))
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
		ca.previousCAs = append(ca.previousCAs, ca.certificate)
	}

	ca.certificate = caCert
	ca.signer = signer
	ca.fingerprint = fingerprint

	// Runs on every load that changed the material, including the very first
	// one: that is what subjects a bootstrapped history to the same rules as
	// one this process built itself.
	ca.normalizePreviousCAs()

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

// normalizePreviousCAs enforces the invariants of the previous-CA history:
// every entry is a usable CA certificate, no entry is the current CA, no
// certificate appears twice, the order runs least-recently-active first, and
// there are never more than maxPreviousCAs of them. Callers must hold ca.mu.
//
// The order of the steps is the point. Dropping the current CA and the
// unusable entries *before* trimming means a rotation back into a certificate
// the history already holds, or an expired anchor nobody can verify against,
// cannot evict a previous CA whose certificates are still in the field. Trimming
// first would spend retention slots on certificates that are about to be
// discarded anyway.
//
// Certificates are compared by their DER bytes, the same identity the
// fingerprint expresses, so "the same CA" means the same certificate rather
// than the same position in a slice.
func (ca *CertificateAuthority) normalizePreviousCAs() {
	now := time.Now()

	kept := make([]*x509.Certificate, 0, len(ca.previousCAs))
	for i, cert := range ca.previousCAs {
		switch {
		case cert == nil:
			continue
		case ca.certificate != nil && cert.Equal(ca.certificate):
			// The current CA is published from ca.certificate; holding it in
			// the history too would duplicate it in the trust bundle and spend
			// a retention slot on it.
			continue
		case slices.ContainsFunc(ca.previousCAs[i+1:], cert.Equal):
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

	if len(kept) > ca.maxPreviousCAs {
		dropped := kept[:len(kept)-ca.maxPreviousCAs]
		for _, cert := range dropped {
			ca.logger.Info("dropping a previous CA certificate from the retained history",
				"reason", "history exceeds the configured maximum", "max", ca.maxPreviousCAs,
				"subject", cert.Subject.String(), "notAfter", cert.NotAfter)
		}
		kept = kept[len(dropped):]
	}

	ca.previousCAs = kept
}

// Sign issues a certificate for cfg under the current CA and returns it
// together with the PEM chain (leaf, then CA).
//
// Failures caused by the CA itself - none loaded, an expired signer, or a
// cfg.Duration that does not fit inside the remaining CA validity - wrap
// [ErrCASignerUnusable]; see its doc. Any other error is terminal.
func (ca *CertificateAuthority) Sign(cfg *podcertificate.Config) (*podcertificate.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ca.certificate == nil {
		return nil, fmt.Errorf("no CA certificate loaded: %w", ErrCASignerUnusable)
	}

	now := time.Now()

	notBefore := now.Add(-ca.backDate)
	if !notBefore.Before(ca.certificate.NotAfter) {
		return nil, fmt.Errorf("the signer has expired: NotAfter=%v: %w", ca.certificate.NotAfter, ErrCASignerUnusable)
	}

	notAfter := notBefore.Add(cfg.Duration)
	if notAfter.After(ca.certificate.NotAfter) {
		return nil, fmt.Errorf("certificate validity period exceeds the signer CA validity: notAfter=%v, caNotAfter=%v: %w", notAfter, ca.certificate.NotAfter, ErrCASignerUnusable)
	}
	if notAfter.Before(now) {
		return nil, fmt.Errorf("certificate not after is in the past: %v", notAfter)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number for %s: %w", cfg.CommonName, err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cfg.CommonName,
		},
		DNSNames:           cfg.DNSNames,
		IPAddresses:        cfg.IPAddresses,
		URIs:               cfg.URIs,
		PublicKeyAlgorithm: cfg.PublicKeyAlgorithm,
		PublicKey:          cfg.PublicKey,
		KeyUsage:           cfg.KeyUsage,
		ExtKeyUsage:        cfg.ExtKeyUsage,
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

	issuedCertificate, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, cfg.PublicKey, ca.signer)
	if err != nil {
		return nil, fmt.Errorf("create certificate for public key type %T: %w", cfg.PublicKey, err)
	}

	return &podcertificate.Certificate{
		// Issued certificate first, then the CA that signed it.
		CertificateChain: string(certificatePEM(issuedCertificate)) + string(certificatePEM(ca.certificate.Raw)),
		Config:           cfg,
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

	if ca.certificate == nil {
		return nil
	}

	bundle := certificatePEM(ca.certificate.Raw)
	for _, cert := range ca.previousCAs {
		bundle = append(bundle, certificatePEM(cert.Raw)...)
	}

	return bundle
}

// CertificateNotAfter reports when the loaded CA certificate expires. It is
// safe for concurrent use: it takes mu, copies a scalar and releases, so a
// caller reading it on a metrics scrape does not hold the lock across signing.
// With no certificate loaded it reports the zero time, which the collector
// renders as a 0 gauge (see metrics.timestamp) - correctly firing the
// staleness alert.
func (ca *CertificateAuthority) CertificateNotAfter() time.Time {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ca.certificate == nil {
		return time.Time{}
	}

	return ca.certificate.NotAfter
}

// TrustBundleSize reports how many certificates the in-memory trust bundle
// holds: the current CA plus the retained previous ones. It is what the signer
// would publish, not a read of the published ClusterTrustBundle; with no CA
// loaded that is nothing, matching TrustBundlePEM. Safe for concurrent use.
func (ca *CertificateAuthority) TrustBundleSize() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	if ca.certificate == nil {
		return 0
	}

	return 1 + len(ca.previousCAs)
}
