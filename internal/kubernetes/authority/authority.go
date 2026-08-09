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
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// ErrCASignerUnusable marks signing failures caused by the state of the CA
// itself (expired signer, or a request whose lifetime cannot fit inside the
// remaining CA validity) rather than by the request. Such failures are
// transient from the request's perspective: a CA rotation can make an
// identical request succeed, so the reconciler requeues instead of recording
// a terminal outcome. Callers match it with errors.Is.
var ErrCASignerUnusable = errors.New("ca signer unusable")

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

	// Watch/reload tuning. Set to sane defaults in New; overridable in tests.
	drainWindow    time.Duration // coalesce window for a burst of fs events
	reloadAttempts int           // bounded retries for a single reload
	reloadBackoff  time.Duration // base delay between reload attempts

	// health tracks the most recent reload outcome and whether the watcher
	// has exited unrecoverably. It is guarded by its own mutex (separate from
	// mu) so a readiness probe can poll Healthy without contending with a
	// reload in progress.
	healthMu      sync.Mutex
	lastReloadErr error
	watcherErr    error
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
		drainWindow:          500 * time.Millisecond,
		reloadAttempts:       5,
		reloadBackoff:        200 * time.Millisecond,
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
		return nil, fmt.Errorf("the signer has expired: NotAfter=%v: %w", ca.certificate.NotAfter, ErrCASignerUnusable)
	}

	naf := nbf.Add(pcConfig.Duration)
	if naf.After(ca.certificate.NotAfter) {
		return nil, fmt.Errorf("certificate validity period exceeds the signer CA validity: notAfter=%v, caNotAfter=%v: %w", naf, ca.certificate.NotAfter, ErrCASignerUnusable)
	}
	if naf.Before(now) {
		return nil, fmt.Errorf("certificate not after is in the past: %v", naf)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("unable to generate a serial number for %s: %w", pcConfig.CommonName, err)
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

	var bundle []byte // nolint:prealloc
	bundle = append(bundle, ca.certificateToPEM()...)
	for _, prevBundle := range ca.previousCertificates {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: prevBundle.Raw,
		})...)
	}

	return bundle
}

// errWatchChannelClosed indicates that fsnotify closed one of its channels.
// This cannot be recovered in place, so the watcher must fail and be restarted.
var errWatchChannelClosed = errors.New("ca-watcher: fsnotify channel closed unexpectedly")

// Watch starts a [fsnotify.Watcher], which reloads the CA cert and private key
// when the underlying files change.
//
// Callers will be notified whenever the CA changes via the provided channel.
// If notifications are not needed, callers must provide nil as the notification
// channel.
//
// This method blocks until the given [context.Context] is canceled. It returns
// nil on a clean shutdown and a non-nil error if the watch cannot be
// established or fsnotify closes a channel; in the latter case [Healthy] also
// reports the failure so a readiness probe can surface it.
func (ca *CertificateAuthority) Watch(ctx context.Context, notify chan<- struct{}) error {
	logger := log.FromContext(ctx).WithName("ca-watcher")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return ca.failWatcher(fmt.Errorf("ca-watcher: unable to create fsnotify.Watcher: %w", err))
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
			return ca.failWatcher(fmt.Errorf("ca-watcher: unable to add watch directory %s: %w", path, err))
		}
	}

	return ca.watchLoop(ctx, logger, watcher.Events, watcher.Errors, notify)
}

// watchLoop consumes filesystem events until ctx is canceled, reloading the CA
// (with bounded retry) whenever the mounted files change. It returns nil on a
// clean shutdown (ctx canceled) and a non-nil error if fsnotify closes a
// channel, so the caller can fail fast and be restarted rather than spinning on
// zero values read from a closed channel.
func (ca *CertificateAuthority) watchLoop(
	ctx context.Context,
	logger logr.Logger,
	events <-chan fsnotify.Event,
	errs <-chan error,
	notify chan<- struct{},
) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-events:
			if !ok {
				return ca.failWatcher(errWatchChannelClosed)
			}
			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) && !event.Has(fsnotify.Rename) {
				continue
			}

			// Coalesce the burst of events a single (near-atomic) CA update
			// produces before reloading.
			switch err := ca.drainEvents(ctx, logger, events); {
			case err == nil:
				// Burst settled; fall through to reload.
			case errors.Is(err, errWatchChannelClosed):
				return ca.failWatcher(err)
			default:
				// ctx canceled while draining.
				return nil
			}

			logger.Info("reloading CA certificate")
			if err := ca.reloadWithRetry(ctx, logger); err != nil {
				// The last-good CA is retained, so signing keeps working.
				// Stay watching so a later good write recovers, but record
				// the failure for the readiness probe.
				logger.Error(err, "failed to reload CA certificate after retries")
				ca.recordReloadResult(err)
				continue
			}
			ca.recordReloadResult(nil)
			logger.Info("CA certificate reloaded successfully")

			// Don't block here, so that reloading the CA can proceed as
			// usual, even if we have slow consumers.
			if notify != nil {
				select {
				case notify <- struct{}{}:
				default:
				}
			}
		case err, ok := <-errs:
			if !ok {
				return ca.failWatcher(errWatchChannelClosed)
			}
			logger.Error(err, "error watching CA certificate")
		}
	}
}

// drainEvents coalesces a burst of filesystem events into a single reload. It
// returns nil once the burst settles (drain window elapses), ctx.Err() if ctx
// is canceled, or errWatchChannelClosed if the events channel is closed.
func (ca *CertificateAuthority) drainEvents(ctx context.Context, logger logr.Logger, events <-chan fsnotify.Event) error {
	timer := time.NewTimer(ca.drainWindow)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e, ok := <-events:
			if !ok {
				return errWatchChannelClosed
			}
			logger.V(1).Info("draining fsnotify event", "event", e.Op.String(), "name", e.Name)
		case <-timer.C:
			return nil
		}
	}
}

// reloadWithRetry attempts to reload the CA, retrying on a bounded linear
// backoff. A failed attempt leaves the last-good CA in place (see load), so
// callers keep signing with the previous material until a good reload succeeds.
// It returns nil on the first successful reload, ctx.Err() if ctx is canceled,
// or the final error once the attempt budget is exhausted.
func (ca *CertificateAuthority) reloadWithRetry(ctx context.Context, logger logr.Logger) error {
	const maxBackoff = 5 * time.Second

	var err error
	for attempt := 1; ; attempt++ {
		if err = ca.load(); err == nil {
			return nil
		}
		if attempt >= ca.reloadAttempts {
			return fmt.Errorf("reload failed after %d attempt(s): %w", attempt, err)
		}
		logger.Error(err, "failed to reload CA certificate, retrying",
			"attempt", attempt, "maxAttempts", ca.reloadAttempts)

		timer := time.NewTimer(min(ca.reloadBackoff*time.Duration(attempt), maxBackoff))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// recordReloadResult stores the outcome of the most recent reload attempt.
func (ca *CertificateAuthority) recordReloadResult(err error) {
	ca.healthMu.Lock()
	defer ca.healthMu.Unlock()
	ca.lastReloadErr = err
}

// failWatcher records the watcher's terminal error and returns it, so a caller
// can surface health and fail its runnable in a single step.
func (ca *CertificateAuthority) failWatcher(err error) error {
	ca.healthMu.Lock()
	ca.watcherErr = err
	ca.healthMu.Unlock()
	return err
}

// Healthy reports whether the CA is still tracking its on-disk material. It
// returns a non-nil error if the file watcher has exited unrecoverably or the
// most recent reload attempt ultimately failed. It is safe for concurrent use
// and is intended to back a readiness probe.
func (ca *CertificateAuthority) Healthy() error {
	ca.healthMu.Lock()
	defer ca.healthMu.Unlock()
	if ca.watcherErr != nil {
		return ca.watcherErr
	}
	return ca.lastReloadErr
}
