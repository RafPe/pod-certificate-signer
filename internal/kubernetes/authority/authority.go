package authority

import (
	"context"
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
	// fingerprint is the SHA-256 of the loaded certificate's DER, used by load
	// to tell a reload that changed the material from one that did not. It is
	// content-based rather than file metadata, so a rotation that preserves
	// mtime is still seen. Guarded by mu, like the fields it describes.
	fingerprint [sha256.Size]byte
	mu          sync.Mutex

	// Watch/reload tuning. Set to sane defaults in New; overridable in tests.
	drainWindow       time.Duration // coalesce window for a burst of fs events
	reloadAttempts    int           // bounded retries for a single reload
	reloadBackoff     time.Duration // base delay between reload attempts
	reconcileInterval time.Duration // periodic reload, independent of events

	// health tracks the recent reload outcomes and whether the watcher has
	// exited unrecoverably. It is guarded by its own mutex (separate from mu)
	// so a readiness probe can poll Healthy without contending with a reload
	// in progress.
	healthMu         sync.Mutex
	lastReloadErr    error
	reloadFailures   int       // consecutive failed reload attempts
	firstFailureTime time.Time // when the current failure streak started
	watcherErr       error
}

// Readiness grace period for CA reload failures. A failed reload leaves the
// last-good CA in place, so signing keeps working; failing readiness on the
// first blip only flaps the replica in and out of the Service for a condition
// that usually resolves on the next write. Readiness therefore fails only once
// the CA has been unloadable persistently: both thresholds must be crossed.
const (
	// reloadFailureThreshold is the number of consecutive failed reload
	// attempts required before readiness may fail.
	reloadFailureThreshold = 3

	// reloadFailureGracePeriod is how long the failure streak must have
	// lasted, measured from its first failure, before readiness may fail.
	reloadFailureGracePeriod = 10 * time.Minute
)

// caReconcileInterval is how often the watch loop reloads the CA without
// waiting for a filesystem event. fsnotify is not a durable event log: watches
// can be dropped, the kernel queue can overflow, and a watched directory that
// is deleted and recreated leaves the watch on the stale inode, in which case
// reloads are not failing, they are simply never attempted again. Reloading on
// a timer is what makes convergence to the material on disk guaranteed rather
// than best effort.
//
// This value has a ceiling, and it is not the obvious one. A tick makes a
// single reload attempt, so a permanently unloadable CA needs
// reloadFailureThreshold ticks to become eligible for a readiness failure.
// Raising the interval past reloadFailureGracePeriod / reloadFailureThreshold
// (3m20s) would make the threshold rather than the grace period the binding
// constraint in Healthy, so the signer would report NotReady *later* than it
// does today - a slower reconcile delaying the alarm rather than only the
// repair. At 60s there is ~3.3x of margin.
const caReconcileInterval = 60 * time.Second

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
		reconcileInterval:    caReconcileInterval,
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

	return ca, nil
}

// load loads the certificate and key for the [CertificateAuthority]. It reports
// whether the material on disk differs from what was already loaded, so callers
// can gate downstream work - notifying consumers, republishing the trust bundle
// - on a real rotation rather than on every successful read. An unchanged read
// still counts as a successful reload: "the CA is readable" is the health
// signal, "the CA changed" is not.
func (ca *CertificateAuthority) load() (bool, error) {
	caCert, err := tls.LoadX509KeyPair(ca.certFile, ca.privKeyFile)
	if err != nil {
		return false, fmt.Errorf("failed to load key pair: %w", err)
	}

	caX509Cert, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Validate: CA
	if !caX509Cert.BasicConstraintsValid || !caX509Cert.IsCA {
		return false, errors.New("certificate is not a valid CA certificate")
	}

	// Validate: key usage
	if (caX509Cert.KeyUsage & x509.KeyUsageCertSign) == 0 {
		return false, errors.New("CA certificate cannot sign certificates")
	}

	// Validate: not expired
	if time.Now().After(caX509Cert.NotAfter) {
		return false, errors.New("CA certificate has expired")
	}

	signer, ok := caCert.PrivateKey.(crypto.Signer)
	if !ok {
		return false, errors.New("private key does not implement crypto.Signer interface")
	}

	fingerprint := sha256.Sum256(caCert.Certificate[0])

	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Unchanged material: return before touching the certificate, the signer or
	// the history. The comparison belongs inside the critical section, since
	// ca.fingerprint is written below under the same lock.
	if ca.certificate != nil && ca.fingerprint == fingerprint {
		return false, nil
	}

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
	ca.fingerprint = fingerprint

	// Remove the current cert from the previous CA certs, in order to avoid
	// duplicate entries in the trust bundle.
	ca.previousCertificates = slices.DeleteFunc(ca.previousCertificates, func(item *x509.Certificate) bool {
		return item.Equal(ca.certificate)
	})

	return true, nil
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

	// Reconcile once now that the watches are registered: a rotation landing
	// between New's initial load and this point produces no observable event,
	// so without this pass it would go unnoticed until the first tick.
	logger.Info("reloading the CA periodically as well as on events", "interval", ca.reconcileInterval)
	ca.reconcileOnce(logger, notify, "watch startup")

	return ca.watchLoop(ctx, logger, watcher.Events, watcher.Errors, notify)
}

// watchLoop consumes filesystem events until ctx is canceled, reloading the CA
// (with bounded retry) whenever the mounted files change, and reloading it
// unconditionally every reconcileInterval so a rotation the event path never
// saw, or failed to load, still converges. It returns nil on a clean shutdown
// (ctx canceled) and a non-nil error if fsnotify closes a channel, so the caller
// can fail fast and be restarted rather than spinning on zero values read from a
// closed channel.
func (ca *CertificateAuthority) watchLoop(
	ctx context.Context,
	logger logr.Logger,
	events <-chan fsnotify.Event,
	errs <-chan error,
	notify chan<- struct{},
) error {
	ticker := time.NewTicker(ca.reconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Reconcile on every tick, not only while reloads are failing: the
			// silent routes (dropped events, a stale inode after the watched
			// directory is recreated) leave the CA in a *successful* state, so
			// a failure-gated pass would never run in exactly those cases.
			ca.reconcileOnce(logger, notify, "periodic reconciliation")
		case event, ok := <-events:
			if !ok {
				return ca.failWatcher(errWatchChannelClosed)
			}
			// Remove is included because a kubelet-style atomic swap replaces
			// the timestamped directory behind ..data, and a plain deletion of
			// the material must be observed rather than silently ignored.
			if !event.Has(fsnotify.Create) && !event.Has(fsnotify.Write) &&
				!event.Has(fsnotify.Rename) && !event.Has(fsnotify.Remove) {
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
			// Read before the reload: reloadWithRetry clears the streak on
			// success.
			wasFailing := ca.reloadFailing()
			changed, err := ca.reloadWithRetry(ctx, logger)
			if err != nil {
				// The last-good CA is retained, so signing keeps working.
				// Stay watching so a later good write - or the next tick -
				// recovers; readiness is only affected once the failures
				// persist (see Healthy).
				logger.Error(err, "failed to reload CA certificate after retries")
				continue
			}
			if !changed {
				// A single rotation can drive more than one reload: two
				// watched directories, events arriving after the drain window,
				// or a tick that already picked the material up. Only the one
				// that actually changed the CA is worth publishing.
				//
				// Recovery is the exception worth announcing: correcting a
				// mismatched pair restores the same certificate, so nothing
				// changed, but "the CA is loadable again" is exactly what an
				// operator who just fixed it is watching for.
				if wasFailing {
					logger.Info("CA certificate reloaded successfully", "recovered", true)
					continue
				}
				logger.V(1).Info("CA certificate on disk is unchanged, nothing to publish")
				continue
			}
			logger.Info("CA certificate reloaded successfully")
			notifyChanged(notify)
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

// reconcileOnce reloads the CA once, without retrying, and notifies callers
// when the material actually changed. The retry budget in reloadWithRetry
// exists to ride out the torn state a rotation briefly leaves on disk, which is
// event-adjacent; a pass that is not correlated with a write has nothing to ride
// out, and the next pass is itself the retry. Keeping it to a single attempt
// also bounds the log stream: a permanently unloadable CA costs one line per
// interval rather than the whole retry burst, forever.
func (ca *CertificateAuthority) reconcileOnce(logger logr.Logger, notify chan<- struct{}, cause string) {
	// Read before the reload: recordReloadResult below clears the streak.
	wasFailing := ca.reloadFailing()
	changed, err := ca.load()

	// Recorded regardless of whether anything changed: a readable CA clears the
	// failure streak (so a replica recovers readiness without a restart), and an
	// unreadable one accumulates towards the readiness threshold even though no
	// filesystem event ever arrived.
	ca.recordReloadResult(err)

	switch {
	case err != nil:
		logger.Error(err, "failed to reload CA certificate; retaining the last-good CA", "cause", cause)
	case changed:
		logger.Info("CA certificate reloaded successfully", "cause", cause)
		notifyChanged(notify)
	case wasFailing:
		// Recovery is worth announcing even though nothing changed. Correcting
		// a mismatched pair restores the *same* certificate, so `changed` is
		// false and the V(1) line below would be the only record - invisible at
		// the default verbosity, to an operator who has just fixed the CA and is
		// watching for confirmation. No notify: nothing moved, so nothing needs
		// republishing.
		logger.Info("CA certificate reloaded successfully", "cause", cause, "recovered", true)
	default:
		logger.V(1).Info("CA certificate on disk is unchanged", "cause", cause)
	}
}

// notifyChanged performs a non-blocking send on notify, so reloading the CA can
// proceed as usual even if we have slow consumers. A nil channel means the
// caller did not ask for notifications.
func notifyChanged(notify chan<- struct{}) {
	if notify == nil {
		return
	}
	select {
	case notify <- struct{}{}:
	default:
	}
}

// reloadWithRetry attempts to reload the CA, retrying on a bounded linear
// backoff. A failed attempt leaves the last-good CA in place (see load), so
// callers keep signing with the previous material until a good reload succeeds.
// Every attempt is recorded for the readiness probe (see Healthy).
// It reports whether the reload changed the CA material, so callers only
// republish on a real rotation. It returns nil on the first successful reload,
// ctx.Err() if ctx is canceled, or the final error once the attempt budget is
// exhausted.
func (ca *CertificateAuthority) reloadWithRetry(ctx context.Context, logger logr.Logger) (bool, error) {
	const maxBackoff = 5 * time.Second

	var err error
	for attempt := 1; ; attempt++ {
		var changed bool
		if changed, err = ca.load(); err == nil {
			ca.recordReloadResult(nil)

			return changed, nil
		}

		// Record each failed attempt rather than only the exhausted burst:
		// nothing reloads again until the next filesystem event, so a CA that
		// stays unloadable must be able to cross the readiness threshold
		// without one.
		failures := ca.recordReloadResult(err)
		if attempt >= ca.reloadAttempts {
			return false, fmt.Errorf("reload failed after %d attempt(s), %d consecutive failure(s): %w",
				attempt, failures, err)
		}
		logger.Error(err, "failed to reload CA certificate, retrying",
			"attempt", attempt, "maxAttempts", ca.reloadAttempts,
			"consecutiveFailures", failures)

		timer := time.NewTimer(min(ca.reloadBackoff*time.Duration(attempt), maxBackoff))
		select {
		case <-ctx.Done():
			timer.Stop()
			return false, ctx.Err()
		case <-timer.C:
		}
	}
}

// reloadFailing reports whether the last reload attempt left the CA in a failed
// state, so a caller can tell a reload that recovered from one that was routine.
//
// Read before the reload it describes, since recordReloadResult clears the
// streak. Only the watch goroutine reloads, so no attempt can interleave.
func (ca *CertificateAuthority) reloadFailing() bool {
	ca.healthMu.Lock()
	defer ca.healthMu.Unlock()

	return ca.reloadFailures > 0
}

// recordReloadResult stores the outcome of the most recent reload attempt and
// returns the resulting number of consecutive failures, so callers can report
// the streak alongside the failure. A successful reload clears the streak.
func (ca *CertificateAuthority) recordReloadResult(err error) int {
	ca.healthMu.Lock()
	defer ca.healthMu.Unlock()

	ca.lastReloadErr = err
	if err == nil {
		ca.reloadFailures = 0
		ca.firstFailureTime = time.Time{}

		return 0
	}

	if ca.reloadFailures == 0 {
		ca.firstFailureTime = ca.now()
	}
	ca.reloadFailures++

	return ca.reloadFailures
}

// now returns the current time from the configured clock, which tests replace
// to exercise time-dependent behavior without sleeping.
func (ca *CertificateAuthority) now() time.Time {
	if ca.nowFunc != nil {
		return ca.nowFunc()
	}

	return time.Now()
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
// returns a non-nil error if the file watcher has exited unrecoverably, or if
// reloads have been failing persistently: at least reloadFailureThreshold
// consecutive attempts spanning at least reloadFailureGracePeriod. Reload
// failures within that grace period are reported as healthy, because the
// last-good CA is retained and signing keeps working. It is safe for concurrent
// use and is intended to back a readiness probe.
func (ca *CertificateAuthority) Healthy() error {
	ca.healthMu.Lock()
	defer ca.healthMu.Unlock()

	// A dead watcher is not a transient file blip: CA rotations would never be
	// observed again, so it fails readiness immediately.
	if ca.watcherErr != nil {
		return ca.watcherErr
	}
	if ca.lastReloadErr == nil || ca.reloadFailures < reloadFailureThreshold {
		return nil
	}
	failingFor := ca.now().Sub(ca.firstFailureTime)
	if failingFor < reloadFailureGracePeriod {
		return nil
	}

	return fmt.Errorf("CA reload failing for %s across %d consecutive attempts: %w",
		failingFor.Round(time.Second), ca.reloadFailures, ca.lastReloadErr)
}
