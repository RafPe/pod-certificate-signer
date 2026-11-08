package authority

import (
	"fmt"
	"sync"
	"time"
)

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

// reloadHealth tracks the recent reload outcomes and whether the watcher has
// exited unrecoverably. It has its own lock, separate from the CA's, so a
// readiness probe or a metrics scrape can read it without contending with a
// reload or a signing operation. The zero value is ready to use.
type reloadHealth struct {
	mu           sync.Mutex
	lastErr      error
	failures     int       // consecutive failed reload attempts
	firstFailure time.Time // when the current failure streak started
	lastSuccess  time.Time // when the CA was last read successfully
	watcherErr   error
}

// record stores the outcome of the most recent reload attempt and returns the
// resulting number of consecutive failures, so callers can report the streak
// alongside the failure. A successful reload clears the streak.
func (h *reloadHealth) record(err error) int {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastErr = err
	if err == nil {
		h.failures = 0
		h.firstFailure = time.Time{}
		h.lastSuccess = time.Now()

		return 0
	}

	if h.failures == 0 {
		h.firstFailure = time.Now()
	}
	h.failures++

	return h.failures
}

// failing reports whether the last reload attempt left the CA in a failed
// state, so a caller can tell a reload that recovered from one that was
// routine. Read before the reload it describes, since record clears the
// streak; only the watch goroutine reloads, so no attempt can interleave.
func (h *reloadHealth) failing() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.failures > 0
}

// failWatcher records the watcher's terminal error and returns it, so a caller
// can surface health and fail its runnable in a single step.
func (h *reloadHealth) failWatcher(err error) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.watcherErr = err
	return err
}

// check is HealthCheck's verdict; see there.
func (h *reloadHealth) check() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// A dead watcher is not a transient file blip: CA rotations would never be
	// observed again, so it fails readiness immediately.
	if h.watcherErr != nil {
		return h.watcherErr
	}
	if h.failures < reloadFailureThreshold {
		return nil
	}
	failingFor := time.Since(h.firstFailure)
	if failingFor < reloadFailureGracePeriod {
		return nil
	}

	return fmt.Errorf("CA reload failing for %s across %d consecutive attempts: %w",
		failingFor.Round(time.Second), h.failures, h.lastErr)
}

// ReloadHealth reports the consecutive-failure streak and when the CA was last
// read successfully. It is safe for concurrent use and does not contend with a
// reload, nor with a signing operation.
func (ca *CertificateAuthority) ReloadHealth() (int, time.Time) {
	ca.health.mu.Lock()
	defer ca.health.mu.Unlock()

	return ca.health.failures, ca.health.lastSuccess
}

// HealthCheck reports whether the CA is still tracking its on-disk material.
// It returns a non-nil error if the file watcher has exited unrecoverably, or if
// reloads have been failing persistently: at least reloadFailureThreshold
// consecutive attempts spanning at least reloadFailureGracePeriod. Reload
// failures within that grace period are reported as healthy, because the
// last-good CA is retained and signing keeps working. It is safe for concurrent
// use and is intended to back a readiness probe.
func (ca *CertificateAuthority) HealthCheck() error {
	return ca.health.check()
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
