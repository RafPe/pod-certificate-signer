package authority

import (
	"fmt"
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
		ca.lastSuccessTime = time.Now()

		return 0
	}

	if ca.reloadFailures == 0 {
		ca.firstFailureTime = time.Now()
	}
	ca.reloadFailures++

	return ca.reloadFailures
}

// ReloadHealth reports the consecutive-failure streak and when the CA was last
// read successfully. It is safe for concurrent use, and takes healthMu rather
// than mu for the same reason HealthCheck does: a poller must not contend with a
// reload, nor with a signing operation.
func (ca *CertificateAuthority) ReloadHealth() (int, time.Time) {
	ca.healthMu.Lock()
	defer ca.healthMu.Unlock()

	return ca.reloadFailures, ca.lastSuccessTime
}

// CertificateNotAfter reports when the loaded CA certificate expires. It is
// safe for concurrent use: it takes mu, copies a scalar and releases, so a
// caller reading it on a metrics scrape does not hold the lock across signing.
func (ca *CertificateAuthority) CertificateNotAfter() time.Time {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// See the certificate field. With no certificate loaded, report the zero
	// time - the collector renders it as a 0 gauge (see metrics.timestamp),
	// which correctly fires the staleness alert.
	if ca.certificate == nil {
		return time.Time{}
	}

	return ca.certificate.NotAfter
}

// TrustBundleSize reports how many certificates the in-memory trust bundle
// holds: the current CA plus the retained previous ones. It is what the signer
// would publish, not a read of the published ClusterTrustBundle. Safe for
// concurrent use.
func (ca *CertificateAuthority) TrustBundleSize() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// See the certificate field: no CA loaded means nothing would be
	// published, matching TrustBundlePEM.
	if ca.certificate == nil {
		return 0
	}

	return 1 + len(ca.previousCertificates)
}

// failWatcher records the watcher's terminal error and returns it, so a caller
// can surface health and fail its runnable in a single step.
func (ca *CertificateAuthority) failWatcher(err error) error {
	ca.healthMu.Lock()
	ca.watcherErr = err
	ca.healthMu.Unlock()
	return err
}

// HealthCheck reports whether the CA is still tracking its on-disk material.
// It returns a non-nil error if the file watcher has exited unrecoverably, or if
// reloads have been failing persistently: at least reloadFailureThreshold
// consecutive attempts spanning at least reloadFailureGracePeriod. Reload
// failures within that grace period are reported as healthy, because the
// last-good CA is retained and signing keeps working. It is safe for concurrent
// use and is intended to back a readiness probe.
func (ca *CertificateAuthority) HealthCheck() error {
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
	failingFor := time.Since(ca.firstFailureTime)
	if failingFor < reloadFailureGracePeriod {
		return nil
	}

	return fmt.Errorf("CA reload failing for %s across %d consecutive attempts: %w",
		failingFor.Round(time.Second), ca.reloadFailures, ca.lastReloadErr)
}
