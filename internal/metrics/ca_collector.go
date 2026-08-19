package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CAState is the view of the certificate authority the collector reads. It is
// an interface so this package stays free of project imports - the authority
// increments CAReloadAttempts, so it imports this package, and the dependency
// cannot run both ways.
//
// Each method must take its lock, copy a scalar and release: a scrape must
// never be able to block on a signing operation, and vice versa.
type CAState interface {
	// ReloadHealth reports the consecutive-failure streak and the time of the
	// last successful reload.
	ReloadHealth() (consecutiveFailures int, lastSuccess time.Time)
	// CertificateNotAfter reports the loaded CA certificate's expiry.
	CertificateNotAfter() time.Time
	// TrustBundleSize reports how many certificates the in-memory trust bundle
	// holds: the current CA plus the retained previous ones.
	TrustBundleSize() int
}

// caCollector reports the CA gauges (M3, M4, M5, M7) at scrape time rather than
// writing them when a reload happens.
//
// That is the point of it. A gauge written by a loop goes stale exactly when
// the loop stops, which is the failure M4 exists to catch - a wedged ticker
// produces no errors, so a failure-based signal stays at zero forever. Reading
// live memory on every scrape means these four cannot lag the reload loop, and
// there is no updater goroutine to start, stop or leak.
type caCollector struct {
	ca CAState

	consecutiveFailures *prometheus.Desc
	lastSuccess         *prometheus.Desc
	expiration          *prometheus.Desc
	trustBundleSize     *prometheus.Desc
}

// NewCACollector returns a collector reporting the CA gauges from ca.
func NewCACollector(ca CAState) prometheus.Collector {
	return &caCollector{
		ca: ca,
		consecutiveFailures: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "ca_reload_consecutive_failures"),
			"Consecutive failed CA reload attempts. Readiness fails once this reaches 3 and has been there for ten minutes, "+
				"so alerting at 3 gives roughly five minutes before the replica leaves the Service.",
			nil, nil),
		lastSuccess: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "ca_reload_last_success_timestamp_seconds"),
			"When the CA was last read successfully, as a Unix timestamp. Seeded at startup from the initial load. "+
				"time() minus this exceeding the 60s reconcile interval by a margin means the reload loop has stopped, "+
				"which no failure-based signal can show.",
			nil, nil),
		expiration: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "ca_expiration_timestamp_seconds"),
			"When the loaded CA certificate expires, as a Unix timestamp. The signer refuses to sign once a requested lifetime "+
				"would run past it, so this minus time() falling below the default certificate duration means the signer is "+
				"about to be unable to issue anything.",
			nil, nil),
		trustBundleSize: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "trust_bundle_certificates"),
			"Certificates in the in-memory trust bundle the signer would publish: the current CA plus retained previous ones. "+
				"This is what the signer holds, not a read of the ClusterTrustBundle object, so it does not detect drift in "+
				"the published bundle.",
			nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *caCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.consecutiveFailures
	ch <- c.lastSuccess
	ch <- c.expiration
	ch <- c.trustBundleSize
}

// Collect implements prometheus.Collector.
func (c *caCollector) Collect(ch chan<- prometheus.Metric) {
	failures, lastSuccess := c.ca.ReloadHealth()

	ch <- prometheus.MustNewConstMetric(c.consecutiveFailures, prometheus.GaugeValue, float64(failures))
	ch <- prometheus.MustNewConstMetric(c.lastSuccess, prometheus.GaugeValue, timestamp(lastSuccess))
	ch <- prometheus.MustNewConstMetric(c.expiration, prometheus.GaugeValue, timestamp(c.ca.CertificateNotAfter()))
	ch <- prometheus.MustNewConstMetric(c.trustBundleSize, prometheus.GaugeValue, float64(c.ca.TrustBundleSize()))
}

// timestamp renders t as Unix seconds, reporting a zero time as 0. A zero
// time.Time is Unix second -62135596800, a negative timestamp that reads as an
// error rather than as "never"; the epoch is the conventional spelling. Either
// way a staleness alert fires, which is correct - the CA has never been read.
// The authority seeds the last-success clock at construction, so this is a
// guard, not the normal path.
func timestamp(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}

	return float64(t.Unix())
}
