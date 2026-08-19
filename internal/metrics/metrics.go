// Package metrics holds the signer's custom Prometheus metric surface.
//
// ADR-0005 (docs/adr/0005-bounded-metrics-surface.md) decides what that surface
// is: nine metric families and a fixed number of time series per replica, with
// no label whose values are derived from an individual pod, request or issued
// certificate. The number of series does not move with the size of the cluster.
//
// Two rules govern anything added here, and they are the durable part of that
// record:
//
//   - a label is a closed enum this package can enumerate, never a passthrough
//     of an error string or an API object's name;
//   - a metric records what happened; an Event explains it to whoever owns the
//     workload; a status condition is the durable verdict.
//
// The declarations live in their own package rather than in package main so
// that internal/controller and internal/kubernetes/authority can both increment
// without an import cycle.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Namespace prefixes every metric this package declares. It is the application
// name with its separators removed, following cert-manager's certmanager_.
const Namespace = "podcertificatesigner"

// Result values for the ClusterTrustBundle publish counter. The first three are
// controller-runtime's CreateOrPatch outcomes, which are a closed set of Go
// constants; the fourth is ours.
const (
	ResultUnchanged = "unchanged"
	ResultCreated   = "created"
	ResultUpdated   = "updated"
	ResultFailed    = "failed"
)

// ClusterTrustBundlePublishAttempts counts ClusterTrustBundle publish attempts
// by result (M6). It replaces the unprefixed ctb_publish_failures_total, whose
// failure count is now {result="failed"}: a failure-only counter cannot express
// a ratio, and its zero is ambiguous between healthy, never-been-leader and
// wedged.
//
// {result="updated"} on a drift-repair tick with no CA rotation to explain it
// means the published bundle was not what we wanted and we overwrote it - i.e.
// somebody edited the cluster's trust anchors.
var ClusterTrustBundlePublishAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "clustertrustbundle_publish_attempts_total",
	Help: "ClusterTrustBundle publish attempts by result. unchanged, created and updated are the CreateOrPatch outcome; " +
		"failed counts publishes that exhausted their retry budget. Only the elected leader publishes.",
}, []string{"result"})

// collectors is every collector this package declares, in registration order.
func collectors() []prometheus.Collector {
	return []prometheus.Collector{
		ClusterTrustBundlePublishAttempts,
	}
}

// Register registers the signer's metric surface with r, together with any
// extra collectors the caller has to construct (the CA state collector needs a
// live CA, so it cannot be a package-level variable).
//
// It takes a prometheus.Registerer rather than reaching for the global registry
// so a test can register the whole surface into a throwaway pedantic registry
// and assert on what came out.
func Register(r prometheus.Registerer, extra ...prometheus.Collector) error {
	for _, c := range append(collectors(), extra...) {
		if err := r.Register(c); err != nil {
			return err
		}
	}
	preInitialise()

	return nil
}

// preInitialise exports a zero for every series that can exist, so an alert
// written as rate(...) > 0 has a series to evaluate against from the first
// scrape rather than from the first occurrence. Only combinations the code can
// actually produce are listed: a permanent zero for an impossible one would be
// worse than none at all.
//
// If a label's values cannot be enumerated here, the label was never bounded.
func preInitialise() {
	for _, result := range []string{ResultUnchanged, ResultCreated, ResultUpdated, ResultFailed} {
		ClusterTrustBundlePublishAttempts.WithLabelValues(result)
	}
}
