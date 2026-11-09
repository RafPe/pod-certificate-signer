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
// that internal/controller, internal/authority and internal/trustbundle can
// all increment without an import cycle.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	certificatesv1 "k8s.io/api/certificates/v1"
)

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

	// ResultChanged is the CA reload counter's third value: the material on
	// disk differed from what was loaded, i.e. a rotation actually took.
	ResultChanged = "changed"
)

// Outcome values for the terminal-outcome counter. They name what happened to
// the request, not which condition type carried it, so an outcome stays
// aggregatable if the API ever grows a fourth condition.
const (
	OutcomeIssued = "issued"
	OutcomeDenied = "denied"
	OutcomeFailed = "failed"
)

// Reason identifies why a PodCertificateRequest ended up where it did: the
// reason written onto its terminal condition, or the event-only outcome of a
// requeue or a drop.
//
// The terminal ones are the certificates API's own condition reasons, spelled
// exactly as they are written onto the object, so a value read off a graph
// greps identically against `kubectl get podcertificaterequest -o yaml`. The
// requeue and drop reasons name conditions the API has no vocabulary for, so
// the signer defines them; they are still a closed set declared here, never a
// passthrough of an error string. They are declared in this package, the leaf
// of the import graph, so the controller that writes them and the metrics
// that count them share one definition.
type Reason string

const (
	ReasonCertificateIssued  Reason = "CertificateIssued"
	ReasonUnsupportedKeyType Reason = Reason(certificatesv1.PodCertificateRequestConditionUnsupportedKeyType)
	ReasonInvalidUserConfig  Reason = Reason(certificatesv1.PodCertificateRequestConditionInvalidUserConfig)
	ReasonSigningFailed      Reason = "SigningFailed"

	// ReasonCASignerUnusable is event-only and is deliberately never written as
	// a condition: the CA cannot sign this request right now (it has expired,
	// or its remaining validity is shorter than the requested lifetime), but a
	// CA rotation can make the same request succeed, so the reconcile requeues
	// rather than recording an outcome. Writing a condition would make the
	// request immutable and turn a recoverable wait into a permanent failure.
	ReasonCASignerUnusable Reason = "CASignerUnusable"
	// ReasonTransient classifies every other requeue: an API read failure, a
	// conflicted write. The controller's own retry loop is doing its job.
	ReasonTransient Reason = "Transient"
	// ReasonAssociatedPodGone is event-only and is never written as a
	// condition: a request whose pod a live read confirms is gone (absent, or
	// replaced by a different pod) is dropped, not failed.
	ReasonAssociatedPodGone Reason = "AssociatedPodGone"
)

// IssuanceOutcome is one outcome/reason pair the reconciler can record.
type IssuanceOutcome struct {
	Outcome string
	Reason  Reason
}

// IssuanceOutcomes is every outcome/reason pair the reconciler can record, and
// the only ones pre-initialised. It is hand-curated rather than derived from
// the reason constants because they do not form a cross product: deriving the
// table would ship a permanent zero series for pairs that cannot occur, which
// is worse than no series at all - it makes an operator believe a category is
// being watched.
var IssuanceOutcomes = []IssuanceOutcome{
	{OutcomeIssued, ReasonCertificateIssued},
	{OutcomeDenied, ReasonUnsupportedKeyType},
	{OutcomeDenied, ReasonInvalidUserConfig},
	{OutcomeFailed, ReasonSigningFailed},
}

// PodCertificateRequests counts terminal PodCertificateRequest outcomes (M1).
// It carries the SLI: issued over total.
//
// Every request contributes at most once, because a terminal condition makes
// the object immutable and every later reconcile short-circuits on it. Requeues
// and drops are deliberately not in here: a requeue is not an outcome, and
// counting one would put retries in the denominator of a success ratio.
var PodCertificateRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "podcertificaterequests_total",
	Help: "Terminal PodCertificateRequest outcomes by outcome and reason. Counted after the status write that makes the outcome real, " +
		"so an outcome discarded by a lost race is not counted. Requeues and drops are counted separately.",
}, []string{"outcome", "reason"})

// PodCertificateRequestRequeues counts reconciles returned for retry (M1b).
// It is per attempt by construction, which is the point: one request requeueing
// forever is exactly the silent hang this isolates, and it would be invisible
// in a terminal-outcome counter.
var PodCertificateRequestRequeues = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "podcertificaterequest_requeues_total",
	Help: "PodCertificateRequest reconciles requeued after a transient error, by reason. Counted per attempt, not per request: " +
		"CASignerUnusable rising with nothing terminal alongside it means requests are hanging on the CA, with pods stuck in ContainerCreating.",
}, []string{"reason"})

// PodCertificateRequestDrops counts requests dropped without a status (M1c):
// each one is a pod that will never get its credential.
//
// A drop writes no status, so the request never becomes immutable and the same
// one can be counted again after a restart or an informer resync. This counts
// occurrences, not distinct requests, and must not be read as the latter.
var PodCertificateRequestDrops = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "podcertificaterequest_drops_total",
	Help: "PodCertificateRequests dropped because a live read confirmed the associated pod is gone. No status is written, so a drop is " +
		"not terminal and the same request may be counted more than once; read this as occurrences, not as distinct requests.",
}, []string{"reason"})

// CAReloadAttempts counts CA reload attempts by result (M2).
//
// It is attempts, not reloads: a single burst retries up to five times, so the
// counter can rise by five where the log rose by one. {result="changed"} marks
// a rotation on every dashboard panel; {result="failed"} is the warning-grade
// alert; {result="unchanged"} is what makes a zero failure count interpretable.
var CAReloadAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: Namespace,
	Name:      "ca_reload_attempts_total",
	Help: "CA reload attempts by result. changed means the material on disk differed from what was loaded; a failed reload retains the " +
		"last-good CA, so signing keeps working. Counted per attempt, and one burst makes several.",
}, []string{"result"})

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
		CAReloadAttempts,
		PodCertificateRequests,
		PodCertificateRequestRequeues,
		PodCertificateRequestDrops,
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
	for _, result := range []string{ResultChanged, ResultUnchanged, ResultFailed} {
		CAReloadAttempts.WithLabelValues(result)
	}
	for _, pair := range IssuanceOutcomes {
		PodCertificateRequests.WithLabelValues(pair.Outcome, string(pair.Reason))
	}
	for _, reason := range []Reason{ReasonCASignerUnusable, ReasonTransient} {
		PodCertificateRequestRequeues.WithLabelValues(string(reason))
	}
	PodCertificateRequestDrops.WithLabelValues(string(ReasonAssociatedPodGone))
	for _, result := range []string{ResultUnchanged, ResultCreated, ResultUpdated, ResultFailed} {
		ClusterTrustBundlePublishAttempts.WithLabelValues(result)
	}
}
