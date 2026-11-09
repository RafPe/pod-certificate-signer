// Package trustbundle keeps the signer's ClusterTrustBundle in step with the
// certificate authority: a runnable that reloads the CA when its files change,
// a leader-gated runnable that publishes the resulting trust bundle, and the
// startup read that seeds the previous-CA history from the bundle a prior
// process published.
package trustbundle

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/signer"
)

// apiRetryBackoff is the retry budget one API operation gets for transient
// errors before its outcome is recorded as failed: a single publish, or the
// startup read of the previous-CA history. Package-level so tests exercise the
// same policy the binary ships with.
var apiRetryBackoff = wait.Backoff{
	Steps:    5,
	Duration: 500 * time.Millisecond,
	Factor:   2.0,
	Jitter:   0.1,
}

// DriftRepairInterval is how often the publisher re-publishes the
// ClusterTrustBundle even without a CA reload event, to repair external drift
// (e.g. a manual edit or a lost event).
const DriftRepairInterval = 10 * time.Minute

// CAWatcher reloads the in-memory CA whenever the mounted certificate or key
// files change. It runs on every replica, independent of leader election, so
// that a standby replica keeps its CA current and never signs or publishes
// with stale material immediately after being promoted to leader.
type CAWatcher struct {
	ca     *authority.CertificateAuthority
	notify chan<- struct{}
}

// Start blocks watching the CA files until ctx is canceled. A failed watch is
// fatal: without it CA rotations would silently never be observed.
func (w *CAWatcher) Start(ctx context.Context) error {
	if err := w.ca.Watch(ctx, w.notify); err != nil {
		return fmt.Errorf("ca-watcher failed: %w", err)
	}
	return nil
}

// NeedLeaderElection reports false so the CA watcher runs on every replica.
func (*CAWatcher) NeedLeaderElection() bool { return false }

// Publisher reconciles the signer's ClusterTrustBundle towards the current CA.
// It publishes when it starts, on every CA reload event, and on a periodic
// drift-repair tick. Publishes are retried with exponential backoff and are
// single-flight (a reconcile triggered while one is in flight is coalesced). It
// is leader-gated so only the elected leader writes the shared resource.
type Publisher struct {
	client   client.Client
	signer   *signer.Signer
	events   <-chan struct{}
	interval time.Duration
	backoff  wait.Backoff

	// runMu is a single-flight guard: TryLock lets a reconcile skip when
	// another is already publishing.
	runMu sync.Mutex

	// healthMu guards the most recent publish outcome, polled by readiness.
	healthMu       sync.Mutex
	lastPublishErr error
}

// NewRunnables wires the CA file watcher and the ClusterTrustBundle publisher
// so that CA reload events flow from the watcher to the publisher over a shared
// channel. The watcher runs on every replica; the publisher is leader-gated.
func NewRunnables(c client.Client, s *signer.Signer, ca *authority.CertificateAuthority) (*CAWatcher, *Publisher) {
	events := make(chan struct{}, 2)
	watcher := &CAWatcher{ca: ca, notify: events}
	publisher := &Publisher{
		client:   c,
		signer:   s,
		events:   events,
		interval: DriftRepairInterval,
		backoff:  apiRetryBackoff,
	}
	return watcher, publisher
}

// Start publishes the ClusterTrustBundle on startup, so a newly-elected leader
// publishes from the current in-memory CA, then on every CA reload event and on
// a periodic drift-repair tick, until ctx is canceled.
func (p *Publisher) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("cluster-trust-bundle")
	logger.Info("starting ClusterTrustBundle publisher", "driftRepairInterval", p.interval)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	p.reconcile(ctx, logger)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-p.events:
			p.reconcile(ctx, logger)
		case <-ticker.C:
			// Periodic drift repair, independent of fsnotify events.
			p.reconcile(ctx, logger)
		}
	}
}

// NeedLeaderElection reports true so only the elected leader writes the
// ClusterTrustBundle.
func (*Publisher) NeedLeaderElection() bool { return true }

// reconcile publishes the current CA trust bundle to the ClusterTrustBundle,
// retrying with exponential backoff. It is single-flight: if a publish is
// already in flight the call is skipped, since the in-flight publish will use
// the latest in-memory CA state anyway. It returns true if a publish ran and
// false if it was skipped.
func (p *Publisher) reconcile(ctx context.Context, logger logr.Logger) bool {
	if !p.runMu.TryLock() {
		logger.V(1).Info("ClusterTrustBundle publish already in progress, skipping")
		return false
	}
	defer p.runMu.Unlock()

	var op controllerutil.OperationResult
	// The retriable predicate is keyed on ctx, not on the error. retry.OnError
	// takes no context and sleeps between attempts with a bare time.Sleep, so a
	// predicate that retried everything spent the whole backoff schedule
	// re-failing after ctx was canceled - a delay paid on leader handover,
	// since controller-runtime releases the Lease only once every runnable has
	// returned. Matching the error against context.Canceled instead would be
	// wrong in the other direction: a transport or per-request deadline
	// surfaces as an error wrapping context.DeadlineExceeded while ctx is still
	// live, and that is exactly the transient failure this backoff exists for.
	err := retry.OnError(p.backoff, func(error) bool { return ctx.Err() == nil }, func() error {
		var perr error
		op, perr = p.publishOnce(ctx, logger)
		return perr
	})
	p.recordPublishResult(err)
	if err != nil {
		metrics.ClusterTrustBundlePublishAttempts.WithLabelValues(metrics.ResultFailed).Inc()
		logger.Error(err, "unable to update ClusterTrustBundle after retries")
		return true
	}
	metrics.ClusterTrustBundlePublishAttempts.WithLabelValues(publishResult(op)).Inc()
	return true
}

// publishResult maps CreateOrPatch's OperationResult onto the bounded result
// label. OperationResult is a closed set of Go constants, and the mutate
// function touches only .spec, so the status results cannot occur; they are
// folded into "updated" rather than minting a label value the surface does not
// budget for.
func publishResult(op controllerutil.OperationResult) string {
	switch op {
	case controllerutil.OperationResultNone:
		return metrics.ResultUnchanged
	case controllerutil.OperationResultCreated:
		return metrics.ResultCreated
	default:
		return metrics.ResultUpdated
	}
}

// publishOnce performs a single CreateOrPatch of the ClusterTrustBundle to the
// current CA trust bundle. The desired bundle is read from the signer once, so
// the object that is read, the spec that is compared and the spec that is
// written all describe the same CA state. The mutate function overwrites (never
// merges) the spec, so CA pruning in the rolling window is preserved.
func (p *Publisher) publishOnce(ctx context.Context, logger logr.Logger) (controllerutil.OperationResult, error) {
	desired := p.signer.ClusterTrustBundle()
	bundle := &certificatesv1.ClusterTrustBundle{ObjectMeta: metav1.ObjectMeta{Name: desired.Name}}
	// Use the direct API client: reading through the manager's cache-backed
	// client would start an informer for ClusterTrustBundles, which requires
	// list/watch RBAC permissions this controller does not need.
	op, err := controllerutil.CreateOrPatch(ctx, p.client, bundle, func() error {
		bundle.Spec = desired.Spec
		return nil
	})
	if err != nil {
		return op, err
	}
	logger.Info("reconciled ClusterTrustBundle", "name", bundle.Name, "operation", op)
	return op, nil
}

// recordPublishResult stores the outcome of the most recent reconcile.
func (p *Publisher) recordPublishResult(err error) {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	p.lastPublishErr = err
}

// HealthCheck reports a non-nil error when the most recent ClusterTrustBundle
// publish failed after retries, so a persistently failing publisher fails
// readiness. It is safe for concurrent use.
func (p *Publisher) HealthCheck() error {
	p.healthMu.Lock()
	defer p.healthMu.Unlock()
	return p.lastPublishErr
}
