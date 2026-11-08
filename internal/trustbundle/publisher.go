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
)

// apiRetryBackoff is the retry budget one API operation gets for transient
// errors before its outcome is recorded as failed: a single publish, or the
// startup read of the previous-CA history. Both consumers read it directly, so
// tests exercise the same policy the binary ships with.
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

// Publisher keeps the signer's ClusterTrustBundle in step with the current CA.
// It publishes when it starts, whenever the CA watcher reports a change, and
// on a periodic drift-repair tick. Publishes are retried with exponential
// backoff. One goroutine runs them all, in order; change notifications that
// arrive while a publish runs wait in a small buffer, and any beyond it are
// dropped, which is safe because the next publish reads the CA as it is then.
// It is leader-gated so only the elected leader writes the shared resource.
type Publisher struct {
	client     client.Client
	signerName string
	ca         *authority.CertificateAuthority
	events     chan struct{}
	interval   time.Duration

	// healthMu guards the most recent publish outcome, polled by readiness.
	healthMu       sync.Mutex
	lastPublishErr error
}

// NewPublisher returns the runnable that publishes ca's trust bundle as the
// ClusterTrustBundle for signerName.
func NewPublisher(c client.Client, signerName string, ca *authority.CertificateAuthority) *Publisher {
	return &Publisher{
		client:     c,
		signerName: signerName,
		ca:         ca,
		// Two slots: one for the change being published, one for a change
		// that lands meanwhile. A third would publish the same CA state again.
		events:   make(chan struct{}, 2),
		interval: DriftRepairInterval,
	}
}

// Notify is the channel the CA watcher signals a changed CA on (see
// authority.NewWatcher). Sends must not block; the watcher's do not.
func (p *Publisher) Notify() chan<- struct{} {
	return p.events
}

// Start publishes the ClusterTrustBundle on startup, so a newly-elected leader
// publishes from the current in-memory CA, then on every CA change and on a
// periodic drift-repair tick, until ctx is canceled.
func (p *Publisher) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("cluster-trust-bundle")
	logger.Info("starting ClusterTrustBundle publisher", "driftRepairInterval", p.interval)

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	p.publish(ctx, logger)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-p.events:
			p.publish(ctx, logger)
		case <-ticker.C:
			// Periodic drift repair, independent of CA changes.
			p.publish(ctx, logger)
		}
	}
}

// NeedLeaderElection reports true so only the elected leader writes the
// ClusterTrustBundle.
func (*Publisher) NeedLeaderElection() bool { return true }

// publish writes the current CA trust bundle to the ClusterTrustBundle,
// retrying with exponential backoff, and records the outcome for readiness and
// the publish counter.
func (p *Publisher) publish(ctx context.Context, logger logr.Logger) {
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
	err := retry.OnError(apiRetryBackoff, func(error) bool { return ctx.Err() == nil }, func() error {
		var perr error
		op, perr = p.publishOnce(ctx, logger)
		return perr
	})
	if ctx.Err() != nil {
		// Shutting down: the publish was abandoned, not failed. Recording it
		// as a failure would flip readiness and count a failed publish for a
		// process that is exiting anyway.
		return
	}
	p.recordPublishResult(err)
	if err != nil {
		metrics.ClusterTrustBundlePublishAttempts.WithLabelValues(string(metrics.PublishFailed)).Inc()
		logger.Error(err, "ClusterTrustBundle publish failed after retries")
		return
	}
	metrics.ClusterTrustBundlePublishAttempts.WithLabelValues(string(publishResult(op))).Inc()
}

// publishResult maps CreateOrPatch's OperationResult onto the bounded result
// label. OperationResult is a closed set of Go constants, and the mutate
// function touches only .spec, so the status results cannot occur; they are
// folded into "updated" rather than minting a label value the surface does not
// budget for.
func publishResult(op controllerutil.OperationResult) metrics.PublishResult {
	switch op {
	case controllerutil.OperationResultNone:
		return metrics.PublishUnchanged
	case controllerutil.OperationResultCreated:
		return metrics.PublishCreated
	default:
		return metrics.PublishUpdated
	}
}

// publishOnce performs a single CreateOrPatch of the ClusterTrustBundle to the
// current CA trust bundle. The desired bundle is read from the CA once, so the
// object that is read, the spec that is compared and the spec that is written
// all describe the same CA state. The mutate function overwrites (never merges)
// the spec, so CA pruning in the rolling window is preserved.
func (p *Publisher) publishOnce(ctx context.Context, logger logr.Logger) (controllerutil.OperationResult, error) {
	desired := desiredBundle(p.signerName, p.ca)
	bundle := &certificatesv1.ClusterTrustBundle{ObjectMeta: metav1.ObjectMeta{Name: desired.Name}}
	// Use the direct API client: reading through the manager's cache-backed
	// client would start an informer for ClusterTrustBundles, which requires
	// list/watch RBAC permissions this controller does not need.
	op, err := controllerutil.CreateOrPatch(ctx, p.client, bundle, func() error {
		bundle.Spec = desired.Spec
		return nil
	})
	if err != nil {
		return op, fmt.Errorf("publish ClusterTrustBundle %q: %w", bundle.Name, err)
	}
	logger.Info("published ClusterTrustBundle", "name", bundle.Name, "operation", op)
	return op, nil
}

// recordPublishResult stores the outcome of the most recent publish.
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
