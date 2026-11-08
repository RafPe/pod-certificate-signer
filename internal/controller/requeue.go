package controller

import (
	"context"
	"errors"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// requeueOrRecordTerminal routes a signRequest error: terminal errors are
// recorded on the PCR and stop the reconcile; transient errors are requeued.
// If recording a terminal outcome fails, that write error is requeued too, so
// the Failed condition is never silently lost.
//
// A requeued error is not logged here: controller-runtime logs the error a
// reconcile returns, so logging it too would report each failure twice. A
// terminal outcome is logged once, at the severity it deserves - a denial is
// the requester's misconfiguration, a failure is the signer's.
func (r *PodCertificateRequestReconciler) requeueOrRecordTerminal(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, err error) (ctrl.Result, error) {
	var te *terminalError
	if !errors.As(err, &te) {
		return r.requeue(pcr, err)
	}

	logger := log.FromContext(ctx)
	if te.kind == outcome.Denied {
		logger.Info("request denied", "reason", te.reason, "error", te.err.Error())
	} else {
		logger.Error(te.err, "request failed", "reason", te.reason)
	}
	if werr := r.recordTerminal(ctx, pcr, te); werr != nil {
		return r.requeue(pcr, werr)
	}
	return ctrl.Result{}, nil
}

// requeue returns err to controller-runtime so the request is retried with
// backoff, counting the requeue and, when the CA is the cause, warning on the
// request. Every requeue of a request that was read goes through here.
func (r *PodCertificateRequestReconciler) requeue(pcr *certificatesv1.PodCertificateRequest, err error) (ctrl.Result, error) {
	if countRequeue(err) == outcome.CASignerUnusable {
		r.warnCASignerUnusable(pcr, err)
	}
	return ctrl.Result{}, err
}

// countRequeue counts one requeue under its classified reason and returns the
// reason. It is the one place the requeue counter moves, so the counter means
// what its help text says: one increment per attempt that did not finish. The
// classification is a closed set: the error text itself is unbounded and
// belongs in the log, never in a label.
func countRequeue(err error) outcome.NonTerminalReason {
	reason := outcome.Transient
	if errors.Is(err, authority.ErrCASignerUnusable) {
		reason = outcome.CASignerUnusable
	}
	metrics.PodCertificateRequestRequeues.WithLabelValues(string(reason)).Inc()
	return reason
}

// warnCASignerUnusable emits the warning event for a request the CA cannot
// sign at the moment. Anything else transient - an API read failure, a
// conflicted write - is the controller's own retry loop doing its job and
// needs no event. Without this one the wait is invisible where an operator
// looks for it: the requeue writes no condition (see outcome.NonTerminalReason),
// so `kubectl describe podcertificaterequest` would show nothing while the pod
// stays in ContainerCreating. It is rate-limited per request (see
// eventThrottle).
func (r *PodCertificateRequestReconciler) warnCASignerUnusable(pcr *certificatesv1.PodCertificateRequest, err error) {
	if !r.caUnusableEvents.allow(pcr.UID) {
		return
	}
	r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(outcome.CASignerUnusable), eventAction,
		"the signing CA cannot issue this certificate yet, retrying until it can: %s", err)
}

// warnPodGone emits the warning event for a request dropped because a live
// read confirmed its pod is gone, with the note saying whether it was absent
// or replaced. The event is the only breadcrumb the request's owner gets, and
// the counter carries the rate - which says the controller is losing a race
// with pod churn rather than dropping the odd stale request.
func (r *PodCertificateRequestReconciler) warnPodGone(pcr *certificatesv1.PodCertificateRequest, note string) {
	metrics.PodCertificateRequestDrops.WithLabelValues(string(outcome.AssociatedPodGone)).Inc()
	r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(outcome.AssociatedPodGone), eventAction, "%s", note)
}
