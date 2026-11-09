package controller

import (
	"context"
	"errors"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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
	var te *TerminalError
	if !errors.As(err, &te) {
		return r.requeue(pcr, err)
	}

	logger := log.FromContext(ctx)
	if te.Denied {
		logger.Info("request denied", "reason", te.Reason, "error", te.Err.Error())
	} else {
		logger.Error(te.Err, "request failed", "reason", te.Reason)
	}
	if werr := r.recordTerminal(ctx, pcr, te); werr != nil {
		return r.requeue(pcr, werr)
	}
	return ctrl.Result{}, nil
}

// requeue returns err to controller-runtime so the request is retried with
// backoff, counting the requeue and announcing it when the CA is the cause.
// Every requeue goes through here, so the requeue counter means what its help
// text says: one increment per attempt that did not finish. The metric is
// unconditional so a rate is meaningful; the event is throttled per request,
// since a CA-unusable requeue repeats until the CA is rotated.
func (r *PodCertificateRequestReconciler) requeue(pcr *certificatesv1.PodCertificateRequest, err error) (ctrl.Result, error) {
	reason := requeueReason(err)
	metrics.PodCertificateRequestRequeues.WithLabelValues(string(reason)).Inc()
	if reason == outcome.CASignerUnusable {
		r.warnCASignerUnusable(pcr, err)
	}
	return ctrl.Result{}, err
}

// recordTerminal records a Denied/Failed condition carried by a *TerminalError.
// The certificate fields are cleared, since kube-apiserver requires them to be
// empty when denying or failing a PodCertificateRequest.
func (r *PodCertificateRequestReconciler) recordTerminal(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, te *TerminalError) error {
	clearCertificate(pcr)
	_, err := r.recordOutcome(ctx, pcr, te.conditionType(), te.Reason, te.Err.Error(), corev1.EventTypeWarning)
	return err
}

// warnCASignerUnusable emits the warning event for a request the CA cannot
// sign at the moment (see outcome.CASignerUnusable). Anything else transient -
// an API read failure, a conflicted write - is the controller's own retry loop
// doing its job and needs no event, so only the CA-unusable case is announced.
//
// Without it the wait is invisible where an operator looks for it: the requeue
// writes no condition, so `kubectl describe podcertificaterequest` shows
// nothing at all, and the pod stays in ContainerCreating while the only signals
// are a controller log line and controller_runtime_reconcile_errors_total.
//
// The emission is rate-limited per request rather than per reconcile: the
// requeue repeats until the CA is rotated, and an event per attempt would be an
// event storm rather than a signal. Deliberately no status write, as with
// warnPodGone (see outcome.EventReason).
func (r *PodCertificateRequestReconciler) warnCASignerUnusable(pcr *certificatesv1.PodCertificateRequest, err error) {
	if !r.caUnusableEvents.allow(pcr.UID) {
		return
	}
	r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(outcome.CASignerUnusable), eventAction,
		"the signing CA cannot issue this certificate yet, retrying until it can: %s", err)
}

// warnPodGone emits the warning event for a request dropped because a live
// read confirmed its pod is gone. The note is supplied by the caller, since
// "absent" and "replaced by a different pod" are different facts for whoever
// reads the event. Deliberately no status write: the drop is not a terminal
// outcome, and the event is the only breadcrumb an operator gets.
func (r *PodCertificateRequestReconciler) warnPodGone(pcr *certificatesv1.PodCertificateRequest, noteFmt string, args ...any) {
	// The event names the object and is the only breadcrumb its owner gets; the
	// metric carries the rate, which is what says the controller is losing a
	// race with pod churn rather than dropping the odd stale request.
	metrics.PodCertificateRequestDrops.WithLabelValues(string(outcome.AssociatedPodGone)).Inc()
	r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(outcome.AssociatedPodGone), eventAction, noteFmt, args...)
}

// requeueReason classifies a transient error for the requeue counter. The
// classification is a closed set computed here: the error text itself is
// unbounded (it can carry std-lib and apiserver detail) and belongs in the log,
// never in a label.
func requeueReason(err error) outcome.EventReason {
	if errors.Is(err, authority.ErrCASignerUnusable) {
		return outcome.CASignerUnusable
	}

	return outcome.Transient
}

// requestOutcome maps a condition type onto the outcome label. The three
// condition types the signer writes are the closed set the certificates API
// defines; anything else would be a condition this controller never records.
func requestOutcome(conditionType string) outcome.Kind {
	switch conditionType {
	case certificatesv1.PodCertificateRequestConditionTypeIssued:
		return outcome.Issued
	case certificatesv1.PodCertificateRequestConditionTypeDenied:
		return outcome.Denied
	default:
		return outcome.Failed
	}
}

// beginRefreshAt is when kubelet should start refreshing cert: RefreshBefore
// ahead of its expiry.
func beginRefreshAt(cert *podcertificate.Certificate) time.Time {
	return cert.NotAfter.Add(-cert.Config.RefreshBefore)
}

// recordIssued writes the issued certificate and its validity bounds onto the
// request status together with the Issued condition. It reports whether the
// write was persisted (see recordOutcome).
func (r *PodCertificateRequestReconciler) recordIssued(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, cert *podcertificate.Certificate) (bool, error) {
	pcr.Status.CertificateChain = cert.CertificateChain
	pcr.Status.NotBefore = &metav1.Time{Time: cert.NotBefore}
	pcr.Status.NotAfter = &metav1.Time{Time: cert.NotAfter}
	pcr.Status.BeginRefreshAt = &metav1.Time{Time: beginRefreshAt(cert)}

	const message = "Certificate successfully issued"
	return r.recordOutcome(ctx, pcr, certificatesv1.PodCertificateRequestConditionTypeIssued, outcome.CertificateIssued, message, corev1.EventTypeNormal)
}

// recordOutcome sets the condition on the PodCertificateRequest, persists the
// status and only then emits the corresponding event. The order matters: the
// event announces an outcome, so it must not be emitted until the write that
// makes the outcome real has succeeded. Emitting first would advertise a result
// that a failed or conflicting write never persisted, and re-advertise it on
// every requeue. It reports whether the write was persisted: false means
// another writer recorded a terminal outcome first and this one was discarded.
func (r *PodCertificateRequestReconciler) recordOutcome(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, conditionType string, reason outcome.ConditionReason, message, eventType string) (bool, error) {
	pcr.Status.Conditions = []metav1.Condition{{
		Type:               conditionType,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(reason),
		Message:            message,
	}}

	persisted, err := r.updateStatusWithRetry(ctx, pcr)
	if err != nil {
		return false, err
	}
	if !persisted {
		// Another writer recorded a terminal outcome first and won the race;
		// this reconcile's outcome was discarded, so there is nothing to
		// announce. updateStatusWithRetry has already logged the loss.
		return false, nil
	}

	// Counted here for the same reason the event is emitted here: the outcome
	// is not real until the write that carries it has persisted. Counting
	// before would inflate the issued rate with certificates no request ever
	// received.
	metrics.PodCertificateRequests.WithLabelValues(string(requestOutcome(conditionType)), string(reason)).Inc()
	// The message is data, not a format: a denial carries the requester's own
	// annotation text, and a % in it must reach the event verbatim.
	r.EventRecorder.Eventf(pcr, nil, eventType, string(reason), eventAction, "%s", message)
	return true, nil
}

// updateStatusWithRetry writes the PodCertificateRequest status, retrying on a
// version conflict within this single reconcile, and reports whether the write
// was persisted. A 409 means another writer advanced the object between the
// read and the write; letting it propagate out of Reconcile would re-run the
// whole signing pipeline next pass, minting a fresh certificate and serial
// number for a status that was ultimately discarded. Instead re-read the live
// object, re-apply the outcome and try again, so the signer runs once
// regardless of a lost race on the write.
//
// If the re-read shows a terminal condition another writer already recorded,
// this reconcile lost the race: the request is now immutable, so its outcome is
// left in place (persisted is false) rather than overwritten.
func (r *PodCertificateRequestReconciler) updateStatusWithRetry(ctx context.Context, pcr *certificatesv1.PodCertificateRequest) (bool, error) {
	desired := pcr.Status.DeepCopy()
	key := client.ObjectKeyFromObject(pcr)

	// PodCertificateRequests are served from the manager cache, which lags the
	// write that caused the conflict; re-read through the API reader so the
	// retry carries the current resourceVersion, not the stale cached one.
	reader := r.APIReader

	persisted := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		err := r.Status().Update(ctx, pcr)
		if err == nil {
			persisted = true
			return nil
		}
		if !apierrors.IsConflict(err) {
			return err
		}
		if gerr := reader.Get(ctx, key, pcr); gerr != nil {
			return gerr
		}
		if isTerminal(pcr) {
			// A terminal outcome already won; leave it in place. Stop retrying
			// (return nil) with persisted still false so the caller announces
			// nothing.
			log.FromContext(ctx).Info("another writer recorded a terminal outcome first; discarding this reconcile's outcome",
				"winningCondition", terminalConditionType(&pcr.Status))
			return nil
		}
		// Not terminal, so nothing on the fresh object needs preserving: a
		// non-terminal request carries no conditions and no certificate block.
		// Re-apply this reconcile's intended status (onto the fresh
		// resourceVersion) and retry.
		desired.DeepCopyInto(&pcr.Status)
		return err
	})
	return persisted, err
}

// clearCertificate empties the certificate block of the request status, which
// kube-apiserver requires when a request is denied or failed.
func clearCertificate(pcr *certificatesv1.PodCertificateRequest) {
	pcr.Status.CertificateChain = ""
	pcr.Status.NotBefore = nil
	pcr.Status.NotAfter = nil
	pcr.Status.BeginRefreshAt = nil
}
