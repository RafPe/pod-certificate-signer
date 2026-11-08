package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// isTerminal reports whether the request already carries a terminal condition
// (Issued, Denied or Failed). kube-apiserver makes such a request immutable,
// so there is nothing left for the reconciler to do with it.
func isTerminal(pcr *certificatesv1.PodCertificateRequest) bool {
	return terminalConditionType(&pcr.Status) != ""
}

// terminalConditionType returns the terminal condition type (Issued, Denied or
// Failed) recorded on the request status, or an empty string when the request
// has not reached a terminal state yet.
func terminalConditionType(status *certificatesv1.PodCertificateRequestStatus) string {
	for _, c := range status.Conditions {
		switch c.Type {
		case certificatesv1.PodCertificateRequestConditionTypeIssued,
			certificatesv1.PodCertificateRequestConditionTypeDenied,
			certificatesv1.PodCertificateRequestConditionTypeFailed:
			return c.Type
		}
	}

	return ""
}

// conditionFor maps a terminal outcome onto the certificates API condition
// type that records it and the event type that announces it. It is the one
// place an outcome kind is translated; every other function carries the kind.
func conditionFor(kind outcome.Kind) (conditionType, eventType string) {
	switch kind {
	case outcome.Issued:
		return certificatesv1.PodCertificateRequestConditionTypeIssued, corev1.EventTypeNormal
	case outcome.Denied:
		return certificatesv1.PodCertificateRequestConditionTypeDenied, corev1.EventTypeWarning
	default:
		return certificatesv1.PodCertificateRequestConditionTypeFailed, corev1.EventTypeWarning
	}
}

// recordTerminal records the Denied or Failed condition a *terminalError
// carries. The certificate fields are cleared, since kube-apiserver requires
// them to be empty when denying or failing a PodCertificateRequest.
func (r *PodCertificateRequestReconciler) recordTerminal(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, te *terminalError) error {
	clearCertificate(pcr)
	_, err := r.recordOutcome(ctx, pcr, te.kind, te.reason, te.err.Error())
	return err
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

	return r.recordOutcome(ctx, pcr, outcome.Issued, outcome.CertificateIssued, "certificate issued")
}

// recordOutcome sets the condition for kind on the PodCertificateRequest,
// persists the status and only then emits the corresponding event. The order
// matters: the event announces an outcome, so it must not be emitted until
// the write that makes the outcome real has succeeded. Emitting first would
// advertise a result that a failed or conflicting write never persisted, and
// re-advertise it on every requeue. It reports whether the write was
// persisted: false means another writer recorded a terminal outcome first and
// this one was discarded.
func (r *PodCertificateRequestReconciler) recordOutcome(
	ctx context.Context,
	pcr *certificatesv1.PodCertificateRequest,
	kind outcome.Kind,
	reason outcome.ConditionReason,
	message string,
) (bool, error) {
	conditionType, eventType := conditionFor(kind)
	pcr.Status.Conditions = []metav1.Condition{{
		Type:               conditionType,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(reason),
		Message:            message,
	}}

	persisted, err := r.updateStatusWithRetry(ctx, pcr)
	if err != nil {
		return false, fmt.Errorf("record %s condition: %w", conditionType, err)
	}
	if !persisted {
		// Another writer recorded a terminal outcome first and won the race;
		// this reconcile's outcome was discarded, so there is nothing to
		// announce. updateStatusWithRetry has already logged the loss.
		return false, nil
	}

	// Counted here for the same reason the event is emitted here: the outcome
	// is not real until the write that carries it has persisted.
	metrics.PodCertificateRequests.WithLabelValues(string(kind), string(reason)).Inc()
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
		// Re-read live: the cache lags the write that caused the conflict.
		if gerr := r.APIReader.Get(ctx, key, pcr); gerr != nil {
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
