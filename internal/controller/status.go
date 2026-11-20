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

// writeResult says what happened to one status write, so the caller can tell
// an outcome that is in place from one that was lost, belongs to no live
// request, was refused, or may or may not have been committed.
type writeResult int

const (
	writePersisted  writeResult = iota // the API server accepted this reconcile's outcome
	writeSuperseded                    // same UID, another terminal outcome is in place
	writeGone                          // the request was deleted or replaced
	writeRejected                      // the API server refused the write with a definite 4xx
	writeUnknown                       // the write may or may not be committed
)

// recordTerminal records the Denied or Failed condition a *terminalError
// carries. The certificate fields are cleared, since kube-apiserver requires
// them to be empty when denying or failing a PodCertificateRequest. It reports
// what happened to the write (see recordOutcome).
func (r *PodCertificateRequestReconciler) recordTerminal(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, te *terminalError) (writeResult, error) {
	clearCertificate(pcr)
	return r.recordOutcome(ctx, pcr, te.kind, te.reason, te.err.Error())
}

// beginRefreshAt is when kubelet should start refreshing cert: RefreshBefore
// ahead of its expiry.
func beginRefreshAt(cert *podcertificate.Certificate) time.Time {
	return cert.NotAfter.Add(-cert.Config.RefreshBefore)
}

// recordIssued writes the issued certificate and its validity bounds onto the
// request status together with the Issued condition. It reports what happened
// to the write (see recordOutcome).
func (r *PodCertificateRequestReconciler) recordIssued(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, cert *podcertificate.Certificate) (writeResult, error) {
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
// re-advertise it on every requeue. It reports what happened to the write
// (see updateStatusWithRetry): only writePersisted is announced and counted,
// and the error is non-nil only for writeRejected and writeUnknown.
func (r *PodCertificateRequestReconciler) recordOutcome(
	ctx context.Context,
	pcr *certificatesv1.PodCertificateRequest,
	kind outcome.Kind,
	reason outcome.ConditionReason,
	message string,
) (writeResult, error) {
	conditionType, eventType := conditionFor(kind)
	pcr.Status.Conditions = []metav1.Condition{{
		Type:               conditionType,
		Status:             metav1.ConditionTrue,
		LastTransitionTime: metav1.Now(),
		Reason:             string(reason),
		Message:            message,
	}}

	result, err := r.updateStatusWithRetry(ctx, pcr)
	if err != nil {
		return result, fmt.Errorf("record %s condition: %w", conditionType, err)
	}
	if result != writePersisted {
		// The outcome lost to another writer or belongs to no live request, so
		// there is nothing to announce. updateStatusWithRetry has already
		// logged why.
		return result, nil
	}

	// Counted here for the same reason the event is emitted here: the outcome
	// is not real until the write that carries it has persisted.
	metrics.PodCertificateRequests.WithLabelValues(string(kind), string(reason)).Inc()
	// The message is data, not a format: a denial carries the requester's own
	// annotation text, and a % in it must reach the event verbatim.
	r.EventRecorder.Eventf(pcr, nil, eventType, string(reason), eventAction, "%s", message)
	return writePersisted, nil
}

// updateStatusWithRetry writes the PodCertificateRequest status, retrying on a
// version conflict within this single reconcile, and reports what happened to
// the write. A 409 means another writer advanced the object between the read
// and the write; letting it propagate out of Reconcile would re-run the whole
// signing pipeline next pass, minting a fresh certificate and serial number
// for a status that was ultimately discarded. Instead re-read the live object,
// re-apply the outcome and try again, so the signer runs once regardless of a
// lost race on the write.
//
// If the re-read shows the Issued condition with this reconcile's own
// certificate chain, the 409 answered a client retry of a write that was
// already committed, and the result is writePersisted.
//
// If the re-read shows any other terminal condition, this reconcile lost the
// race: the request is now immutable, so its outcome is left in place
// (writeSuperseded) rather than overwritten.
//
// If the re-read finds no request, or a request with another UID, the request
// this reconcile computed the outcome for was deleted. Nothing is written, the
// result is writeGone and pcr is left as it was: the outcome belongs to no
// live request, and a replacement with the same name is reconciled through its
// own create event. A 404 on the write itself means the same and is not
// requeued.
//
// The error is non-nil only for writeRejected, a definite refusal of the
// write, and writeUnknown, where the write may have been committed: a timeout,
// a cancelled context, a 5xx, a 429, a failed re-read, or conflicts that
// outlast the retries.
func (r *PodCertificateRequestReconciler) updateStatusWithRetry(ctx context.Context, pcr *certificatesv1.PodCertificateRequest) (writeResult, error) {
	desired := pcr.Status.DeepCopy()
	key := client.ObjectKeyFromObject(pcr)
	uid := pcr.UID

	// Each attempt sets result before it returns. It starts at writeUnknown
	// because the zero value is writePersisted, which would announce a write
	// on any path that forgot to set it.
	result := writeUnknown
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		result = writeUnknown
		err := r.Status().Update(ctx, pcr)
		if err == nil {
			result = writePersisted
			return nil
		}
		if !apierrors.IsConflict(err) {
			result = classifyWriteError(err)
			if result == writeGone {
				log.FromContext(ctx).Info("request was deleted before its status was written; discarding this reconcile's outcome",
					"uid", uid)
				return nil
			}
			return err
		}
		// Re-read live: the cache lags the write that caused the conflict.
		live := &certificatesv1.PodCertificateRequest{}
		if gerr := r.APIReader.Get(ctx, key, live); gerr != nil {
			if apierrors.IsNotFound(gerr) {
				log.FromContext(ctx).Info("request was deleted before its status was written; discarding this reconcile's outcome",
					"uid", uid)
				result = writeGone
				return nil
			}
			return gerr
		}
		if live.UID != uid {
			log.FromContext(ctx).Info("request was replaced before its status was written; discarding this reconcile's outcome",
				"uid", uid, "replacementUID", live.UID)
			result = writeGone
			return nil
		}
		live.DeepCopyInto(pcr)
		if isOwnIssued(&pcr.Status, desired) {
			result = writePersisted
			return nil
		}
		if isTerminal(pcr) {
			// A terminal outcome already won; leave it in place. Stop retrying
			// (return nil) so the caller announces nothing.
			log.FromContext(ctx).Info("another writer recorded a terminal outcome first; discarding this reconcile's outcome",
				"winningCondition", terminalConditionType(&pcr.Status))
			result = writeSuperseded
			return nil
		}
		// Not terminal, so nothing on the fresh object needs preserving: a
		// non-terminal request carries no conditions and no certificate block.
		// Re-apply this reconcile's intended status (onto the fresh
		// resourceVersion) and retry.
		desired.DeepCopyInto(&pcr.Status)
		return err
	})
	return result, err
}

// classifyWriteError maps a status write error other than a conflict onto a
// writeResult. Only a 404 and the 4xx codes that refuse a request outright are
// definite: every other error, a timeout or a 5xx among them, can arrive
// after the API server committed the write.
func classifyWriteError(err error) writeResult {
	switch {
	case apierrors.IsNotFound(err):
		return writeGone
	case apierrors.IsInvalid(err), apierrors.IsForbidden(err), apierrors.IsBadRequest(err), apierrors.IsUnauthorized(err):
		return writeRejected
	default:
		return writeUnknown
	}
}

// isOwnIssued reports whether live carries the Issued condition with the
// certificate chain desired was going to write. A certificate chain is unique
// to one signing, so a match means this reconcile's own write is in place.
func isOwnIssued(live, desired *certificatesv1.PodCertificateRequestStatus) bool {
	return terminalConditionType(desired) == certificatesv1.PodCertificateRequestConditionTypeIssued &&
		terminalConditionType(live) == certificatesv1.PodCertificateRequestConditionTypeIssued &&
		live.CertificateChain == desired.CertificateChain
}

// clearCertificate empties the certificate block of the request status, which
// kube-apiserver requires when a request is denied or failed.
func clearCertificate(pcr *certificatesv1.PodCertificateRequest) {
	pcr.Status.CertificateChain = ""
	pcr.Status.NotBefore = nil
	pcr.Status.NotAfter = nil
	pcr.Status.BeginRefreshAt = nil
}
