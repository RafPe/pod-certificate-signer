// Package outcome is the vocabulary for what happened to a
// PodCertificateRequest: the reasons the controller writes onto a request or
// attaches to its events, and the outcome kinds the metrics count them under.
//
// It is a package of its own so that the controller, which writes the values,
// and the metrics, which count them, share one definition without either
// owning the other's concern: the controller cannot be imported by the metrics
// (that would be a cycle), and telemetry should not own the controller's API
// vocabulary. A value read off a graph therefore greps identically against
// `kubectl get podcertificaterequest -o yaml` and the controller's events.
package outcome

import certificatesv1 "k8s.io/api/certificates/v1"

// ConditionReason is the reason written onto a request's terminal condition.
// Only these values ever reach the status: the type is what stops an
// event-only reason from being recorded as a condition.
type ConditionReason string

// The terminal condition reasons. The two denials are the certificates API's
// own constants, spelled exactly as the API defines them.
const (
	CertificateIssued  ConditionReason = "CertificateIssued"
	UnsupportedKeyType ConditionReason = ConditionReason(certificatesv1.PodCertificateRequestConditionUnsupportedKeyType)
	InvalidUserConfig  ConditionReason = ConditionReason(certificatesv1.PodCertificateRequestConditionInvalidUserConfig)
	SigningFailed      ConditionReason = "SigningFailed"
)

// NonTerminalReason names something that happened to a request without ending
// it: a requeue, a drop, or a notice attached to an issuance. It labels events
// and the requeue and drop counters (Transient labels only the counter), and
// is never written onto the status - a condition makes a request immutable,
// so writing one for a non-terminal reason would freeze a request that could
// still succeed.
type NonTerminalReason string

const (
	// CASignerUnusable: the CA cannot sign this request right now (it has
	// expired, or its remaining validity is shorter than the requested
	// lifetime). A CA rotation can make the same request succeed, so it is
	// requeued; see authority.ErrCASignerUnusable.
	CASignerUnusable NonTerminalReason = "CASignerUnusable"
	// Transient: every other requeue - an API read failure, a conflicted
	// write. The controller's own retry loop is doing its job.
	Transient NonTerminalReason = "Transient"
	// AssociatedPodGone: a live read confirmed the request's pod is gone
	// (absent, or replaced by a different pod), so the request is dropped.
	AssociatedPodGone NonTerminalReason = "AssociatedPodGone"
	// DefaultSANSkipped: the certificate issued, but a default that could not
	// be applied (e.g. the pod DNS SANs for an over-long pod name) is surfaced
	// so the operator can see why.
	DefaultSANSkipped NonTerminalReason = "DefaultSANSkipped"
)

// Kind is what happened to a request that reached a terminal condition. It
// names the outcome rather than the condition type that carried it, so it
// stays aggregatable if the API ever grows a fourth condition.
type Kind string

const (
	Issued Kind = "issued"
	Denied Kind = "denied"
	Failed Kind = "failed"
)
