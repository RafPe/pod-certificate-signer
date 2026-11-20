// ADR-0007: the issuance audit record.

package controller

import (
	"context"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/audit"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
)

// auditOn reports whether the reconciler writes audit records. Both fields
// are checked, not one: tests build the struct by hand, and half a pair must
// stay silent rather than panic.
func (r *PodCertificateRequestReconciler) auditOn() bool {
	return r.Audit != nil && r.AuditRecords != nil
}

// auditSigned writes the signed record for cert and returns it, or nil when
// audit is off. It runs before the status write, so every certificate the API
// server can accept already has its full record. The record is built from
// pcr as read for this reconcile; the follow-up must come from the returned
// record, because a conflict re-read can replace pcr.
//
// Every record is written under context.WithoutCancel: a shutdown that
// cancelled the reconcile must not lose the record of a certificate that may
// still be published. The sink bounds the wait with its own write timeout.
func (r *PodCertificateRequestReconciler) auditSigned(ctx context.Context, pcr *certificatesv1.PodCertificateRequest,
	pod *corev1.Pod, cert *podcertificate.Certificate) *audit.Record {
	if !r.auditOn() {
		return nil
	}
	supplied := podcertificate.SuppliedAnnotations(pcr, pod, r.CertificateOptions.AllowPodAnnotations)
	rec := r.AuditRecords.Signed(pcr, pod, cert, supplied)
	r.Audit.Record(context.WithoutCancel(ctx), rec)
	return &rec
}

// auditFollowUp writes what happened to the Issued status write of the
// certificate in signed. signed is nil when audit is off.
func (r *PodCertificateRequestReconciler) auditFollowUp(ctx context.Context, signed *audit.Record, result writeResult) {
	if signed == nil || !r.auditOn() {
		return
	}
	event, reason := followUpFor(result)
	r.Audit.Record(context.WithoutCancel(ctx), r.AuditRecords.FollowUp(event, reason, *signed))
}

// followUpFor maps the result of an Issued status write onto the event and
// reason of its follow-up record.
func followUpFor(result writeResult) (audit.Event, string) {
	switch result {
	case writePersisted:
		return audit.EventPublished, audit.ReasonStatusWritten
	case writeSuperseded:
		return audit.EventSuperseded, audit.ReasonOtherWriterWon
	case writeGone:
		return audit.EventSuperseded, audit.ReasonRequestGone
	case writeRejected:
		return audit.EventSuperseded, audit.ReasonWriteRejected
	default:
		return audit.EventUnknown, audit.ReasonWriteAmbiguous
	}
}

// auditTerminal writes the denied or failed record for te. The caller calls
// it only after the terminal status write persisted: a reconcile that lost
// the race, or does not know whether its write committed, has no outcome to
// record. pod is the live pod, or nil when signRequest did not read one.
func (r *PodCertificateRequestReconciler) auditTerminal(ctx context.Context, pcr *certificatesv1.PodCertificateRequest,
	pod *corev1.Pod, te *terminalError) {
	if !r.auditOn() {
		return
	}
	event := audit.EventFailed
	if te.kind == outcome.Denied {
		event = audit.EventDenied
	}
	supplied := podcertificate.SuppliedAnnotations(pcr, pod, r.CertificateOptions.AllowPodAnnotations)
	rec := r.AuditRecords.Terminal(event, string(te.reason), te.err.Error(), pcr, pod, supplied)
	r.Audit.Record(context.WithoutCancel(ctx), rec)
}
