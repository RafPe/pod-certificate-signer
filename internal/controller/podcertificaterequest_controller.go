/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package controller reconciles PodCertificateRequests addressed to this
// signer: it verifies the request against the live pod, resolves the
// certificate configuration, signs, and records the Issued, Denied or Failed
// outcome on the request status together with the matching event.
package controller

import (
	"context"
	"errors"
	"time"

	"github.com/go-logr/logr"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"

	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// ReasonDefaultSANSkipped is the one event-only reason this package owns: the
// certificate still issues, but a default that could not be applied (e.g. the
// pod DNS SANs for an over-long pod name) is surfaced as a Warning event so the
// operator can see why. Every other reason is written onto the object or
// counted, so it lives in the metrics package with the rest of the vocabulary.
const ReasonDefaultSANSkipped metrics.Reason = "DefaultSANSkipped"

// eventAction is the action every event this controller emits is attributed
// to; it names the operation, where the reason names the outcome.
const eventAction = "SignPodCertificateRequest"

// TerminalError marks a failure that can never succeed on retry. The reconciler
// records the carried condition (Denied or Failed, with Reason and the error
// text as message) on the PodCertificateRequest and stops. Any error that is
// NOT a *TerminalError is treated as transient and returned to
// controller-runtime so it requeues with backoff.
//
// Construct it with [denied] or [failed], which pick the condition type.
type TerminalError struct {
	Reason        metrics.Reason
	ConditionType string // certificatesv1.PodCertificateRequestConditionType{Denied,Failed}
	Err           error
}

func (e *TerminalError) Error() string { return e.Err.Error() }
func (e *TerminalError) Unwrap() error { return e.Err }

// denied wraps err as a terminal "Denied" outcome: the signer refuses the
// request (e.g. unsupported key type, invalid user configuration).
func denied(reason metrics.Reason, err error) error {
	return &TerminalError{Reason: reason, ConditionType: certificatesv1.PodCertificateRequestConditionTypeDenied, Err: err}
}

// failed wraps err as a terminal "Failed" outcome: the signer could not issue
// the certificate. The only Failed reason is SigningFailed (a missing pod is
// dropped, not failed), so the reason is fixed rather than a parameter; unlike
// denied, whose reason varies.
func failed(err error) error {
	return &TerminalError{Reason: metrics.ReasonSigningFailed, ConditionType: certificatesv1.PodCertificateRequestConditionTypeFailed, Err: err}
}

// podSigner is the consumer-side view of the signing dependency the reconciler
// needs. Keeping it an interface (rather than the concrete certificate
// authority) lets the reconcile path be unit-tested with a stub.
type podSigner interface {
	Sign(*podcertificate.PodCertificateConfig) (*podcertificate.PodCertificate, error)
}

// Compile-time assertion that the production CA satisfies the seam.
var _ podSigner = (*authority.CertificateAuthority)(nil)

// PodCertificateRequestReconciler reconciles a PodCertificateRequest object.
//
// Client, APIReader, Signer, SignerName and EventRecorder are required;
// NewPodCertificateRequestReconciler fills the manager-derived ones. Tests
// build the struct directly with fakes.
//
// RBAC is not derived from this type: the ClusterRole and Role the controller
// runs with are hand-maintained in charts/pod-certificate-signer/templates and
// are the single source of truth for what it may do.
type PodCertificateRequestReconciler struct {
	client.Client
	// APIReader reads directly from the API server. The associated pod is
	// always read through it, never through the manager cache: the cache can
	// miss a just-created pod or still hold a previous pod of the same name,
	// and a certificate must never be issued against the wrong pod. (main.go
	// also excludes Pods from the cache, so a cached read would fall through
	// to the API server anyway; reading through APIReader states the intent
	// here, where it is relied upon.)
	APIReader client.Reader
	Log       logr.Logger
	// Signer issues the certificate once the request has been verified and its
	// configuration resolved.
	Signer podSigner
	// SignerName is the spec.signerName this controller answers for; requests
	// addressed to any other signer are left alone.
	SignerName    string
	EventRecorder events.EventRecorder
	// CertificateOptions is the process-wide policy the certificate
	// configuration is built under: the cluster FQDN and the feature flags.
	CertificateOptions podcertificate.Options

	// caUnusableEvents rate-limits the CASignerUnusable warning per request, so
	// a requeue loop reports the condition rather than flooding the event
	// stream with it. The zero value is ready to use; it carries a mutex, so
	// the reconciler must always be used through a pointer.
	caUnusableEvents eventThrottle
}

// NewPodCertificateRequestReconciler wires a reconciler to mgr: the cached
// client, the cache-bypassing API reader, a named logger and event recorder.
// name is the controller name used for the logger and as the event reporter;
// signerName is the spec.signerName the controller answers for.
func NewPodCertificateRequestReconciler(
	mgr ctrl.Manager,
	name, signerName string,
	ca *authority.CertificateAuthority,
	certOpts podcertificate.Options,
) (*PodCertificateRequestReconciler, error) {
	if signerName == "" {
		return nil, errors.New("a signer name is required")
	}
	if ca == nil {
		return nil, errors.New("a certificate authority is required")
	}
	return &PodCertificateRequestReconciler{
		Client:             mgr.GetClient(),
		APIReader:          mgr.GetAPIReader(),
		Log:                ctrl.Log.WithName(name),
		Signer:             ca,
		SignerName:         signerName,
		EventRecorder:      mgr.GetEventRecorder(name),
		CertificateOptions: certOpts,
	}, nil
}

// SetupWithManager registers the reconciler with mgr, watching
// PodCertificateRequests and skipping those that are already terminal.
func (r *PodCertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// MaxConcurrentReconciles is inherited from the manager-wide controller
	// configuration (see the -max-concurrent-reconciles flag).
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1.PodCertificateRequest{}).
		WithEventFilter(predicate.Funcs{
			// Skip create events for requests which are already in a terminal state.
			CreateFunc: func(e event.CreateEvent) bool {
				pcr, ok := e.Object.(*certificatesv1.PodCertificateRequest)
				if !ok {
					return false
				}

				terminal := isTerminal(pcr)
				r.Log.V(1).Info("Check if PodCertificateRequest is terminal", "terminal", terminal, "event", "create", "request-name", pcr.Name)
				return !terminal
			},
		}).
		Complete(r)
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pcr certificatesv1.PodCertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &pcr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil // gone: nothing to do
		}
		return r.requeue(ctx, &pcr, err)
	}

	// Use a request-scoped logger: reconciles run concurrently, so the shared
	// reconciler state must not be mutated here.
	logger := r.Log.WithValues("name", req.Name, "namespace", req.Namespace, "podName", pcr.Spec.PodName, "podNamespace", pcr.Namespace)
	ctx = logr.NewContext(ctx, logger)

	if !pcr.DeletionTimestamp.IsZero() {
		logger.Info("PodCertificateRequest has been deleted.")
		return ctrl.Result{}, nil
	}
	if pcr.Spec.SignerName != r.SignerName {
		logger.Info("PodCertificateRequest signer name does not match controller signer name", "signerName", pcr.Spec.SignerName, "controllerSignerName", r.SignerName)
		return ctrl.Result{}, nil
	}
	if isTerminal(&pcr) {
		logger.Info("PodCertificateRequest is immutable")
		return ctrl.Result{}, nil
	}

	cert, err := r.signRequest(ctx, &pcr)
	if err != nil {
		return r.requeueOrRecordTerminal(ctx, &pcr, err)
	}
	if cert == nil {
		// Nothing to sign: the pod is being deleted, or the request is stale
		// (pod absent or UID-mismatched on the live read). Drop without requeue.
		return ctrl.Result{}, nil
	}

	persisted, err := r.recordIssued(ctx, &pcr, cert)
	if err != nil {
		logger.Error(err, "failed to record issued certificate; requeueing")
		return r.requeue(ctx, &pcr, err)
	}
	if persisted {
		logger.Info("issued certificate",
			"commonName", cert.Config.CommonName,
			"dnsNames", cert.Config.DNSNames,
			"uris", cert.Config.URIs,
			"extKeyUsage", cert.Config.ExtKeyUsage,
			"notAfter", cert.NotAfter.Format(time.RFC3339),
			"beginRefreshAt", beginRefreshAt(cert).Format(time.RFC3339))
	}
	return ctrl.Result{}, nil
}

// signRequest runs the signing pipeline for a PodCertificateRequest. It returns:
//   - (cert, nil)  on success
//   - (nil, nil)   when there is nothing to do: the associated pod is being
//     deleted, or a live read confirms it is gone (absent, or carrying a
//     different UID than the request asked for). A confirmed-gone drop emits a
//     warning event and writes no status; a pod being deleted is silent.
//   - (nil, *TerminalError) for permanent failures (recorded on the PCR, no retry)
//   - (nil, err)   for transient failures (requeued with backoff)
func (r *PodCertificateRequestReconciler) signRequest(ctx context.Context, pcr *certificatesv1.PodCertificateRequest) (*podcertificate.PodCertificate, error) {
	logger := log.FromContext(ctx)

	// Read the pod live, never from the manager cache: the cache can miss a
	// just-created pod (racing the request) or still hold a previous pod that
	// shared this name, and a certificate must never be issued against the
	// wrong pod. The live UID is then gated against the one the request names.
	pod, err := getPod(ctx, r.APIReader, pcr.Spec.PodName, pcr.Namespace)
	if apierrors.IsNotFound(err) {
		// The pod is gone: the request is stale, not a terminal failure to
		// sign. Drop it.
		logger.Info("associated pod not found on a live read; dropping stale request")
		r.warnPodGone(pcr, "associated pod %s/%s (uid %s) not found; dropping request",
			pcr.Namespace, pcr.Spec.PodName, pcr.Spec.PodUID)
		return nil, nil
	}
	if err != nil {
		return nil, err // transient
	}

	// Identity gate: only sign for the exact pod the request was created for.
	if pod.UID != pcr.Spec.PodUID {
		logger.Info("associated pod UID does not match the request; dropping stale request",
			"podUID", pod.UID, "requestPodUID", pcr.Spec.PodUID)
		r.warnPodGone(pcr, "associated pod %s/%s was replaced (request uid %s, live uid %s); dropping request",
			pcr.Namespace, pcr.Spec.PodName, pcr.Spec.PodUID, pod.UID)
		return nil, nil
	}

	if !pod.DeletionTimestamp.IsZero() {
		logger.Info("Pod has been deleted.")
		return nil, nil
	}

	// certificates.k8s.io/v1 dropped spec.pkixPublicKey: every kubelet that
	// speaks the GA API sends the PKCS#10 stub, so it is the only source of
	// the subject public key.
	csr, err := podcertificate.ParseCSR(pcr.Spec.StubPKCS10Request)
	if err != nil {
		return nil, denied(metrics.ReasonUnsupportedKeyType, err)
	}

	pcConfig, err := podcertificate.NewPodCertificateConfig(ctx, pcr, pod, csr, r.CertificateOptions)
	if err != nil {
		return nil, denied(metrics.ReasonInvalidUserConfig, err)
	}
	// Non-fatal notices (e.g. default pod DNS SANs dropped for an over-long pod
	// name): the certificate still issues, but the operator must see why a
	// default was omitted, so surface each as a Warning event and a log line.
	for _, warning := range pcConfig.Warnings {
		logger.Info(warning)
		r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(ReasonDefaultSANSkipped), eventAction, "%s", warning)
	}

	if err := pcConfig.Validate(); err != nil {
		return nil, denied(metrics.ReasonInvalidUserConfig, err)
	}

	cert, err := r.Signer.Sign(pcConfig)
	if err != nil {
		// CA-availability failures are transient: a CA rotation can let an
		// identical request succeed, so requeue rather than record a terminal
		// Failed outcome the request could never recover from.
		if errors.Is(err, authority.ErrCASignerUnusable) {
			return nil, err
		}
		return nil, failed(err)
	}
	return cert, nil
}
