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

package controller

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/go-logr/logr"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/api"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	podcertificate "github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"

	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Reason identifies an outcome reported for a PodCertificateRequest: a
// terminal/issued condition recorded on the object, or an event-only outcome
// where noted below.
type Reason string

const (
	ReasonAssociatedPodNotFound Reason = "AssociatedPodNotFound"
	ReasonSigningFailed         Reason = "SigningFailed"
	ReasonCertificateIssued     Reason = "CertificateIssued"

	// ReasonAssociatedPodGone is event-only and is never written as a
	// condition: a request whose pod a live read confirms is gone (absent, or
	// replaced by a different pod) is dropped, not failed. The event note says
	// which of the two it was.
	ReasonAssociatedPodGone Reason = "AssociatedPodGone"

	// ReasonDefaultSANSkipped is event-only: the certificate still issues, but a
	// default that could not be applied (e.g. the pod DNS SANs for an over-long
	// pod name) is surfaced as a Warning event so the operator can see why.
	ReasonDefaultSANSkipped Reason = "DefaultSANSkipped"

	// Well-known condition reasons defined by the certificates v1beta1 API.
	ReasonUnsupportedKeyType     Reason = Reason(capiv1beta1.PodCertificateRequestConditionUnsupportedKeyType)
	ReasonInvalidUserAnnotations Reason = Reason(capiv1beta1.PodCertificateRequestConditionInvalidUserConfig)
)

// TerminalError marks a failure that can never succeed on retry. The reconciler
// records the carried condition (Denied or Failed, with Reason and the error
// text as message) on the PodCertificateRequest and stops. Any error that is
// NOT a *TerminalError is treated as transient and returned to
// controller-runtime so it requeues with backoff.
//
// Construct it with [denied] or [failed], which pick the condition type.
type TerminalError struct {
	Reason        Reason
	ConditionType string // capiv1beta1.PodCertificateRequestConditionType{Denied,Failed}
	Err           error
}

func (e *TerminalError) Error() string { return e.Err.Error() }
func (e *TerminalError) Unwrap() error { return e.Err }

// denied wraps err as a terminal "Denied" outcome: the signer refuses the
// request (e.g. unsupported key type, invalid user configuration).
func denied(reason Reason, err error) error {
	return &TerminalError{Reason: reason, ConditionType: capiv1beta1.PodCertificateRequestConditionTypeDenied, Err: err}
}

// failed wraps err as a terminal "Failed" outcome: the signer could not issue
// the certificate. The only remaining Failed reason is SigningFailed (a missing
// pod is now dropped, not failed), so the reason is fixed rather than a
// parameter; unlike denied, whose reason varies.
func failed(err error) error {
	return &TerminalError{Reason: ReasonSigningFailed, ConditionType: capiv1beta1.PodCertificateRequestConditionTypeFailed, Err: err}
}

// podSigner is the consumer-side view of the signing dependency the reconciler
// needs. Keeping it an interface (rather than the concrete *signer.Signer) lets
// the reconcile path be unit-tested with a stub.
type podSigner interface {
	SignPodCertificate(*podcertificate.PodCertificateConfig) (*podcertificate.PodCertificate, error)
	IsSignerNameMatching(string) bool
	Name() string
}

// Compile-time assertion that the production signer satisfies the seam.
var _ podSigner = (*signer.Signer)(nil)

// PodCertificateRequestReconciler reconciles a PodCertificateRequest object
type PodCertificateRequestReconciler struct {
	client.Client
	// APIReader reads directly from the API server, bypassing the manager
	// cache. It is used to re-read the associated pod when the cached read
	// misses or returns a stale (UID-mismatched) object, so the request is
	// verified against live pod identity before signing.
	APIReader     client.Reader
	Log           logr.Logger
	Scheme        *runtime.Scheme
	Signer        podSigner
	ClusterFqdn   string
	EventRecorder events.EventRecorder
	// EnableAnnotationInterpolation allows ${...} placeholders in the
	// certificate configuration annotations (feature flag, off by default).
	EnableAnnotationInterpolation bool
	// HonorCSRSANs uses DNS/IP SANs embedded in the kubelet-generated CSR
	// (feature flag, off by default; kubelet generates empty CSRs today). CSR
	// SANs remain subject to the identity constraints unless
	// AllowUnverifiedIdentities is set.
	HonorCSRSANs bool
	// AllowUnverifiedIdentities lifts the requirement that annotation-provided
	// certificate identities derive from the verified request fields (feature
	// flag, off by default; keeping it off is the safe, recommended posture).
	AllowUnverifiedIdentities bool
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=clustertrustbundles,verbs=get;create;update;patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=sign;attest
// +kubebuilder:rbac:groups=core;events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get

func (r *PodCertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// MaxConcurrentReconciles is inherited from the manager-wide controller
	// configuration (see the -max-concurrent-reconciles flag).
	return ctrl.NewControllerManagedBy(mgr).
		For(&capiv1beta1.PodCertificateRequest{}).
		WithEventFilter(predicate.Funcs{
			// Skip create events for requests which are already in a terminal state.
			CreateFunc: func(e event.CreateEvent) bool {
				pcr, ok := e.Object.(*capiv1beta1.PodCertificateRequest)
				if !ok {
					return false
				}

				isPcrImmutable := api.IsPodCertificateRequestImmutable(pcr)
				r.Log.V(1).Info("Check if PodCertificateRequest is immutable", "immutable", isPcrImmutable, "event", "create", "request-name", pcr.Name)
				return !isPcrImmutable // True for processing request ; False for skipping request
			},
		}).
		Complete(r)
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pcr capiv1beta1.PodCertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &pcr); err != nil {
		// Gone -> drop; any real error -> requeue.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Use a request-scoped logger: reconciles run concurrently, so the shared
	// reconciler state must not be mutated here.
	log := r.Log.WithValues("name", req.Name, "namespace", req.Namespace, "podName", pcr.Spec.PodName, "podNamespace", pcr.Namespace)
	ctx = logr.NewContext(ctx, log)

	if !pcr.DeletionTimestamp.IsZero() {
		log.Info("PodCertificateRequest has been deleted.")
		return ctrl.Result{}, nil
	}
	if !r.Signer.IsSignerNameMatching(pcr.Spec.SignerName) {
		log.Info("PodCertificateRequest signer name does not match controller signer name", "signerName", pcr.Spec.SignerName, "controllerSignerName", r.Signer.Name())
		return ctrl.Result{}, nil
	}
	if api.IsPodCertificateRequestImmutable(&pcr) {
		log.Info("PodCertificateRequest is immutable")
		return ctrl.Result{}, nil
	}

	log.Info("Lookup pod associated with PodCertificateRequest")
	cert, err := r.process(ctx, &pcr)
	if err != nil {
		return r.recordFailure(ctx, &pcr, err)
	}
	if cert == nil {
		// Nothing to sign: the pod is being deleted, or the request is stale
		// (pod absent or UID-mismatched on the live read). Drop without requeue.
		return ctrl.Result{}, nil
	}

	log.Info("Successfully signed the certificate")
	if err := r.recordIssued(ctx, &pcr, cert); err != nil {
		log.Error(err, "failed to record issued certificate; requeueing")
		return ctrl.Result{}, err
	}
	log.Info("Successfully issued certificate")
	return ctrl.Result{}, nil
}

// process runs the signing pipeline for a PodCertificateRequest. It returns:
//   - (cert, nil)  on success
//   - (nil, nil)   when there is nothing to do: the associated pod is being
//     deleted, or a live read confirms it is gone (absent, or carrying a
//     different UID than the request asked for). A confirmed-gone drop emits a
//     warning event and writes no status; a pod being deleted is silent.
//   - (nil, *TerminalError) for permanent failures (recorded on the PCR, no retry)
//   - (nil, err)   for transient failures (requeued with backoff)
func (r *PodCertificateRequestReconciler) process(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest) (*podcertificate.PodCertificate, error) {
	log := logf.FromContext(ctx)

	// Read the pod from the manager cache first. The cache can be stale in two
	// ways that matter here: it may miss a just-created pod (racing the
	// request), or it may still hold a previous pod that shared this name. In
	// both cases re-read directly from the API server and gate on the pod's
	// live UID, so a certificate is never issued against the wrong pod.
	crPod, err := api.GetPod(ctx, r.Client, pcr.Spec.PodName, pcr.Namespace)
	switch {
	case apierrors.IsNotFound(err):
		// Cache miss; fall through to the live read below.
	case err != nil:
		return nil, err // transient
	}

	if crPod == nil || crPod.UID != pcr.Spec.PodUID {
		crPod, err = api.GetPod(ctx, r.APIReader, pcr.Spec.PodName, pcr.Namespace)
		switch {
		case apierrors.IsNotFound(err):
			// The pod is gone on a live read too: the request is stale, not a
			// terminal failure to sign. Drop it.
			log.Info("associated pod not found on a live read; dropping stale request")
			r.recordPodGone(pcr, "associated pod %s/%s (uid %s) not found; dropping request",
				pcr.Namespace, pcr.Spec.PodName, pcr.Spec.PodUID)
			return nil, nil
		case err != nil:
			return nil, err // transient
		}
	}

	// Identity gate: only sign for the exact pod the request was created for.
	if crPod.UID != pcr.Spec.PodUID {
		log.Info("associated pod UID does not match the request; dropping stale request",
			"podUID", crPod.UID, "requestPodUID", pcr.Spec.PodUID)
		r.recordPodGone(pcr, "associated pod %s/%s was replaced (request uid %s, live uid %s); dropping request",
			pcr.Namespace, pcr.Spec.PodName, pcr.Spec.PodUID, crPod.UID)
		return nil, nil
	}

	if !crPod.DeletionTimestamp.IsZero() {
		log.Info("Pod has been deleted.")
		return nil, nil
	}

	configOpts := podcertificate.Options{
		ClusterFQDN:               r.ClusterFqdn,
		EnableInterpolation:       r.EnableAnnotationInterpolation,
		HonorCSRSANs:              r.HonorCSRSANs,
		AllowUnverifiedIdentities: r.AllowUnverifiedIdentities,
	}
	var publicKey crypto.PublicKey
	var publicKeyAlgorithm x509.PublicKeyAlgorithm
	if len(pcr.Spec.StubPKCS10Request) > 0 {
		csrInfo, cerr := signer.ParseCSR(pcr.Spec.StubPKCS10Request)
		if cerr != nil {
			return nil, denied(ReasonUnsupportedKeyType, cerr)
		}
		publicKey, publicKeyAlgorithm = csrInfo.PublicKey, csrInfo.PublicKeyAlgorithm
		configOpts.CSRDNSNames = csrInfo.DNSNames
		configOpts.CSRIPAddresses = csrInfo.IPAddresses
	} else {
		// PKIXPublicKey is deprecated in favour of StubPKCS10Request, but is
		// still sent by kubelets which pre-date the CSR stub.
		publicKey, publicKeyAlgorithm, err = signer.ParsePKIXPublicKey(pcr.Spec.PKIXPublicKey) //nolint:staticcheck
		if err != nil {
			return nil, denied(ReasonUnsupportedKeyType, err)
		}
	}
	pcConfig, err := podcertificate.NewPodCertificateConfig(pcr, crPod, configOpts, publicKey, publicKeyAlgorithm)
	if err != nil {
		return nil, denied(ReasonInvalidUserAnnotations, err)
	}
	// Non-fatal notices (e.g. default pod DNS SANs dropped for an over-long pod
	// name): the certificate still issues, but the operator must see why a
	// default was omitted, so surface each as a Warning event and a log line.
	for _, warning := range pcConfig.Warnings {
		log.Info(warning)
		r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(ReasonDefaultSANSkipped), "SignPodCertificateRequest", "%s", warning)
	}
	pcConfig.LogConfiguration(ctx)

	if err := pcConfig.Validate(); err != nil {
		return nil, denied(ReasonInvalidUserAnnotations, err)
	}

	cert, err := r.Signer.SignPodCertificate(pcConfig)
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

// recordFailure routes a process() error: terminal errors are recorded on the
// PCR and stop the reconcile; transient errors are returned so controller-runtime
// requeues with backoff. If recording a terminal outcome fails, that write error
// is returned so the reconcile requeues (the Failed condition is never silently lost).
func (r *PodCertificateRequestReconciler) recordFailure(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest, err error) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var te *TerminalError
	if !errors.As(err, &te) {
		log.Error(err, "transient error; requeueing")
		metrics.PodCertificateRequestRequeues.WithLabelValues(requeueReason(err)).Inc()
		return ctrl.Result{}, err
	}

	log.Error(te.Err, "terminal failure", "reason", te.Reason)
	if werr := r.recordTerminal(ctx, pcr, te); werr != nil {
		log.Error(werr, "failed to record terminal outcome; requeueing", "reason", te.Reason)
		return ctrl.Result{}, werr
	}
	return ctrl.Result{}, nil
}

// recordTerminal records a Denied/Failed condition carried by a *TerminalError.
// The certificate fields are cleared, since kube-apiserver requires them to be
// empty when denying or failing a PodCertificateRequest.
func (r *PodCertificateRequestReconciler) recordTerminal(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest, te *TerminalError) error {
	r.clearPodCertificateRequestStatusFields(pcr)
	return r.recordOutcome(ctx, pcr, te.ConditionType, te.Reason, te.Err.Error(), corev1.EventTypeWarning)
}

// recordPodGone emits the warning event for a request dropped because a live
// read confirmed its pod is gone. The note is supplied by the caller, since
// "absent" and "replaced by a different pod" are different facts for whoever
// reads the event. Deliberately no status write: the drop is not a terminal
// outcome, and the event is the only breadcrumb an operator gets.
func (r *PodCertificateRequestReconciler) recordPodGone(pcr *capiv1beta1.PodCertificateRequest, noteFmt string, args ...any) {
	// The event names the object and is the only breadcrumb its owner gets; the
	// metric carries the rate, which is what says the controller is losing a
	// race with pod churn rather than dropping the odd stale request.
	metrics.PodCertificateRequestDrops.WithLabelValues(metrics.ReasonAssociatedPodGone).Inc()
	r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(ReasonAssociatedPodGone), "SignPodCertificateRequest", noteFmt, args...)
}

// requeueReason classifies a transient error for the requeue counter. The
// classification is a closed set computed here: the error text itself is
// unbounded (it can carry std-lib and apiserver detail) and belongs in the log,
// never in a label.
func requeueReason(err error) string {
	if errors.Is(err, authority.ErrCASignerUnusable) {
		return metrics.ReasonCASignerUnusable
	}

	return metrics.ReasonTransient
}

// requestOutcome maps a condition type onto the outcome label. The three
// condition types the signer writes are the closed set the certificates API
// defines; anything else would be a condition this controller never records.
func requestOutcome(conditionType string) string {
	switch conditionType {
	case capiv1beta1.PodCertificateRequestConditionTypeIssued:
		return metrics.OutcomeIssued
	case capiv1beta1.PodCertificateRequestConditionTypeDenied:
		return metrics.OutcomeDenied
	default:
		return metrics.OutcomeFailed
	}
}

func (r *PodCertificateRequestReconciler) recordIssued(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest, cert *podcertificate.PodCertificate) error {
	r.setCertificateOnPodCertificateRequest(ctx, pcr, cert)
	const message = "Certificate successfully issued"
	return r.recordOutcome(ctx, pcr, capiv1beta1.PodCertificateRequestConditionTypeIssued, ReasonCertificateIssued, message, corev1.EventTypeNormal)
}

func (r *PodCertificateRequestReconciler) setCertificateOnPodCertificateRequest(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest, podCertificate *podcertificate.PodCertificate) {
	beginRefreshAt := podCertificate.NotAfter().Add(-podCertificate.Config().RefreshBefore)

	logf.FromContext(ctx).V(1).Info("Setting the certificate in the PodCertificateRequest",
		"podName", pcr.Spec.PodName,
		"commonName", podCertificate.Config().CommonName,
		"dnsNames", podCertificate.Config().DNSNames,
		"uris", podCertificate.Config().URIs,
		"duration", podCertificate.Config().Duration.String(),
		"refreshBefore", podCertificate.Config().RefreshBefore.String(),
		"beginRefreshAt", beginRefreshAt.Format(time.RFC1123Z))

	pcr.Status.CertificateChain = podCertificate.CertificateChain()
	pcr.Status.NotBefore = &metav1.Time{Time: podCertificate.NotBefore()}
	pcr.Status.NotAfter = &metav1.Time{Time: podCertificate.NotAfter()}
	pcr.Status.BeginRefreshAt = &metav1.Time{Time: beginRefreshAt}
}

// ------------------------------------------------ GENERIC FUNCTIONS  ------------------------------------------------

// recordOutcome sets the condition on the PodCertificateRequest, persists the
// status and only then emits the corresponding event. The order matters: the
// event announces an outcome, so it must not be emitted until the write that
// makes the outcome real has succeeded. Emitting first would advertise a result
// that a failed or conflicting write never persisted, and re-advertise it on
// every requeue.
func (r *PodCertificateRequestReconciler) recordOutcome(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest, conditionType string, reason Reason, message, eventType string) error {
	r.setPodCertificateRequestStatusCondition(pcr, conditionType, string(reason), message)

	persisted, err := r.updateStatusWithRetry(ctx, pcr)
	if err != nil {
		return err
	}
	if !persisted {
		// Another writer recorded a terminal outcome first and won the race;
		// this reconcile's outcome was discarded, so there is nothing to
		// announce. updateStatusWithRetry has already logged the loss.
		return nil
	}

	// Counted here for the same reason the event is emitted here: the outcome
	// is not real until the write that carries it has persisted. Counting
	// before would inflate the issued rate with certificates no request ever
	// received.
	metrics.PodCertificateRequests.WithLabelValues(requestOutcome(conditionType), string(reason)).Inc()
	r.EventRecorder.Eventf(pcr, nil, eventType, string(reason), "SignPodCertificateRequest", message)
	return nil
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
func (r *PodCertificateRequestReconciler) updateStatusWithRetry(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest) (bool, error) {
	desired := pcr.Status.DeepCopy()
	key := client.ObjectKeyFromObject(pcr)

	// PodCertificateRequests are served from the manager cache, which lags the
	// write that caused the conflict; re-read through the API reader so the
	// retry carries the current resourceVersion, not the stale cached one.
	reader := r.statusRetryReader()

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
		if api.IsPodCertificateRequestImmutable(pcr) {
			// A terminal outcome already won; leave it in place. Stop retrying
			// (return nil) with persisted still false so the caller announces
			// nothing.
			logf.FromContext(ctx).Info("another writer recorded a terminal outcome first; discarding this reconcile's outcome",
				"winningCondition", api.GetPodCertificateRequestConditionType(&pcr.Status))
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

// statusRetryReader returns the reader used to re-read a PodCertificateRequest
// before retrying a conflicted status write: the cache-bypassing APIReader in
// production, falling back to the cached client when none is wired (unit tests).
func (r *PodCertificateRequestReconciler) statusRetryReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

func (r *PodCertificateRequestReconciler) setPodCertificateRequestStatusCondition(pcr *capiv1beta1.PodCertificateRequest, conditionType, reason, message string) {
	pcr.Status.Conditions = []metav1.Condition{
		{
			Type:               conditionType,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             reason,
			Message:            message,
		},
	}
}

func (r *PodCertificateRequestReconciler) clearPodCertificateRequestStatusFields(pcr *capiv1beta1.PodCertificateRequest) {
	pcr.Status.CertificateChain = ""
	pcr.Status.NotBefore = nil
	pcr.Status.NotAfter = nil
	pcr.Status.BeginRefreshAt = nil
}
