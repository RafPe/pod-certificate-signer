package controller

import (
	"context"
	"errors"
	"time"

	"github.com/go-logr/logr"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/signer"

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

// Reason identifies an outcome reported for a PodCertificateRequest. The
// vocabulary is declared once, in the metrics package, so the reason written
// onto the object and the label that counts it cannot drift apart.
type Reason = metrics.Reason

const (
	ReasonSigningFailed      = metrics.ReasonSigningFailed
	ReasonCertificateIssued  = metrics.ReasonCertificateIssued
	ReasonAssociatedPodGone  = metrics.ReasonAssociatedPodGone
	ReasonCASignerUnusable   = metrics.ReasonCASignerUnusable
	ReasonUnsupportedKeyType = metrics.ReasonUnsupportedKeyType
	ReasonInvalidUserConfig  = metrics.ReasonInvalidUserConfig

	// ReasonDefaultSANSkipped is event-only: the certificate still issues, but a
	// default that could not be applied (e.g. the pod DNS SANs for an over-long
	// pod name) is surfaced as a Warning event so the operator can see why. It
	// is neither a condition nor a metric label, so it lives here.
	ReasonDefaultSANSkipped Reason = "DefaultSANSkipped"
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
	ConditionType string // certificatesv1.PodCertificateRequestConditionType{Denied,Failed}
	Err           error
}

func (e *TerminalError) Error() string { return e.Err.Error() }
func (e *TerminalError) Unwrap() error { return e.Err }

// denied wraps err as a terminal "Denied" outcome: the signer refuses the
// request (e.g. unsupported key type, invalid user configuration).
func denied(reason Reason, err error) error {
	return &TerminalError{Reason: reason, ConditionType: certificatesv1.PodCertificateRequestConditionTypeDenied, Err: err}
}

// failed wraps err as a terminal "Failed" outcome: the signer could not issue
// the certificate. The only Failed reason is SigningFailed (a missing pod is
// dropped, not failed), so the reason is fixed rather than a parameter; unlike
// denied, whose reason varies.
func failed(err error) error {
	return &TerminalError{Reason: ReasonSigningFailed, ConditionType: certificatesv1.PodCertificateRequestConditionTypeFailed, Err: err}
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

// PodCertificateRequestReconciler reconciles a PodCertificateRequest object.
//
// RBAC is not derived from this type: the ClusterRole and Role the controller
// runs with are hand-maintained in charts/pod-certificate-signer/templates and
// are the single source of truth for what it may do.
type PodCertificateRequestReconciler struct {
	client.Client
	// APIReader reads directly from the API server, bypassing the manager
	// cache. It is used to re-read the associated pod when the cached read
	// misses or returns a stale (UID-mismatched) object, so the request is
	// verified against live pod identity before signing.
	APIReader     client.Reader
	Log           logr.Logger
	Signer        podSigner
	EventRecorder events.EventRecorder
	// Certificate is the process-wide policy the certificate configuration is
	// built under: the cluster FQDN and the three feature flags.
	Certificate podcertificate.Options

	// caUnusableEvents rate-limits the CASignerUnusable warning per request, so
	// a requeue loop reports the condition rather than flooding the event
	// stream with it. The zero value is ready to use; it carries a mutex, so
	// the reconciler must always be used through a pointer.
	caUnusableEvents eventThrottle
}

// NewPodCertificateRequestReconciler wires a reconciler to mgr: the cached
// client, the cache-bypassing API reader, a named logger and event recorder.
// name is the controller name used for the logger and as the event reporter.
func NewPodCertificateRequestReconciler(mgr ctrl.Manager, name string, s *signer.Signer, certificate podcertificate.Options) (*PodCertificateRequestReconciler, error) {
	if s == nil {
		return nil, errors.New("a signer is required")
	}
	return &PodCertificateRequestReconciler{
		Client:        mgr.GetClient(),
		APIReader:     mgr.GetAPIReader(),
		Log:           ctrl.Log.WithName(name),
		Signer:        s,
		EventRecorder: mgr.GetEventRecorder(name),
		Certificate:   certificate,
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
		// Gone -> drop; any real error -> requeue.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Use a request-scoped logger: reconciles run concurrently, so the shared
	// reconciler state must not be mutated here.
	logger := r.Log.WithValues("name", req.Name, "namespace", req.Namespace, "podName", pcr.Spec.PodName, "podNamespace", pcr.Namespace)
	ctx = logr.NewContext(ctx, logger)

	if !pcr.DeletionTimestamp.IsZero() {
		logger.Info("PodCertificateRequest has been deleted.")
		return ctrl.Result{}, nil
	}
	if !r.Signer.IsSignerNameMatching(pcr.Spec.SignerName) {
		logger.Info("PodCertificateRequest signer name does not match controller signer name", "signerName", pcr.Spec.SignerName, "controllerSignerName", r.Signer.Name())
		return ctrl.Result{}, nil
	}
	if isTerminal(&pcr) {
		logger.Info("PodCertificateRequest is immutable")
		return ctrl.Result{}, nil
	}

	cert, err := r.signRequest(ctx, &pcr)
	if err != nil {
		return r.recordFailure(ctx, &pcr, err)
	}
	if cert == nil {
		// Nothing to sign: the pod is being deleted, or the request is stale
		// (pod absent or UID-mismatched on the live read). Drop without requeue.
		return ctrl.Result{}, nil
	}

	persisted, err := r.recordIssued(ctx, &pcr, cert)
	if err != nil {
		logger.Error(err, "failed to record issued certificate; requeueing")
		return ctrl.Result{}, err
	}
	if persisted {
		config := cert.Config()
		logger.Info("issued certificate",
			"commonName", config.CommonName,
			"dnsNames", config.DNSNames,
			"uris", config.URIs,
			"extKeyUsage", config.ExtKeyUsage,
			"notAfter", cert.NotAfter().Format(time.RFC3339),
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

	// Read the pod from the manager cache first. The cache can be stale in two
	// ways that matter here: it may miss a just-created pod (racing the
	// request), or it may still hold a previous pod that shared this name. In
	// both cases re-read directly from the API server and gate on the pod's
	// live UID, so a certificate is never issued against the wrong pod.
	pod, err := getPod(ctx, r.Client, pcr.Spec.PodName, pcr.Namespace)
	switch {
	case apierrors.IsNotFound(err):
		// Cache miss; fall through to the live read below.
	case err != nil:
		return nil, err // transient
	}

	if pod == nil || pod.UID != pcr.Spec.PodUID {
		pod, err = getPod(ctx, r.APIReader, pcr.Spec.PodName, pcr.Namespace)
		switch {
		case apierrors.IsNotFound(err):
			// The pod is gone on a live read too: the request is stale, not a
			// terminal failure to sign. Drop it.
			logger.Info("associated pod not found on a live read; dropping stale request")
			r.recordPodGone(pcr, "associated pod %s/%s (uid %s) not found; dropping request",
				pcr.Namespace, pcr.Spec.PodName, pcr.Spec.PodUID)
			return nil, nil
		case err != nil:
			return nil, err // transient
		}
	}

	// Identity gate: only sign for the exact pod the request was created for.
	if pod.UID != pcr.Spec.PodUID {
		logger.Info("associated pod UID does not match the request; dropping stale request",
			"podUID", pod.UID, "requestPodUID", pcr.Spec.PodUID)
		r.recordPodGone(pcr, "associated pod %s/%s was replaced (request uid %s, live uid %s); dropping request",
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
	csr, err := signer.ParseCSR(pcr.Spec.StubPKCS10Request)
	if err != nil {
		return nil, denied(ReasonUnsupportedKeyType, err)
	}

	pcConfig, err := podcertificate.NewPodCertificateConfig(ctx, pcr, pod, csr, r.Certificate)
	if err != nil {
		return nil, denied(ReasonInvalidUserConfig, err)
	}
	// Non-fatal notices (e.g. default pod DNS SANs dropped for an over-long pod
	// name): the certificate still issues, but the operator must see why a
	// default was omitted, so surface each as a Warning event and a log line.
	for _, warning := range pcConfig.Warnings {
		logger.Info(warning)
		r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(ReasonDefaultSANSkipped), "SignPodCertificateRequest", "%s", warning)
	}

	if err := pcConfig.Validate(); err != nil {
		return nil, denied(ReasonInvalidUserConfig, err)
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
