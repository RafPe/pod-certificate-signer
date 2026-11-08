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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/tools/events"
	"k8s.io/client-go/util/retry"
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
		logger.Info("PodCertificateRequest is already terminal")
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

// recordFailure routes a signRequest error: terminal errors are recorded on the
// PCR and stop the reconcile; transient errors are returned so controller-runtime
// requeues with backoff. If recording a terminal outcome fails, that write error
// is returned so the reconcile requeues (the Failed condition is never silently lost).
func (r *PodCertificateRequestReconciler) recordFailure(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, err error) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var te *TerminalError
	if !errors.As(err, &te) {
		logger.Error(err, "transient error; requeueing")
		// Count every requeue, then announce the CA-unusable ones. The metric is
		// unconditional so a rate is meaningful; the event is throttled per
		// request, since the requeue repeats until the CA is rotated.
		metrics.PodCertificateRequestRequeues.WithLabelValues(string(requeueReason(err))).Inc()
		r.recordCASignerUnusable(pcr, err)
		return ctrl.Result{}, err
	}

	logger.Error(te.Err, "terminal failure", "reason", te.Reason)
	if werr := r.recordTerminal(ctx, pcr, te); werr != nil {
		logger.Error(werr, "failed to record terminal outcome; requeueing", "reason", te.Reason)
		return ctrl.Result{}, werr
	}
	return ctrl.Result{}, nil
}

// recordTerminal records a Denied/Failed condition carried by a *TerminalError.
// The certificate fields are cleared, since kube-apiserver requires them to be
// empty when denying or failing a PodCertificateRequest.
func (r *PodCertificateRequestReconciler) recordTerminal(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, te *TerminalError) error {
	clearCertificate(pcr)
	_, err := r.recordOutcome(ctx, pcr, te.ConditionType, te.Reason, te.Err.Error(), corev1.EventTypeWarning)
	return err
}

// recordCASignerUnusable emits the warning event for a request the CA cannot
// sign at the moment (see ReasonCASignerUnusable). Anything else transient - an
// API read failure, a conflicted write - is the controller's own retry loop
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
// recordPodGone: the outcome is not terminal, and a condition would freeze the
// request (see ReasonCASignerUnusable).
func (r *PodCertificateRequestReconciler) recordCASignerUnusable(pcr *certificatesv1.PodCertificateRequest, err error) {
	if !errors.Is(err, authority.ErrCASignerUnusable) {
		return
	}
	if !r.caUnusableEvents.allow(pcr.UID) {
		return
	}
	r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(ReasonCASignerUnusable), "SignPodCertificateRequest",
		"the signing CA cannot issue this certificate yet, retrying until it can: %s", err)
}

// recordPodGone emits the warning event for a request dropped because a live
// read confirmed its pod is gone. The note is supplied by the caller, since
// "absent" and "replaced by a different pod" are different facts for whoever
// reads the event. Deliberately no status write: the drop is not a terminal
// outcome, and the event is the only breadcrumb an operator gets.
func (r *PodCertificateRequestReconciler) recordPodGone(pcr *certificatesv1.PodCertificateRequest, noteFmt string, args ...any) {
	// The event names the object and is the only breadcrumb its owner gets; the
	// metric carries the rate, which is what says the controller is losing a
	// race with pod churn rather than dropping the odd stale request.
	metrics.PodCertificateRequestDrops.WithLabelValues(string(ReasonAssociatedPodGone)).Inc()
	r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(ReasonAssociatedPodGone), "SignPodCertificateRequest", noteFmt, args...)
}

// requeueReason classifies a transient error for the requeue counter. The
// classification is a closed set computed here: the error text itself is
// unbounded (it can carry std-lib and apiserver detail) and belongs in the log,
// never in a label.
func requeueReason(err error) Reason {
	if errors.Is(err, authority.ErrCASignerUnusable) {
		return ReasonCASignerUnusable
	}

	return metrics.ReasonTransient
}

// requestOutcome maps a condition type onto the outcome label. The three
// condition types the signer writes are the closed set the certificates API
// defines; anything else would be a condition this controller never records.
func requestOutcome(conditionType string) string {
	switch conditionType {
	case certificatesv1.PodCertificateRequestConditionTypeIssued:
		return metrics.OutcomeIssued
	case certificatesv1.PodCertificateRequestConditionTypeDenied:
		return metrics.OutcomeDenied
	default:
		return metrics.OutcomeFailed
	}
}

// beginRefreshAt is when kubelet should start refreshing cert: RefreshBefore
// ahead of its expiry.
func beginRefreshAt(cert *podcertificate.PodCertificate) time.Time {
	return cert.NotAfter().Add(-cert.Config().RefreshBefore)
}

// recordIssued writes the issued certificate and its validity bounds onto the
// request status together with the Issued condition. It reports whether the
// write was persisted (see recordOutcome).
func (r *PodCertificateRequestReconciler) recordIssued(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, cert *podcertificate.PodCertificate) (bool, error) {
	pcr.Status.CertificateChain = cert.CertificateChain()
	pcr.Status.NotBefore = &metav1.Time{Time: cert.NotBefore()}
	pcr.Status.NotAfter = &metav1.Time{Time: cert.NotAfter()}
	pcr.Status.BeginRefreshAt = &metav1.Time{Time: beginRefreshAt(cert)}

	const message = "Certificate successfully issued"
	return r.recordOutcome(ctx, pcr, certificatesv1.PodCertificateRequestConditionTypeIssued, ReasonCertificateIssued, message, corev1.EventTypeNormal)
}

// recordOutcome sets the condition on the PodCertificateRequest, persists the
// status and only then emits the corresponding event. The order matters: the
// event announces an outcome, so it must not be emitted until the write that
// makes the outcome real has succeeded. Emitting first would advertise a result
// that a failed or conflicting write never persisted, and re-advertise it on
// every requeue. It reports whether the write was persisted: false means
// another writer recorded a terminal outcome first and this one was discarded.
func (r *PodCertificateRequestReconciler) recordOutcome(ctx context.Context, pcr *certificatesv1.PodCertificateRequest, conditionType string, reason Reason, message, eventType string) (bool, error) {
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
	metrics.PodCertificateRequests.WithLabelValues(requestOutcome(conditionType), string(reason)).Inc()
	r.EventRecorder.Eventf(pcr, nil, eventType, string(reason), "SignPodCertificateRequest", message)
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

// statusRetryReader returns the reader used to re-read a PodCertificateRequest
// before retrying a conflicted status write: the cache-bypassing APIReader in
// production, falling back to the cached client when none is wired (unit tests).
func (r *PodCertificateRequestReconciler) statusRetryReader() client.Reader {
	if r.APIReader != nil {
		return r.APIReader
	}
	return r.Client
}

// clearCertificate empties the certificate block of the request status, which
// kube-apiserver requires when a request is denied or failed.
func clearCertificate(pcr *certificatesv1.PodCertificateRequest) {
	pcr.Status.CertificateChain = ""
	pcr.Status.NotBefore = nil
	pcr.Status.NotAfter = nil
	pcr.Status.BeginRefreshAt = nil
}
