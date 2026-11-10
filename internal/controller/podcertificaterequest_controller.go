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
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"

	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// eventAction is the action every event this controller emits is attributed
// to; it names the operation, where the reason names the outcome.
const eventAction = "SignPodCertificateRequest"

// terminalError marks a failure that can never succeed on retry. The
// reconciler records the carried outcome (Denied or Failed, with its reason and
// the error text as message) on the PodCertificateRequest and stops. Any error
// that is not a *terminalError is treated as transient and returned to
// controller-runtime so it requeues with backoff. denied and failed are its
// only constructors, so its kind is always Denied or Failed.
type terminalError struct {
	kind   outcome.Kind
	reason outcome.ConditionReason
	err    error
}

func (e *terminalError) Error() string { return e.err.Error() }
func (e *terminalError) Unwrap() error { return e.err }

// denied wraps err as a terminal "Denied" outcome: the signer refuses the
// request (e.g. unsupported key type, invalid user configuration).
func denied(reason outcome.ConditionReason, err error) error {
	return &terminalError{kind: outcome.Denied, reason: reason, err: err}
}

// failed wraps err as a terminal "Failed" outcome: the signer could not issue
// the certificate. The only Failed reason is SigningFailed (a missing pod is
// dropped, not failed), so the reason is fixed rather than a parameter.
func failed(err error) error {
	return &terminalError{kind: outcome.Failed, reason: outcome.SigningFailed, err: err}
}

// errDropRequest marks a request there is nothing to sign for: the pod is
// being deleted, or a live read shows the request is stale. Reconcile drops it
// without a status write and without a requeue. errPodGone is the stale case,
// which Reconcile also announces (see warnPodGone); signRequest wraps it with
// a note saying whether the pod was absent or replaced.
var (
	errDropRequest = errors.New("request dropped")
	errPodGone     = fmt.Errorf("associated pod is gone: %w", errDropRequest)
)

// Signer is the consumer-side view of the signing dependency the reconciler
// needs. Keeping it an interface (rather than the concrete certificate
// authority) lets the reconcile path be unit-tested with a stub.
type Signer interface {
	Sign(*podcertificate.Config) (*podcertificate.Certificate, error)
}

// Compile-time assertion that the production CA satisfies the seam.
var _ Signer = (*authority.CertificateAuthority)(nil)

// PodCertificateRequestReconciler reconciles a PodCertificateRequest object.
//
// NewPodCertificateRequestReconciler is the production path and validates its
// inputs. Unit tests build the struct directly, with fakes for only the fields
// the path under test reads: Client and APIReader for any read or status
// write, Signer and SignerName once a request is signed, EventRecorder once an
// event is emitted. A zero-valued field the exercised path reads panics.
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
	// also excludes Pods from the cache; reading through APIReader states the
	// intent here, where it is relied upon.) Conflicted status writes re-read
	// through it too, since the cache lags the write that conflicted.
	APIReader client.Reader
	Log       logr.Logger
	// Signer issues the certificate once the request has been verified and its
	// configuration resolved.
	Signer Signer
	// SignerName is the spec.signerName this controller answers for; requests
	// addressed to any other signer are left alone.
	SignerName    string
	EventRecorder events.EventRecorder
	// CertificateOptions is the process-wide policy the certificate
	// configuration is built under: the cluster FQDN and the feature flags.
	CertificateOptions podcertificate.Options

	// caUnusableEvents rate-limits the CASignerUnusable warning per request.
	// It carries a mutex, so the reconciler must always be used through a
	// pointer.
	caUnusableEvents eventThrottle
}

// NewPodCertificateRequestReconciler wires a reconciler to mgr: the cached
// client, the cache-bypassing API reader, a named logger and event recorder.
// name is the controller name used for the logger and as the event reporter;
// signerName is the spec.signerName the controller answers for.
func NewPodCertificateRequestReconciler(
	mgr ctrl.Manager,
	name, signerName string,
	signer Signer,
	certOpts podcertificate.Options,
) (*PodCertificateRequestReconciler, error) {
	if name == "" {
		return nil, errors.New("a controller name is required")
	}
	if signerName == "" {
		return nil, errors.New("a signer name is required")
	}
	if signer == nil {
		return nil, errors.New("a signer is required")
	}
	return &PodCertificateRequestReconciler{
		Client:             mgr.GetClient(),
		APIReader:          mgr.GetAPIReader(),
		Log:                ctrl.Log.WithName(name),
		Signer:             signer,
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
				return ok && !isTerminal(pcr)
			},
		}).
		Complete(r)
}

// Reconcile signs one PodCertificateRequest addressed to this signer. It skips
// deleted, foreign-signer and already-terminal requests, runs signRequest, and
// records the Issued outcome; terminal failures are written to the request,
// stale requests are dropped, and anything transient is requeued.
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pcr certificatesv1.PodCertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &pcr); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil // gone: nothing to do
		}
		// Nothing was read, so there is no request to warn on: count only.
		countRequeue(err)
		return ctrl.Result{}, fmt.Errorf("get PodCertificateRequest: %w", err)
	}

	// Use a request-scoped logger: reconciles run concurrently, so the shared
	// reconciler state must not be mutated here.
	logger := r.Log.WithValues("name", req.Name, "namespace", req.Namespace, "podName", pcr.Spec.PodName, "podNamespace", pcr.Namespace)
	ctx = logr.NewContext(ctx, logger)

	if !pcr.DeletionTimestamp.IsZero() {
		logger.Info("request is being deleted; nothing to do")
		return ctrl.Result{}, nil
	}
	if pcr.Spec.SignerName != r.SignerName {
		logger.Info("request is addressed to another signer; ignoring", "signerName", pcr.Spec.SignerName, "controllerSignerName", r.SignerName)
		return ctrl.Result{}, nil
	}
	if isTerminal(&pcr) {
		logger.Info("request is already terminal; nothing to do")
		return ctrl.Result{}, nil
	}

	cert, err := r.signRequest(ctx, &pcr)
	if errors.Is(err, errDropRequest) {
		logger.Info("dropping request", "reason", err.Error())
		if errors.Is(err, errPodGone) {
			r.warnPodGone(&pcr, err.Error())
		}
		return ctrl.Result{}, nil
	}
	if err != nil {
		return r.requeueOrRecordTerminal(ctx, &pcr, err)
	}

	persisted, err := r.recordIssued(ctx, &pcr, cert)
	if err != nil {
		return r.requeue(&pcr, err)
	}
	if persisted {
		logger.Info("issued certificate",
			"commonName", cert.Config.CommonName,
			"dnsNames", cert.Config.DNSNames,
			"ipAddresses", cert.Config.IPAddresses,
			"uris", cert.Config.URIs,
			"extKeyUsage", cert.Config.ExtKeyUsage,
			"notAfter", cert.NotAfter.Format(time.RFC3339),
			"beginRefreshAt", beginRefreshAt(cert).Format(time.RFC3339))
	}
	return ctrl.Result{}, nil
}

// signRequest runs the signing pipeline for a PodCertificateRequest. It
// reports nothing itself; Reconcile routes what it returns:
//   - (cert, nil) on success; cert is never nil when err is nil
//   - (nil, err wrapping errDropRequest) when there is nothing to do: the
//     associated pod is being deleted, or a live read confirms it is gone
//     (absent, or carrying a different UID than the request asked for). The
//     gone case wraps errPodGone, with a note saying which.
//   - (nil, *terminalError) for permanent failures (recorded on the PCR, no retry)
//   - (nil, err) for transient failures (requeued with backoff)
func (r *PodCertificateRequestReconciler) signRequest(ctx context.Context, pcr *certificatesv1.PodCertificateRequest) (*podcertificate.Certificate, error) {
	logger := log.FromContext(ctx)

	// Live read, then gate on the UID the request names (see APIReader).
	pod, err := getPod(ctx, r.APIReader, pcr.Spec.PodName, pcr.Namespace)
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("associated pod %s/%s (uid %s) not found; dropping request: %w",
			pcr.Namespace, pcr.Spec.PodName, pcr.Spec.PodUID, errPodGone)
	}
	if err != nil {
		return nil, err // transient
	}
	if pod.UID != pcr.Spec.PodUID {
		return nil, fmt.Errorf("associated pod %s/%s was replaced (request uid %s, live uid %s); dropping request: %w",
			pcr.Namespace, pcr.Spec.PodName, pcr.Spec.PodUID, pod.UID, errPodGone)
	}
	if !pod.DeletionTimestamp.IsZero() {
		return nil, fmt.Errorf("associated pod is being deleted: %w", errDropRequest)
	}

	// certificates.k8s.io/v1 dropped spec.pkixPublicKey: every kubelet that
	// speaks the GA API sends the PKCS#10 stub, so it is the only source of
	// the subject public key.
	csr, err := podcertificate.ParseCSR(pcr.Spec.StubPKCS10Request)
	if err != nil {
		return nil, denied(outcome.UnsupportedKeyType, err)
	}

	cfg, err := podcertificate.NewConfig(ctx, pcr, pod, csr, r.CertificateOptions)
	if err != nil {
		return nil, denied(outcome.InvalidUserConfig, err)
	}
	// Non-fatal notices (e.g. default pod DNS SANs dropped for an over-long pod
	// name): the certificate still issues, but the operator must see why a
	// default was omitted.
	for _, notice := range cfg.Notices {
		logger.Info(notice.Message, "reason", notice.Reason)
		r.EventRecorder.Eventf(pcr, nil, corev1.EventTypeWarning, string(notice.Reason), eventAction, "%s", notice.Message)
	}

	cert, err := r.Signer.Sign(cfg)
	if errors.Is(err, authority.ErrCASignerUnusable) {
		return nil, err // transient: requeued until the CA can sign
	}
	if err != nil {
		return nil, failed(err)
	}
	return cert, nil
}

// getPod reads the request's pod through reader and wraps a failure with the
// pod's key. The reconciler passes its APIReader, so the read is live.
func getPod(ctx context.Context, reader client.Reader, podName, podNamespace string) (*corev1.Pod, error) {
	var pod corev1.Pod
	key := types.NamespacedName{Name: podName, Namespace: podNamespace}
	if err := reader.Get(ctx, key, &pod); err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", podNamespace, podName, err)
	}

	return &pod, nil
}
