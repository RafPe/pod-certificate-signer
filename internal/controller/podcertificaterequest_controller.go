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
	"errors"
	"fmt"
	"time"

	// "crypto/ed25519"
	// "crypto/rsa"
	// "crypto/x509"

	"github.com/go-logr/logr"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/api"
	podcertificate "github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"

	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Reason identifies a terminal/issued outcome recorded on a PodCertificateRequest.
type Reason string

// TerminalError marks a failure that can never succeed on retry. The reconciler
// records the carried Reason on the PodCertificateRequest and stops. Any error
// that is NOT a *TerminalError is treated as transient and returned to
// controller-runtime so it requeues with backoff.
type TerminalError struct {
	Reason Reason
	Err    error
}

func (e *TerminalError) Error() string { return e.Err.Error() }
func (e *TerminalError) Unwrap() error { return e.Err }

func terminal(reason Reason, err error) error {
	return &TerminalError{Reason: reason, Err: err}
}

// PodCertificateRequestReconciler reconciles a PodCertificateRequest object
type PodCertificateRequestReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	Signer        *signer.Signer
	ClusterFqdn   string
	EventRecorder record.EventRecorder
}

// Outcome is the terminal/issued state recorded on a PodCertificateRequest for a
// given Reason. EventType and whether to clear the certificate fields are derived
// from ConditionType, so they are not stored.
type Outcome struct {
	ConditionType string // capiv1beta1.PodCertificateRequestConditionType{Failed,Denied,Issued}
	Message       string
}

func (o Outcome) eventType() string {
	if o.ConditionType == capiv1beta1.PodCertificateRequestConditionTypeIssued {
		return corev1.EventTypeNormal
	}
	return corev1.EventTypeWarning
}

const (
	ReasonCertificateConfigurationInvalid Reason = "CertificateConfigurationInvalid"
	ReasonAssociatedPodNotFound           Reason = "AssociatedPodNotFound"
	ReasonSigningFailed                   Reason = "SigningFailed"
	ReasonSigningDenied                   Reason = "SigningDenied"
	ReasonCertificateIssued               Reason = "CertificateIssued"
	ReasonUnsupportedKeyType              Reason = "UnsupportedKeyType"
)

var outcomes = map[Reason]Outcome{
	ReasonAssociatedPodNotFound:           {capiv1beta1.PodCertificateRequestConditionTypeFailed, "Pod for associated PodCertificateRequest not found"},
	ReasonUnsupportedKeyType:              {capiv1beta1.PodCertificateRequestConditionTypeDenied, "Unsupported key type"},
	ReasonCertificateConfigurationInvalid: {capiv1beta1.PodCertificateRequestConditionTypeFailed, "Certificate configuration is invalid"},
	ReasonSigningFailed:                   {capiv1beta1.PodCertificateRequestConditionTypeFailed, "Failed to sign certificate"},
	ReasonSigningDenied:                   {capiv1beta1.PodCertificateRequestConditionTypeDenied, "Signing denied"},
	ReasonCertificateIssued:               {capiv1beta1.PodCertificateRequestConditionTypeIssued, "Certificate successfully issued"},
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;update;patch

func (r *PodCertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{MaxConcurrentReconciles: 2}). //TODO Create a configurable setup for this
		For(&capiv1beta1.PodCertificateRequest{}).
		WithEventFilter(predicate.Funcs{
			// Allow create events
			CreateFunc: func(e event.CreateEvent) bool {

				isPcrImmutable := api.IsPodCertificateRequestImmutable(e.Object.(*capiv1beta1.PodCertificateRequest))

				// V(1) - Debug level (basic debugging)
				r.Log.Info("Check if PodCertificateRequest is immutable", "immutable", isPcrImmutable, "event", "create", "request-name", e.Object.(*capiv1beta1.PodCertificateRequest).Name)
				return !isPcrImmutable // True for processing request ; False for skipping request
			},
		}).
		Complete(r)
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pcr capiv1beta1.PodCertificateRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &pcr); err != nil {
		// Gone -> drop; any real error -> requeue.
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	r.Log = logf.Log.WithValues("name", req.Name, "namespace", req.Namespace, "podName", pcr.Spec.PodName, "podNamespace", pcr.Namespace)
	ctx = logr.NewContext(ctx, r.Log)

	if !pcr.DeletionTimestamp.IsZero() {
		r.Log.Info("PodCertificateRequest has been deleted.")
		return ctrl.Result{}, nil
	}
	if !r.Signer.IsSignerNameMatching(pcr.Spec.SignerName) {
		r.Log.Info("PodCertificateRequest signer name does not match controller signer name", "signerName", pcr.Spec.SignerName, "controllerSignerName", r.Signer.GetSignerName())
		return ctrl.Result{}, nil
	}
	if api.IsPodCertificateRequestImmutable(&pcr) {
		r.Log.Info("PodCertificateRequest is immutable")
		return ctrl.Result{}, nil
	}

	r.Log.Info("Lookup pod associated with PodCertificateRequest")
	cert, err := r.process(ctx, &pcr)
	if err != nil {
		return r.recordFailure(ctx, &pcr, err)
	}
	if cert == nil {
		return ctrl.Result{}, nil // pod is being deleted -> nothing to do
	}

	r.Log.Info("Successfully signed the certificate")
	if err := r.recordIssued(ctx, &pcr, cert); err != nil {
		r.Log.Error(err, "failed to record issued certificate; requeueing")
		return ctrl.Result{}, err
	}
	r.Log.Info("Successfully issued certificate")
	return ctrl.Result{}, nil
}

// process runs the signing pipeline for a PodCertificateRequest. It returns:
//   - (cert, nil)  on success
//   - (nil, nil)   when there is nothing to do (the associated pod is being deleted)
//   - (nil, *TerminalError) for permanent failures (recorded on the PCR, no retry)
//   - (nil, err)   for transient failures (requeued with backoff)
func (r *PodCertificateRequestReconciler) process(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest) (*podcertificate.PodCertificate, error) {
	crPod, err := api.GetPod(ctx, r.Client, pcr.Spec.PodName, pcr.Namespace)
	switch {
	case apierrors.IsNotFound(err):
		return nil, terminal(ReasonAssociatedPodNotFound, err)
	case err != nil:
		return nil, err // transient
	}
	if !crPod.DeletionTimestamp.IsZero() {
		r.Log.Info("Pod has been deleted.")
		return nil, nil
	}

	publicKey, publicKeyAlgorithm, err := r.Signer.ParsePkixPublicKey(pcr.Spec.PKIXPublicKey)
	if err != nil {
		return nil, terminal(ReasonUnsupportedKeyType, err)
	}

	pcConfig, err := podcertificate.NewPodCertificateConfig(crPod, r.Signer.GetSignerName(), publicKey, publicKeyAlgorithm)
	if err != nil {
		return nil, terminal(ReasonCertificateConfigurationInvalid, err)
	}
	pcConfig.LogConfiguration(ctx)

	if err := r.Signer.ValidatePodCertificateConfig(pcConfig); err != nil {
		return nil, terminal(ReasonCertificateConfigurationInvalid, err)
	}

	cert, err := r.Signer.SignPodCertificate(pcConfig)
	if err != nil {
		return nil, terminal(ReasonSigningFailed, err)
	}
	return cert, nil
}

// recordFailure routes a process() error: terminal errors are recorded on the
// PCR and stop the reconcile; transient errors are returned so controller-runtime
// requeues with backoff. If recording a terminal outcome fails, that write error
// is returned so the reconcile requeues (the Failed condition is never silently lost).
func (r *PodCertificateRequestReconciler) recordFailure(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest, err error) (ctrl.Result, error) {
	var te *TerminalError
	if !errors.As(err, &te) {
		r.Log.Error(err, "transient error; requeueing")
		return ctrl.Result{}, err
	}

	r.Log.Error(te.Err, "terminal failure", "reason", te.Reason)
	if werr := r.applyOutcome(ctx, pcr, te.Reason); werr != nil {
		r.Log.Error(werr, "failed to record terminal outcome; requeueing", "reason", te.Reason)
		return ctrl.Result{}, werr
	}
	return ctrl.Result{}, nil
}

func (r *PodCertificateRequestReconciler) recordIssued(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest, cert *podcertificate.PodCertificate) error {
	r.setCertificateOnPodCertificateRequest(pcr, cert)
	return r.applyOutcome(ctx, pcr, ReasonCertificateIssued)
}

func (r *PodCertificateRequestReconciler) setCertificateOnPodCertificateRequest(pcr *capiv1beta1.PodCertificateRequest, podCertificate *podcertificate.PodCertificate) {

	//TODO: For validation of config!
	beginRefreshAt := podCertificate.NotAfter().Add(-podCertificate.Config().RefreshBefore)

	r.Log.V(1).Info("Setting the certificate in the PodCertificateRequest",
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

func (r *PodCertificateRequestReconciler) applyOutcome(ctx context.Context, pcr *capiv1beta1.PodCertificateRequest, reason Reason) error {
	o, ok := outcomes[reason]
	if !ok {
		return fmt.Errorf("no outcome registered for reason %q", reason)
	}

	if o.ConditionType != capiv1beta1.PodCertificateRequestConditionTypeIssued {
		r.clearPodCertificateRequestStatusFields(pcr)
	}

	r.setPodCertificateRequestStatusCondition(pcr, o.ConditionType, string(reason), o.Message)
	r.EventRecorder.Event(pcr, o.eventType(), string(reason), o.Message)

	return r.Status().Update(ctx, pcr)
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
