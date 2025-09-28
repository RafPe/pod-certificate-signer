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
	"fmt"
	"time"

	// "crypto/ed25519"
	// "crypto/rsa"
	// "crypto/x509"

	"github.com/go-logr/logr"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/api"
	podcertificate "github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"

	capi "k8s.io/api/certificates/v1alpha1"
	corev1 "k8s.io/api/core/v1"
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

// PodCertificateRequestReconciler reconciles a PodCertificateRequest object
type PodCertificateRequestReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	Signer        *signer.Signer
	ClusterFqdn   string
	EventRecorder record.EventRecorder
}
type StatusConfig struct {
	ConditionType    string
	ConditionReason  string
	ConditionMessage string
	EventType        string
	EventReason      string
	EventMessage     string
}

const (
	PodCertificateRequestConditionCertificateIssued                     string = "CertificateIssued"
	PodCertificateRequestConditionReasonPodNotFound                     string = "PodNotFound"
	PodCertificateRequestConditionReasonCertificateConfigurationInvalid string = "CertificateConfigurationInvalid"
)

const (
	ReasonCertificateConfigurationInvalid = "CertificateConfigurationInvalid"
	ReasonAssociatedPodNotFound           = "AssociatedPodNotFound"
	ReasonSigningFailed                   = "SigningFailed"
	ReasonSigningDenied                   = "SigningDenied"
	ReasonCertificateIssued               = "CertificateIssued"
	ReasonUnsupportedKeyType              = "UnsupportedKeyType"
)

var statusMap = map[string]StatusConfig{
	ReasonCertificateConfigurationInvalid: {
		ConditionType:    capi.PodCertificateRequestConditionTypeFailed,
		ConditionReason:  ReasonCertificateConfigurationInvalid,
		ConditionMessage: "Certificate configuration is invalid",
		EventType:        corev1.EventTypeWarning,
		EventReason:      ReasonCertificateConfigurationInvalid,
		EventMessage:     "Certificate configuration is invalid",
	},
	ReasonAssociatedPodNotFound: {
		ConditionType:    capi.PodCertificateRequestConditionTypeFailed,
		ConditionReason:  ReasonAssociatedPodNotFound,
		ConditionMessage: "Pod for associated PodCertificateRequest not found",
		EventType:        corev1.EventTypeWarning,
		EventReason:      ReasonAssociatedPodNotFound,
		EventMessage:     "Pod for associated PodCertificateRequest not found",
	},
	ReasonSigningDenied: {
		ConditionType:    capi.PodCertificateRequestConditionTypeDenied,
		ConditionReason:  ReasonSigningDenied,
		ConditionMessage: "Signing denied",
		EventType:        corev1.EventTypeWarning,
		EventReason:      ReasonSigningDenied,
		EventMessage:     "Signing denied",
	},
	ReasonSigningFailed: {
		ConditionType:    capi.PodCertificateRequestConditionTypeFailed,
		ConditionReason:  ReasonSigningFailed,
		ConditionMessage: "Failed to sign certificate",
		EventType:        corev1.EventTypeWarning,
		EventReason:      ReasonSigningFailed,
		EventMessage:     "Failed to sign certificate",
	},
	ReasonCertificateIssued: {
		ConditionType:    capi.PodCertificateRequestConditionTypeIssued,
		ConditionReason:  ReasonCertificateIssued,
		ConditionMessage: "Certificate successfully issued",
		EventType:        corev1.EventTypeNormal,
		EventReason:      ReasonCertificateIssued,
		EventMessage:     "Certificate successfully issued",
	},
	ReasonUnsupportedKeyType: {
		ConditionType:    capi.PodCertificateRequestConditionTypeDenied,
		ConditionReason:  capi.PodCertificateRequestConditionUnsupportedKeyType,
		ConditionMessage: "Unsupported key type",
		EventType:        corev1.EventTypeWarning,
		EventReason:      capi.PodCertificateRequestConditionUnsupportedKeyType,
		EventMessage:     "Unsupported key type",
	},
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;update;patch

func (r *PodCertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(controller.Options{MaxConcurrentReconciles: 2}). //TODO Create a configurable setup for this
		For(&capi.PodCertificateRequest{}).
		WithEventFilter(predicate.Funcs{
			// Allow create events
			CreateFunc: func(e event.CreateEvent) bool {

				isPcrImmutable := api.IsPodCertificateRequestImmutable(e.Object.(*capi.PodCertificateRequest))

				// V(1) - Debug level (basic debugging)
				r.Log.Info("Check if PodCertificateRequest is immutable", "immutable", isPcrImmutable, "event", "create", "request-name", e.Object.(*capi.PodCertificateRequest).Name)
				return !isPcrImmutable // True for processing request ; False for skipping request
			},
		}).
		Complete(r)
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var pcr capi.PodCertificateRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &pcr); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
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
	crPod, err := api.GetPod(ctx, r.Client, pcr.Spec.PodName, pcr.Namespace)
	if err != nil {
		r.Log.Error(err, "Failed to retrieve pod associated with PodCertificateRequest")
		r.updatePodCertificateRequestStatusWithReason(ctx, &pcr, ReasonAssociatedPodNotFound, "", true)

		return ctrl.Result{}, nil
	}

	if !crPod.DeletionTimestamp.IsZero() {
		r.Log.Info("Pod has been deleted.")
		return ctrl.Result{}, nil
	}

	publicKey, publicKeyAlgorithm, err := r.Signer.ParsePkixPublicKey(pcr.Spec.PKIXPublicKey)
	if err != nil {
		r.Log.Error(err, "Public key is not supported/invalid")
		r.updatePodCertificateRequestStatusWithReason(ctx, &pcr, ReasonUnsupportedKeyType, "", true)
		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
	}

	pcConfig, err := podcertificate.NewPodCertificateConfig(
		crPod,
		r.Signer.GetSignerName(),
		publicKey,
		publicKeyAlgorithm)
	if err != nil {
		r.Log.Error(err, "Failed to create PodCertificateConfig")
		r.updatePodCertificateRequestStatusWithReason(ctx, &pcr, ReasonCertificateConfigurationInvalid, "", true)
		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
	}
	pcConfig.LogConfiguration(ctx)

	if err := r.Signer.ValidatePodCertificateConfig(pcConfig); err != nil {
		r.Log.Error(err, "Failed to validate the PodCertificateConfig")
		r.updatePodCertificateRequestStatusWithReason(ctx, &pcr, ReasonCertificateConfigurationInvalid, "", true)
		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
	}

	podCertificate, err := r.Signer.SignPodCertificate(pcConfig)
	if err != nil {
		r.Log.Error(err, "Failed to sign the certificate")
		r.updatePodCertificateRequestStatusWithReason(ctx, &pcr, ReasonSigningFailed, "", true)

		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
	}
	r.Log.Info("Successfully signed the certificate")

	if err := r.issueCertificate(ctx, &pcr, podCertificate); err != nil {
		r.Log.Error(err, "failed to update the PodCertificateRequest status")
		r.updatePodCertificateRequestStatusWithReason(ctx, &pcr, ReasonCertificateConfigurationInvalid, "", true)

		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
	}

	r.Log.Info("Successfully issued certificate")
	return ctrl.Result{}, nil // DON'T REQUEUE - Terminal success

}

func (r *PodCertificateRequestReconciler) issueCertificate(ctx context.Context, pcr *capi.PodCertificateRequest, podCertificate *podcertificate.PodCertificate) error {

	r.setCertificateOnPodCertificateRequest(pcr, podCertificate)

	return r.updatePodCertificateRequestStatusWithReason(ctx, pcr, ReasonCertificateIssued, "", false)
}

func (r *PodCertificateRequestReconciler) setCertificateOnPodCertificateRequest(pcr *capi.PodCertificateRequest, podCertificate *podcertificate.PodCertificate) {

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

func (r *PodCertificateRequestReconciler) updatePodCertificateRequestStatusWithReason(ctx context.Context, pcr *capi.PodCertificateRequest, reason string, customMessage string, clearFields bool) error {
	config, exists := statusMap[reason]
	if !exists {
		return fmt.Errorf("unknown reason: %s", reason)
	}

	if clearFields {
		r.clearPodCertificateRequestStatusFields(pcr)
	}

	// Use custom message if provided, otherwise use default
	conditionMessage := customMessage
	eventMessage := customMessage
	if customMessage == "" {
		conditionMessage = config.ConditionMessage
		eventMessage = config.EventMessage
	}

	r.setPodCertificateRequestStatusCondition(
		pcr,
		config.ConditionType,
		config.ConditionReason,
		conditionMessage,
	)

	r.EventRecorder.Event(
		pcr,
		config.EventType,
		config.EventReason,
		eventMessage,
	)

	return r.updatePodCertificateRequestStatus(ctx, pcr)
}

func (r *PodCertificateRequestReconciler) setPodCertificateRequestStatusCondition(pcr *capi.PodCertificateRequest, conditionType, reason, message string) {
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

func (r *PodCertificateRequestReconciler) clearPodCertificateRequestStatusFields(pcr *capi.PodCertificateRequest) {
	pcr.Status.CertificateChain = ""
	pcr.Status.NotBefore = nil
	pcr.Status.NotAfter = nil
	pcr.Status.BeginRefreshAt = nil
}

func (r *PodCertificateRequestReconciler) updatePodCertificateRequestStatus(ctx context.Context, pcr *capi.PodCertificateRequest) error {
	return r.Status().Update(ctx, pcr)
}
