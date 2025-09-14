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
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/api"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/ca"

	capi "k8s.io/api/certificates/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// PodCertificateRequestReconciler reconciles a PodCertificateRequest object
type PodCertificateRequestReconciler struct {
	client.Client
	Log           logr.Logger
	Scheme        *runtime.Scheme
	CA            *ca.CA
	SignerName    string
	EventRecorder record.EventRecorder
}

const (
	PodCertificateRequestConditionCertificateIssued string = "CertificateIssued"
)

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;update;patch

func (r *PodCertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&capi.PodCertificateRequest{}).
		WithEventFilter(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				// Simple check without method calls
				if newCert, ok := e.ObjectNew.(*capi.PodCertificateRequest); ok && newCert != nil {
					return newCert.Status.CertificateChain == ""
				}
				return true
			},
			// UpdateFunc: func(e event.UpdateEvent) bool {
			// 	newCert := e.ObjectNew.(*capi.PodCertificateRequest)

			// 	return !r.isAlreadyIssued(newCert)

			// 	// if newCert, ok := e.ObjectNew.(*capi.PodCertificateRequest); ok {
			// 	// 	return !r.isAlreadyIssued(newCert)
			// 	// }
			// 	// return true
			// },

			// // Allow create events
			// CreateFunc: func(e event.CreateEvent) bool {
			// 	return true
			// },

			// // Allow delete events
			// DeleteFunc: func(e event.DeleteEvent) bool {
			// 	return true
			// },

			// // Allow generic events (e.g., external triggers)
			// GenericFunc: func(e event.GenericEvent) bool {
			// 	return true
			// },
		}).
		Complete(r)
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log = logf.FromContext(ctx)

	// Retrieve the object from the ctx and map to PodCertificateRequest
	var pcr capi.PodCertificateRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &pcr); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, fmt.Errorf("Error %q getting PodCertificateRequest", err)
	}
	r.Log.Info("Processing PodCertificateRequest")

	// Check if the PodCertificateRequest has already been issued - if so we skip the event
	if api.IsPodCertificateRequestIssued(&pcr) {
		r.Log.Info("PodCertificateRequest already issued - skipping")
		return ctrl.Result{}, nil
	}

	// Check if the public key type is supported
	if !r.isPublicKeyTypeSupported(pcr.Spec.PKIXPublicKey) {
		r.Log.Error(fmt.Errorf("Unsupported public key type"), "Unsupported public key type")

		r.setPodCertificateRequestStatusCondition(
			ctx, &pcr,
			capi.PodCertificateRequestConditionTypeFailed,         // Condition type
			capi.PodCertificateRequestConditionUnsupportedKeyType, // Condition reason
			"Unsupported public key type")                         // Condition message

		return ctrl.Result{}, nil
	}

	// Retrieve the pod associated with the PodCertificateRequest - if we fail to do so we are facing
	// problems which needs to be addressed - but its not necessarily condition to fail the request
	// TODO: Verify if we should/should not fail the request
	pod, err := r.getPodCertificateRequestAssociatedPod(ctx, &pcr)
	if err != nil {
		r.Log.Error(err, "Failed to get associated pod", "podName", pod.Name)
		return ctrl.Result{}, err
	}

	r.Log.Info("Found associated pod for PodCertificateRequest", "podName", pod.Name)

	// if dnsNames, found := r.getPodAnnotation(pod, "coolcert.example.com/foo-san"); found {
	// 	// Use annotation value
	// 	r.Log.Info("Using DNS names from annotation", "value", dnsNames)
	// } else {
	// 	// Use default
	// 	dnsNames = []string{}
	// 	r.Log.Info("No SANs found in pod annotations, using empty []string", "value", dnsNames)
	// }

	// Issue certificate
	commonName := pcr.Spec.PodName                    // Adjust based on your CRD spec
	dnsNames := []string{pcr.Spec.ServiceAccountName} // Adjust based on your CRD spec
	duration := 1 * time.Hour                         // 1 hour for testing

	// Issue certificate using the public key from the request
	podCertificate, err := r.CA.IssueCertificateForPublicKey(
		pcr.Spec.PKIXPublicKey,
		commonName,
		dnsNames,
		duration,
	)
	if err != nil {
		r.Log.Error(err, "Failed to issue certificate", "podName", pod.Name)
		return ctrl.Result{}, err
	}

	r.updatePodCertificateRequestWithCertificate(ctx, &pcr, podCertificate)
	r.updatePodAnnotations(ctx, &pcr, pod)

	// Successfully issued certificate
	r.Log.Info("Certificate successfully issued")
	r.EventRecorder.Event(&pcr, corev1.EventTypeNormal, "CertificateIssued", "Certificate successfully issued")

	return ctrl.Result{}, nil
}

func (r *PodCertificateRequestReconciler) isPublicKeyTypeSupported(publicKeyBytes []byte) bool {

	// Parse the public key from the request - this handles both RSA and Ed25519
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		r.Log.Error(err, "Failed to parse PodCertificateRequest public key")
		return false
	}

	// Log the key type for debugging
	switch publicKey.(type) {
	case *rsa.PublicKey:
		fmt.Printf("Using RSA public key\n")
	case ed25519.PublicKey:
		fmt.Printf("Using Ed25519 public key\n")
	default:
		return false
	}

	return true
}

func (r *PodCertificateRequestReconciler) issuePodCertificate(ctx context.Context, pcr *capi.PodCertificateRequest, podCertificate *ca.PodCertificate) error {

	// Update certificate fields
	pcr.Status.CertificateChain = podCertificate.CertificateChain
	pcr.Status.NotBefore = &metav1.Time{Time: podCertificate.NotBefore}
	pcr.Status.NotAfter = &metav1.Time{Time: podCertificate.NotAfter}
	pcr.Status.BeginRefreshAt = &metav1.Time{Time: podCertificate.NotBefore.Add(10 * time.Minute)}

	r.setPodCertificateRequestStatusCondition(
		ctx, pcr,
		capi.PodCertificateRequestConditionTypeIssued,   // Condition type
		PodCertificateRequestConditionCertificateIssued, // Condition reason
		"Certificate successfully issued")               // Condition message

	if err := r.Status().Update(ctx, pcr); err != nil {
		r.Log.Error(err, "failed to update status")
		return err
	}

	return nil
}

func (r *PodCertificateRequestReconciler) updatePodCertificateRequestWithCertificate(ctx context.Context, pcr *capi.PodCertificateRequest, podCertificate *ca.PodCertificate) error {

	// Update certificate fields
	pcr.Status.CertificateChain = podCertificate.CertificateChain
	pcr.Status.NotBefore = &metav1.Time{Time: podCertificate.NotBefore}
	pcr.Status.NotAfter = &metav1.Time{Time: podCertificate.NotAfter}
	pcr.Status.BeginRefreshAt = &metav1.Time{Time: podCertificate.NotBefore.Add(10 * time.Minute)}

	r.setPodCertificateRequestStatusCondition(
		ctx, pcr,
		capi.PodCertificateRequestConditionTypeIssued,   // Condition type
		PodCertificateRequestConditionCertificateIssued, // Condition reason
		"Certificate successfully issued")               // Condition message

	if err := r.Status().Update(ctx, pcr); err != nil {
		r.Log.Error(err, "failed to update status")
		return err
	}

	return nil
}

func (r *PodCertificateRequestReconciler) updatePodAnnotations(ctx context.Context, pcr *capi.PodCertificateRequest, pod *corev1.Pod) error {

	// Add annotations to the pod
	if err := r.patchPodAnnotations(ctx, pod, map[string]string{
		fmt.Sprintf("%s-request-name-request-name", pcr.Spec.SignerName): pcr.Name,
		fmt.Sprintf("%s-request-name-issued-at", pcr.Spec.SignerName):    time.Now().Format(time.RFC3339),
	}); err != nil {
		r.Log.Error(err, "failed to patch annotations to pod", "podName", pod.Name)
	}

	return nil
}

func (r *PodCertificateRequestReconciler) setPodCertificateRequestStatusCondition(ctx context.Context, pcr *capi.PodCertificateRequest, conditionType, reason, message string) {

	pcr.Status.Conditions = []metav1.Condition{
		{
			Type:               conditionType,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             reason,
			Message:            message,
		},
	}

	if err := r.Status().Update(ctx, pcr); err != nil {
		r.Log.Error(err, "failed to update status with failure condition")
	}
}

func (r *PodCertificateRequestReconciler) getPodCertificateRequestAssociatedPod(ctx context.Context, pcr *capi.PodCertificateRequest) (*corev1.Pod, error) {

	// Fetch the pod
	var pod corev1.Pod
	podKey := types.NamespacedName{
		Name:      pcr.Spec.PodName,
		Namespace: pcr.Namespace,
	}

	// This condition should not ever happen - since kube-apiserver is responsible for creating the requests
	// and also validates the proof of possession during creation of the PodCertificateRequest we have this check as a fail safe
	if err := r.Get(ctx, podKey, &pod); err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", pcr.Namespace, pcr.Spec.PodName, err)
	}

	return &pod, nil
}

func (r *PodCertificateRequestReconciler) patchPodAnnotations(ctx context.Context, pod *corev1.Pod, annotations map[string]string) error {
	patch := client.MergeFrom(pod.DeepCopy())

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	for key, value := range annotations {
		pod.Annotations[key] = value
	}

	return r.Patch(ctx, pod, patch)
}

func (r *PodCertificateRequestReconciler) getPodAnnotation(pod *v1.Pod, annotationKey string) (string, bool) {
	if pod == nil || pod.Annotations == nil {
		return "", false
	}

	value, exists := pod.Annotations[annotationKey]
	return value, exists
}
