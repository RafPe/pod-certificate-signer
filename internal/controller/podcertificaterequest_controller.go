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

	"github.com/go-logr/logr"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/ca"
	certificatesv1alpha1 "k8s.io/api/certificates/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
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

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=podcertificaterequests/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch;update;patch

func (r *PodCertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1alpha1.PodCertificateRequest{}).
		WithEventFilter(predicate.Funcs{
			UpdateFunc: func(e event.UpdateEvent) bool {
				// Simple check without method calls
				if newCert, ok := e.ObjectNew.(*certificatesv1alpha1.PodCertificateRequest); ok && newCert != nil {
					return newCert.Status.CertificateChain == ""
				}
				return true
			},
			// UpdateFunc: func(e event.UpdateEvent) bool {
			// 	newCert := e.ObjectNew.(*certificatesv1alpha1.PodCertificateRequest)

			// 	return !r.isAlreadyIssued(newCert)

			// 	// if newCert, ok := e.ObjectNew.(*certificatesv1alpha1.PodCertificateRequest); ok {
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
// TODO(user): Modify the Reconcile function to compare the state specified by
// the PodCertificateRequest object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.21.0/pkg/reconcile
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log = logf.FromContext(ctx)

	// Retrieve the object from the ctx and map to PodCertificateRequest
	var certReq certificatesv1alpha1.PodCertificateRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &certReq); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, fmt.Errorf("Error %q getting PodCertificateRequest", err)
	}
	r.Log.Info("Processing PodCertificateRequest", "name", certReq.Name, "namespace", certReq.Namespace, "signer-name", certReq.Spec.SignerName)

	// Check if certificate has already issued
	if r.isAlreadyIssued(&certReq) {
		r.Log.Info("PodCertificateRequest already issued", "name", certReq.Name, "namespace", certReq.Namespace)
		return ctrl.Result{}, nil
	}

	// Get the associated pod - this is optional for us to retrieve custom annotations if exist
	pod, err := r.getAssociatedPod(ctx, &certReq)
	if err != nil {
		r.Log.Error(err, "Failed to get associated pod")
		r.setFailedCondition(ctx, &certReq, "PodNotFound", err.Error())
		return ctrl.Result{}, nil // Don't retry if pod doesn't exist
	}
	r.Log.Info("Found associated pod for PodCertificateRequest", "name", certReq.Name, "namespace", certReq.Namespace, "pod", pod.Name)

	// if dnsNames, found := r.getPodAnnotation(pod, "coolcert.example.com/foo-san"); found {
	// 	// Use annotation value
	// 	r.Log.Info("Using DNS names from annotation", "value", dnsNames)
	// } else {
	// 	// Use default
	// 	dnsNames = []string{}
	// 	r.Log.Info("No SANs found in pod annotations, using empty []string", "value", dnsNames)
	// }

	r.Log.Info("Generating x509 certificate request ... ", "signer-name", certReq.Spec.SignerName)

	// Issue certificate
	commonName := certReq.Spec.PodName                    // Adjust based on your CRD spec
	dnsNames := []string{certReq.Spec.ServiceAccountName} // Adjust based on your CRD spec
	duration := 1 * time.Hour                             // 1 hour for testing

	// Issue certificate using the public key from the request
	certificateChain, notBefore, notAfter, err := r.CA.IssueCertificateForPublicKey(
		certReq.Spec.PKIXPublicKey,
		commonName,
		dnsNames,
		duration,
	)
	if err != nil {
		r.Log.Error(err, "failed to issue certificate")
		r.setFailedCondition(ctx, &certReq, "CertificateIssueFailed", fmt.Sprintf("Failed to issue certificate: %v", err))
		r.EventRecorder.Event(&certReq, v1.EventTypeWarning, "CertificateIssueFailed", "Failed to issue certificate")
		return ctrl.Result{}, err
	}

	// Update certificate fields
	certReq.Status.CertificateChain = certificateChain
	certReq.Status.NotBefore = &metav1.Time{Time: notBefore}
	certReq.Status.NotAfter = &metav1.Time{Time: notAfter}
	certReq.Status.BeginRefreshAt = &metav1.Time{Time: notBefore.Add(10 * time.Minute)}

	// Add Issued condition
	certReq.Status.Conditions = []metav1.Condition{
		{
			Type:               "Issued",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "CertificateIssued",
			Message:            "Certificate successfully issued",
		},
	}

	// Update the status
	if err := r.Status().Update(ctx, &certReq); err != nil {
		r.Log.Error(err, "failed to update status")
		return ctrl.Result{}, err
	}

	// Successfully issued certificate
	r.Log.Info("Certificate successfully issued")
	r.EventRecorder.Event(&certReq, v1.EventTypeNormal, "CertificateIssues", "Certificate successfully issued")

	return ctrl.Result{}, nil
}

func (r *PodCertificateRequestReconciler) setFailedCondition(ctx context.Context, certReq *certificatesv1alpha1.PodCertificateRequest, reason, message string) {
	certReq.Status.Conditions = []metav1.Condition{
		{
			Type:               "Failed",
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             reason,
			Message:            message,
		},
	}

	if err := r.Status().Update(ctx, certReq); err != nil {
		r.Log.Error(err, "failed to update status with failure condition")
	}
}

func (r *PodCertificateRequestReconciler) getAssociatedPod(ctx context.Context, certReq *certificatesv1alpha1.PodCertificateRequest) (*corev1.Pod, error) {
	// Validate required fields
	if certReq.Spec.PodName == "" {
		return nil, fmt.Errorf("podName is empty")
	}
	if certReq.Namespace == "" {
		return nil, fmt.Errorf("namespace is empty")
	}

	// Fetch the pod
	var pod v1.Pod
	podKey := types.NamespacedName{
		Name:      certReq.Spec.PodName,
		Namespace: certReq.Namespace,
	}

	// This condition should not ever happen - since kube-apiserver is responsible for creating the requests
	// and also validates the proof of possession during creation of the PodCertificateRequest we have this check as a fail safe
	if err := r.Get(ctx, podKey, &pod); err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", certReq.Namespace, certReq.Spec.PodName, err)
	}

	// Validate UID matches (security check)
	if certReq.Spec.PodUID != "" && string(pod.UID) != string(certReq.Spec.PodUID) {
		return nil, fmt.Errorf("pod UID mismatch: expected %s, got %s", certReq.Spec.PodUID, pod.UID)
	}

	return &pod, nil
}

func (r *PodCertificateRequestReconciler) isAlreadyIssued(certReq *certificatesv1alpha1.PodCertificateRequest) bool {
	if certReq == nil {
		return false
	}

	// Status might not be initialized on new objects
	if certReq.Status.Conditions == nil {
		return false
	}

	// Avoid range over nil slice
	for i := 0; i < len(certReq.Status.Conditions); i++ {
		condition := certReq.Status.Conditions[i]
		if condition.Type == "Issued" && condition.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// func (r *PodCertificateRequestReconciler) getPodAnnotation(pod *v1.Pod, annotationKey string) (string, bool) {
// 	if pod == nil || pod.Annotations == nil {
// 		return "", false
// 	}

// 	value, exists := pod.Annotations[annotationKey]
// 	return value, exists
// }
