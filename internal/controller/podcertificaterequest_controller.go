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
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/api"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/ca"

	capi "k8s.io/api/certificates/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	CA            *ca.CA
	SignerName    string
	ClusterFqdn   string
	EventRecorder record.EventRecorder
}

const (
	PodCertificateRequestConditionCertificateIssued                     string = "CertificateIssued"
	PodCertificateRequestConditionReasonPodNotFound                     string = "PodNotFound"
	PodCertificateRequestConditionReasonCertificateConfigurationInvalid string = "CertificateConfigurationInvalid"
)

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
			// UpdateFunc: func(e event.UpdateEvent) bool {

			// 	isPcrImmutable := api.IsPodCertificateRequestImmutable(e.ObjectNew.(*capi.PodCertificateRequest))

			// 	//TODO: Check here r.SignerName that the object matches our designation

			// 	// V(1) - Debug level (basic debugging)
			// 	r.Log.Info("Check if PodCertificateRequest is immutable", "immutable", isPcrImmutable, "event", "update", "request-name", e.ObjectNew.(*capi.PodCertificateRequest).Name)
			// 	return !isPcrImmutable // True for processing request ; False for skipping request

			// 	// // Simple check without method calls
			// 	// if newCert, ok := e.ObjectNew.(*capi.PodCertificateRequest); ok && newCert != nil {
			// 	// 	return newCert.Status.CertificateChain == ""
			// 	// }
			// 	// return true
			// },

			// Allow create events
			CreateFunc: func(e event.CreateEvent) bool {

				isPcrImmutable := api.IsPodCertificateRequestImmutable(e.Object.(*capi.PodCertificateRequest))

				// V(1) - Debug level (basic debugging)
				r.Log.Info("Check if PodCertificateRequest is immutable", "immutable", isPcrImmutable, "event", "create", "request-name", e.Object.(*capi.PodCertificateRequest).Name)
				return !isPcrImmutable // True for processing request ; False for skipping request

				// // Skip handling of immutable requests
				// if api.IsPodCertificateRequestImmutable(e.Object.(*capi.PodCertificateRequest)) {
				// 	// V(1) - Debug level (basic debugging)
				// 	r.Log.V(1).Info("Check if PodCertificateRequest is immutable", "immutable", true, "request-name", e.Object.(*capi.PodCertificateRequest).Name)
				// 	return true
				// }

				// return true

				//				return true
			},

			// // Allow delete events
			// DeleteFunc: func(e event.DeleteEvent) bool {
			// 	return true
			// },

			// // Allow generic events (e.g., external triggers)
			// GenericFunc: func(e event.GenericEvent) bool {
			// 	isPcrImmutable := api.IsPodCertificateRequestImmutable(e.Object.(*capi.PodCertificateRequest))

			// 	//TODO: Check here r.SignerName that the object matches our designation

			// 	// V(1) - Debug level (basic debugging)
			// 	r.Log.Info("Check if PodCertificateRequest is immutable", "immutable", isPcrImmutable, "event", "update", "request-name", e.Object.(*capi.PodCertificateRequest).Name)
			// 	return !isPcrImmutable // True for processing request ; False for skipping request
			// },
		}).
		Complete(r)
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	//r.Log = logf.Log.WithName("PodCertificateRequestReconciler").WithValues("request-name", req.Name)

	r.Log = logf.Log.WithValues("name", req.Name, "namespace", req.Namespace)
	// r.Log = logf.FromContext(ctx)

	// Retrieve the object from the ctx and map to PodCertificateRequest
	var pcr capi.PodCertificateRequest
	if err := r.Client.Get(ctx, req.NamespacedName, &pcr); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)

	}

	if api.IsPodCertificateRequestImmutable(&pcr) {
		r.Log.Info("PodCertificateRequest is immutable - skipping")
		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)

	}

	// Verify our signer name matches the one from request
	//TODO: Move to SetupWithManager func ?
	if !r.isSignerNameMatching(&pcr) {
		r.Log.Info("Signer name does not match - skipping")
		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)

	}

	// This should now be handled by our configuration of SetupMgr which drops immutable requests
	// Check if the PodCertificateRequest has already been issued - if so we skip the event
	if api.IsPodCertificateRequestIssued(&pcr) {
		r.Log.Info("PodCertificateRequest already issued - skipping")
		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)

	}

	// Check if the public key type is supported
	if !r.isPublicKeyTypeSupported(pcr.Spec.PKIXPublicKey) {
		err := fmt.Errorf("Unsupported public key type")

		r.Log.Error(err, "The key provided in the PodCertificateRequest is not a supported type")

		r.setPodCertificateRequestStatusCondition(
			&pcr,
			capi.PodCertificateRequestConditionTypeFailed,         // Condition type
			capi.PodCertificateRequestConditionUnsupportedKeyType, // Condition reason
			"Unsupported public key type")                         // Condition message

		r.clearPodCertificateRequestStatusFields(&pcr)
		r.updatePodCertificateRequestStatus(ctx, &pcr)

		r.EventRecorder.Event(
			&pcr,
			corev1.EventTypeWarning,
			capi.PodCertificateRequestConditionUnsupportedKeyType,
			"Unsupported public key type")

		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
	}

	// Retrieve the pod associated with the PodCertificateRequest - if we fail to do so we are facing
	// problems which needs to be addressed - as we cannot issue a certificate without a pod :)
	pod, err := r.getPodCertificateRequestAssociatedPod(ctx, &pcr)
	if err != nil {
		r.Log.Error(err, "Failed to find associated pod", "podName", pcr.Spec.PodName)

		r.setPodCertificateRequestStatusCondition(
			&pcr,
			capi.PodCertificateRequestConditionTypeFailed,        // Condition type
			PodCertificateRequestConditionReasonPodNotFound,      // Condition reason
			"Pod for associated PodCertificateRequest not found") // Condition message

		r.clearPodCertificateRequestStatusFields(&pcr)
		r.updatePodCertificateRequestStatus(ctx, &pcr)

		r.EventRecorder.Event(
			&pcr,
			corev1.EventTypeWarning,
			PodCertificateRequestConditionReasonPodNotFound,
			"Pod for associated PodCertificateRequest not found")

		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
	}

	r.Log.Info("Found associated pod for PodCertificateRequest", "podName", pod.Name)

	// Extract the configuration for the certificate from the pod annotations or use defailts if none.
	podCertificateRequestConfiguration := r.getPodCertificateRequestConfiguration(&pcr, pod)

	// Issue certificate using the public key from the request
	podCertificate, err := r.CA.IssueCertificateForPublicKey(
		pcr.Spec.PKIXPublicKey,
		podCertificateRequestConfiguration)
	if err != nil {
		r.Log.Error(err, "Failed to issue certificate", "podName", pod.Name)
		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
	}

	// Set the certificate in the PodCertificateRequest and update annotations on the pod
	err = r.setPodCertificateRequestWithCertificate(ctx, &pcr, podCertificate)
	if err != nil {
		r.Log.Error(err, "Certificate configuration is invalid!")

		r.setPodCertificateRequestStatusCondition(
			&pcr,
			capi.PodCertificateRequestConditionTypeFailed,                       // Condition type
			PodCertificateRequestConditionReasonCertificateConfigurationInvalid, // Condition reason
			"Pod for associated PodCertificateRequest not found")                // Condition message

		r.clearPodCertificateRequestStatusFields(&pcr)
		r.updatePodCertificateRequestStatus(ctx, &pcr)

		r.EventRecorder.Event(
			&pcr,
			corev1.EventTypeWarning,
			PodCertificateRequestConditionReasonCertificateConfigurationInvalid,
			"Certificate configuration is invalid")

		return ctrl.Result{}, nil // DON'T REQUEUE - Terminal failure (log but don't retry)
	}

	r.setDefaultPodAnnotations(ctx, &pcr, pod)

	// Successfully issued certificate
	r.Log.Info("Certificate successfully issued")
	r.EventRecorder.Event(
		&pcr,
		corev1.EventTypeNormal,
		capi.PodCertificateRequestConditionTypeIssued,
		"Certificate successfully issued")

	return ctrl.Result{}, nil // DON'T REQUEUE - Terminal success

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
		r.Log.Info("Using RSA public key")
	case ed25519.PublicKey:
		r.Log.Info("Using Ed25519 public key")
	default:
		return false
	}

	return true
}

func (r *PodCertificateRequestReconciler) isSignerNameMatching(pcr *capi.PodCertificateRequest) bool {
	return pcr.Spec.SignerName == r.SignerName
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

func (r *PodCertificateRequestReconciler) setPodCertificateRequestWithCertificate(ctx context.Context, pcr *capi.PodCertificateRequest, podCertificate *ca.PodCertificate) error {

	// We update only fields required
	beginRefreshAt := podCertificate.NotAfter.Add(-podCertificate.Config.RefreshBefore)

	r.Log.V(1).Info("Setting the certificate in the PodCertificateRequest",
		"podName", pcr.Spec.PodName,
		"commonName", podCertificate.Config.CommonName,
		"dnsNames", podCertificate.Config.DNSNames,
		"duration", podCertificate.Config.Duration.String(),
		"refreshBefore", podCertificate.Config.RefreshBefore.String(),
		"beginRefreshAt", beginRefreshAt.Format(time.RFC1123Z))

	pcr.Status.CertificateChain = podCertificate.CertificateChain
	pcr.Status.NotBefore = &metav1.Time{Time: podCertificate.NotBefore}
	pcr.Status.NotAfter = &metav1.Time{Time: podCertificate.NotAfter}
	pcr.Status.BeginRefreshAt = &metav1.Time{Time: beginRefreshAt}

	r.setPodCertificateRequestStatusCondition(
		pcr,
		capi.PodCertificateRequestConditionTypeIssued,   // Condition type
		PodCertificateRequestConditionCertificateIssued, // Condition reason
		"Certificate successfully issued")               // Condition message

	if err := r.Status().Update(ctx, pcr); err != nil {
		r.Log.Error(err, "failed to update the PodCertificateRequest status")
		return err
	}

	return nil
}

func (r *PodCertificateRequestReconciler) setDefaultPodAnnotations(ctx context.Context, pcr *capi.PodCertificateRequest, pod *corev1.Pod) error {

	// Add annotations to the pod
	if err := r.patchPodAnnotations(ctx, pod, map[string]string{
		fmt.Sprintf("%s-request-name", r.SignerName): pcr.Name,
		fmt.Sprintf("%s-issued-at", r.SignerName):    time.Now().Format(time.RFC3339),
	}); err != nil {
		r.Log.Error(err, "failed to patch annotations to pod", "podName", pod.Name)
	}

	return nil
}

func (r *PodCertificateRequestReconciler) clearPodCertificateRequestStatusFields(pcr *capi.PodCertificateRequest) {

	pcr.Status.CertificateChain = ""
	pcr.Status.NotBefore = nil
	pcr.Status.NotAfter = nil
	pcr.Status.BeginRefreshAt = nil

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

func (r *PodCertificateRequestReconciler) updatePodCertificateRequestStatus(ctx context.Context, pcr *capi.PodCertificateRequest) error {

	err := r.Status().Update(ctx, pcr)
	if err != nil {
		r.Log.Error(err, "failed to update status with failure condition")
		return err
	}

	return nil
}

func (r *PodCertificateRequestReconciler) getPodCertificateRequestConfiguration(pcr *capi.PodCertificateRequest, pod *corev1.Pod) *ca.PodCertificateConfig {

	// V(0) - Info level (default, always shown)
	r.Log.Info("Generating the certificate configuration for the PodCertificateRequest")

	// // V(1) - Debug level (basic debugging)
	// r.Log.V(1).Info("Processing certificate request", "podName", pod.Name)

	// // V(2) - Trace level (detailed debugging)
	// r.Log.V(2).Info("Annotation values", "commonName", commonName, "duration", duration)

	// // V(3) - Very verbose (internal state)
	// r.Log.V(3).Info("Internal state", "certReq", certReq)

	// signer/name-cn                  => common name for the certificate
	// signer/name-san                 => dns names for the certificate
	// signer/name-duration            => duration for the certificate
	// signer/name-refresh-before      => refresh time before the certificate expires
	//TODO: we need testing on various combination of time/duration and refresh to make sure we are alligned with requirements of the API server
	//TODO: Add these default annotations into a static map for easy retrieval ?

	defaultCertificateDuration := 1 * time.Hour       // default value for certificate duration
	certificateDuration := defaultCertificateDuration // set the value for default if we fail to parse from annotations

	defaultRefreshBefore := 30 * time.Minute // default value for refresh before
	refreshBefore := defaultRefreshBefore    // set the value for default if we fail to parse from annotations

	// Retrieve the common name from the pod annotation
	// V(1) - Debug level (basic debugging)
	r.Log.V(1).Info("Retrieving certificate common name from the annotations", "podName", pod.Name)

	commonName := r.getAnnotationOrDefault(pod,
		fmt.Sprintf("%s-cn", r.SignerName),
		pcr.Spec.PodName,
		"cn")

	// Retrieve the duration from the pod annotation
	// V(1) - Debug level (basic debugging)
	r.Log.V(1).Info("Retrieving certificate duration time from the annotations", "podName", pod.Name)

	durationStr := r.getAnnotationOrDefault(pod,
		fmt.Sprintf("%s-duration", r.SignerName),
		"", // empty string means no annotation found
		"duration")

	if durationStr != "" {
		parsedCertificateDuration, err := time.ParseDuration(durationStr)
		if err != nil {
			r.Log.V(1).Info("Could not parse duration from annotation - using default value", "podName", pod.Name)
		} else {
			certificateDuration = parsedCertificateDuration
			r.Log.V(1).Info("Parsed duration from annotation - using the supplied value", "podName", pod.Name, "duration", certificateDuration.String())
		}
	}

	// Retrieve the duration from the pod annotation
	// V(1) - Debug level (basic debugging)
	r.Log.V(1).Info("Retrieving certificate refresh window time from the annotations", "podName", pod.Name)

	refreshBeforeStr := r.getAnnotationOrDefault(pod,
		fmt.Sprintf("%s-refresh", r.SignerName),
		"", // empty string means no annotation found
		"refresh-before")

	if refreshBeforeStr != "" {
		parsedCertificateRefreshDuration, err := time.ParseDuration(refreshBeforeStr)
		if err != nil {
			r.Log.V(1).Info("Could not parse refresh window from annotation - using default value", "podName", pod.Name)
		} else {
			refreshBefore = parsedCertificateRefreshDuration
			r.Log.V(1).Info("Parsed refresh window from annotation - using the supplied value", "podName", pod.Name, "refresh-before", refreshBefore.String())
		}
	}

	dnsNames := r.getCommaSeparatedAnnotation(pod,
		fmt.Sprintf("%s-san", r.SignerName),
		"dnsNames")

	pcConfig := &ca.PodCertificateConfig{
		CommonName:    commonName,
		DNSNames:      dnsNames,
		Duration:      certificateDuration,
		RefreshBefore: refreshBefore,
	}
	//TODO: Add method to validate the integrity of the certificate configuration?!

	return pcConfig
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

func (r *PodCertificateRequestReconciler) getPodAnnotation(pod *corev1.Pod, annotationKey string) (string, bool) {
	if pod == nil || pod.Annotations == nil {
		return "", false
	}

	value, exists := pod.Annotations[annotationKey]
	return value, exists
}

// getAnnotationOrDefault retrieves an annotation from the pod or returns a default value if the annotation is not found
func (r *PodCertificateRequestReconciler) getAnnotationOrDefault(pod *corev1.Pod, annotationKey, defaultValue, fieldName string) string {
	value, exists := r.getPodAnnotation(pod, annotationKey)
	if !exists {
		r.Log.V(1).Info("No annotation found - using default",
			"field", fieldName,
			"key", annotationKey,
			"default", defaultValue)
		return defaultValue
	}

	r.Log.V(1).Info("Annotation found - using supplied value",
		"field", fieldName,
		"key", annotationKey,
		"value", value)
	return value
}

func (r *PodCertificateRequestReconciler) getCommaSeparatedAnnotation(pod *corev1.Pod, annotationKey, fieldName string) []string {
	value := r.getAnnotationOrDefault(pod, annotationKey, "", fieldName)
	if value == "" {
		return []string{}
	}

	var result []string
	for _, dns := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(dns); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
