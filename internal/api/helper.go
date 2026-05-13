package api

import (
	"context"
	"fmt"

	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func IsPodCertificateRequestImmutable(pcr *capiv1beta1.PodCertificateRequest) bool {
	return GetPodCertificateRequestConditionType(&pcr.Status) != ""
}

func IsPodCertificateStatusIssued(pcr *capiv1beta1.PodCertificateRequest) bool {
	return GetPodCertificateRequestConditionType(&pcr.Status) == capiv1beta1.PodCertificateRequestConditionTypeIssued
}

func GetPodCertificateRequestConditionType(status *capiv1beta1.PodCertificateRequestStatus) string {
	// Fail safe if the object would be set to nil
	if status.Conditions == nil {
		return ""
	}

	// // Well-known condition types for PodCertificateRequests
	// const (
	// 	// Denied indicates the request was denied by the signer.
	// 	PodCertificateRequestConditionTypeDenied string = "Denied"
	// 	// Failed indicates the signer failed to issue the certificate.
	// 	PodCertificateRequestConditionTypeFailed string = "Failed"
	// 	// Issued indicates the certificate has been issued.
	// 	PodCertificateRequestConditionTypeIssued string = "Issued"
	// )

	for _, c := range status.Conditions {
		if c.Type == capiv1beta1.PodCertificateRequestConditionTypeIssued {
			return capiv1beta1.PodCertificateRequestConditionTypeIssued
		}
		if c.Type == capiv1beta1.PodCertificateRequestConditionTypeDenied {
			return capiv1beta1.PodCertificateRequestConditionTypeDenied
		}
		if c.Type == capiv1beta1.PodCertificateRequestConditionTypeFailed {
			return capiv1beta1.PodCertificateRequestConditionTypeFailed
		}
	}

	return ""
}

func GetPodAnnotation(pod *corev1.Pod, annotationKey string) (string, bool) {
	if pod == nil || pod.Annotations == nil {
		return "", false
	}

	value, exists := pod.Annotations[annotationKey]
	if !exists || value == "" {
		return "", false
	}

	return value, true
}

func GetPod(ctx context.Context, c client.Client, podName, podNamespace string) (*corev1.Pod, error) {

	var pod corev1.Pod
	podKey := types.NamespacedName{
		Name:      podName,
		Namespace: podNamespace,
	}

	if err := c.Get(ctx, podKey, &pod); err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", podNamespace, podName, err)
	}

	return &pod, nil
}
