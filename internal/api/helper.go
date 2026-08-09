package api

import (
	"context"
	"fmt"

	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// IsPodCertificateRequestImmutable reports whether the request already carries
// a terminal condition (Issued, Denied or Failed) and can no longer be updated.
func IsPodCertificateRequestImmutable(pcr *capiv1beta1.PodCertificateRequest) bool {
	return GetPodCertificateRequestConditionType(&pcr.Status) != ""
}

// IsPodCertificateStatusIssued reports whether the request has been issued.
func IsPodCertificateStatusIssued(pcr *capiv1beta1.PodCertificateRequest) bool {
	return GetPodCertificateRequestConditionType(&pcr.Status) == capiv1beta1.PodCertificateRequestConditionTypeIssued
}

// GetPodCertificateRequestConditionType returns the terminal condition type
// (Issued, Denied or Failed) recorded on the request status, or an empty
// string when the request has not reached a terminal state yet.
func GetPodCertificateRequestConditionType(status *capiv1beta1.PodCertificateRequestStatus) string {
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

// GetPodAnnotation returns the value of the given pod annotation. It reports
// false when the pod is nil, or the annotation is absent or empty.
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

// GetPod fetches the pod with the given name and namespace. It takes a
// client.Reader so callers can pass either the cached manager client or the
// cache-bypassing APIReader.
func GetPod(ctx context.Context, c client.Reader, podName, podNamespace string) (*corev1.Pod, error) {
	var pod corev1.Pod
	podKey := types.NamespacedName{
		Name:      podName,
		Namespace: podNamespace,
	}

	if err := c.Get(ctx, podKey, &pod); err != nil {
		return nil, fmt.Errorf("get pod %s/%s: %w", podNamespace, podName, err)
	}

	return &pod, nil
}
