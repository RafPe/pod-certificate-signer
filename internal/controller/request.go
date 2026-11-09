package controller

import (
	"context"
	"fmt"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// isTerminal reports whether the request already carries a terminal condition
// (Issued, Denied or Failed). kube-apiserver makes such a request immutable,
// so there is nothing left for the reconciler to do with it.
func isTerminal(pcr *certificatesv1.PodCertificateRequest) bool {
	return terminalConditionType(&pcr.Status) != ""
}

// terminalConditionType returns the terminal condition type (Issued, Denied or
// Failed) recorded on the request status, or an empty string when the request
// has not reached a terminal state yet.
func terminalConditionType(status *certificatesv1.PodCertificateRequestStatus) string {
	for _, c := range status.Conditions {
		switch c.Type {
		case certificatesv1.PodCertificateRequestConditionTypeIssued,
			certificatesv1.PodCertificateRequestConditionTypeDenied,
			certificatesv1.PodCertificateRequestConditionTypeFailed:
			return c.Type
		}
	}

	return ""
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
