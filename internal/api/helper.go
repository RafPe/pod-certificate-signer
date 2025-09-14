package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
	// capi "k8s.io/api/certificates/v1alpha1"
)

// // IsCertificateRequestApproved returns true if a certificate request has the
// // "Approved" condition and no "Denied" conditions; false otherwise.
// func IsCertificateRequestApproved(csr *capi.CertificateSigningRequest) bool {
// 	approved, denied := GetCertApprovalCondition(&csr.Status)
// 	return approved && !denied
// }

// func GetCertApprovalCondition(status *capi.Certific) (approved bool, denied bool) {
// 	for _, c := range status.Conditions {
// 		if c.Type == capi.Cer {
// 			approved = true
// 		}
// 		if c.Type == capi.CertificateDenied {
// 			denied = true
// 		}
// 	}
// 	return
// }

func AddPodAnnotation(ctx context.Context, pod *corev1.Pod, certFingerprint string) error {
	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}

	pod.Annotations["cert.example.com/fingerprint"] = certFingerprint
	pod.Annotations["cert.example.com/issued-at"] = time.Now().Format(time.RFC3339)

	if err := r.Update(ctx, pod); err != nil {
		return fmt.Errorf("failed to update pod annotations: %w", err)
	}

	return nil
}

// ParseCSR decodes a PEM encoded CSR
// Copied from https://github.com/kubernetes/kubernetes/blob/v1.34.1/pkg/apis/certificates/v1/helpers.go
func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	return csr, nil
}
