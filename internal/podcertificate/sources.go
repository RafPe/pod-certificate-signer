package podcertificate

import (
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
)

// Source names where the value of one resolved certificate field came from.
type Source string

// Origins a resolved certificate field can take its value from.
const (
	// SourcePCR is the request spec.unverifiedUserAnnotations.
	SourcePCR Source = "pcr"
	// SourcePod is the deprecated pod-annotation fallback.
	SourcePod Source = "pod"
	// SourceCSR is the SANs in the kubelet-generated PKCS#10 CSR.
	SourceCSR Source = "csr"
	// SourceDefault is the signer's own default, which for IPAddresses and
	// URIs is an empty field.
	SourceDefault Source = "default"
)

// FieldSources records the [Source] of each requester-configurable field of a
// [Config].
type FieldSources struct {
	CommonName, DNSNames, IPAddresses, URIs, ExtKeyUsage, Duration, RefreshBefore Source
}

// SuppliedAnnotations returns the signer configuration annotations the
// requester supplied: every key annotationKey(signerName, suffix) present in
// pcr.Spec.UnverifiedUserAnnotations, plus, when allowPodAnnotations is true,
// those present only on the pod. Values are raw, before interpolation.
func SuppliedAnnotations(pcr *certificatesv1.PodCertificateRequest, pod *corev1.Pod, allowPodAnnotations bool) map[string]string {
	supplied := make(map[string]string)
	for _, suffix := range annotationSuffixes {
		key := annotationKey(pcr.Spec.SignerName, suffix)
		if value, ok := pcr.Spec.UnverifiedUserAnnotations[key]; ok {
			supplied[key] = value
			continue
		}
		if !allowPodAnnotations || pod == nil {
			continue
		}
		if value, ok := podAnnotation(pod, key); ok {
			supplied[key] = value
		}
	}
	return supplied
}
