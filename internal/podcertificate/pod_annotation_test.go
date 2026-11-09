package podcertificate

import (
	"context"
	"testing"
)

// Pod annotations are shared with every other consumer of the pod, so unknown
// keys there are never a reason to deny. In particular a signer-name prefix
// cannot be used to spot typos: example.com/pod-client-eku belongs to a signer
// named example.com/pod-client, and denying it would break example.com/pod's
// own request on a pod that uses both signers.
func TestPodAnnotationsUnknownKeysIgnored(t *testing.T) {
	cases := []struct {
		name        string
		annotations map[string]string
	}{
		{"key of a signer whose name extends this one", map[string]string{testSignerName + "-client-eku": "client"}},
		{"unknown key under the signer prefix", map[string]string{testSignerName + "-sna": "x.example.org"}},
		{"unrelated annotation", map[string]string{"prometheus.io/scrape": "true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPodCertificateConfig(context.Background(), testPCR(nil), testPod(tc.annotations), nil, Options{}); err != nil {
				t.Fatalf("NewPodCertificateConfig(pod annotations %v) error = %v, want nil", tc.annotations, err)
			}
		})
	}
}

// A value read from a pod annotation still configures the certificate, with
// the request annotation winning when both are set.
func TestPodAnnotationFallbackAndPrecedence(t *testing.T) {
	podOnly, err := NewPodCertificateConfig(context.Background(), testPCR(nil),
		testPod(map[string]string{testSignerName + "-duration": "2h"}), nil, Options{})
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if podOnly.Duration.Hours() != 2 {
		t.Errorf("Duration = %v, want 2h from the pod annotation", podOnly.Duration)
	}

	both, err := NewPodCertificateConfig(context.Background(),
		testPCR(map[string]string{testSignerName + "-duration": "3h"}),
		testPod(map[string]string{testSignerName + "-duration": "2h"}), nil, Options{})
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if both.Duration.Hours() != 3 {
		t.Errorf("Duration = %v, want 3h: the request annotation takes precedence", both.Duration)
	}
}

// duration and refresh are interpolated like every other annotation: a
// placeholder is either expanded or, with interpolation off, denied - never
// handed to the duration parser as a literal.
func TestDurationAnnotationsInterpolate(t *testing.T) {
	pcr := testPCR(map[string]string{testSignerName + "-duration": "${pod.name}"})
	pcr.Spec.PodName = "4h"
	pod := testPod(nil)
	pod.Name = "4h"

	config, err := NewPodCertificateConfig(context.Background(), pcr, pod, nil, Options{EnableInterpolation: true})
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if config.Duration.Hours() != 4 {
		t.Errorf("Duration = %v, want the interpolated 4h", config.Duration)
	}

	_, err = NewPodCertificateConfig(context.Background(), pcr, pod, nil, Options{})
	if err == nil {
		t.Fatal("want a denial for a ${...} duration with interpolation disabled, got nil")
	}
}
