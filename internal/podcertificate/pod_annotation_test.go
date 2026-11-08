package podcertificate

import (
	"context"
	"testing"
)

// The deprecated pod-annotation path is validated like the request path: a
// pod annotation that carries the signer's prefix but names no known item is
// a typo the request would have been denied for, so it is denied here too
// rather than silently falling back to the defaults. Annotations under any
// other prefix belong to other consumers of the pod and are ignored.
func TestPodAnnotationsUnknownSignerKeyDenied(t *testing.T) {
	cases := []struct {
		name        string
		annotations map[string]string
		wantErr     bool
	}{
		{"typo under the signer prefix", map[string]string{testSignerName + "-sna": "x.example.org"}, true},
		{"known key under the signer prefix", map[string]string{testSignerName + "-eku": "client"}, false},
		{"unrelated annotation", map[string]string{"prometheus.io/scrape": "true"}, false},
		{"signer prefix without the separator", map[string]string{testSignerName + "sna": "x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPodCertificateConfig(context.Background(), testPCR(nil), testPod(tc.annotations), nil, Options{})
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("NewPodCertificateConfig(pod annotations %v) error = %v, want error = %t", tc.annotations, err, tc.wantErr)
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
