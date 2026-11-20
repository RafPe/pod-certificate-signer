package podcertificate

import (
	"context"
	"maps"
	"testing"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
)

// verifiedTestDNSName is a default DNS name of testPod, so it clears the
// verified-identity allowlist from every source.
const verifiedTestDNSName = "mypod.myns.pod.cluster.local"

func TestConfigSourcesDefaults(t *testing.T) {
	config, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), testCSR(nil), Options{})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	want := FieldSources{
		CommonName:    SourceDefault,
		DNSNames:      SourceDefault,
		IPAddresses:   SourceDefault,
		URIs:          SourceDefault,
		ExtKeyUsage:   SourceDefault,
		Duration:      SourceDefault,
		RefreshBefore: SourceDefault,
	}
	if config.Sources != want {
		t.Errorf("Sources = %+v, want %+v", config.Sources, want)
	}
}

func TestConfigSourcesPerOrigin(t *testing.T) {
	cases := []struct {
		name  string
		pcr   map[string]string
		pod   map[string]string
		csr   *CSR
		opts  Options
		check func(t *testing.T, got FieldSources)
	}{
		{
			name: "san in the request",
			pcr:  map[string]string{testSignerName + "-san": verifiedTestDNSName},
			check: func(t *testing.T, got FieldSources) {
				if got.DNSNames != SourcePCR {
					t.Errorf("DNSNames source = %q, want %q", got.DNSNames, SourcePCR)
				}
			},
		},
		{
			name: "san only on the pod",
			pod:  map[string]string{testSignerName + "-san": verifiedTestDNSName},
			opts: Options{AllowPodAnnotations: true},
			check: func(t *testing.T, got FieldSources) {
				if got.DNSNames != SourcePod {
					t.Errorf("DNSNames source = %q, want %q", got.DNSNames, SourcePod)
				}
			},
		},
		{
			name: "CSR DNS names without an annotation",
			csr:  &CSR{DNSNames: []string{verifiedTestDNSName}},
			opts: Options{HonorCSRSANs: true},
			check: func(t *testing.T, got FieldSources) {
				if got.DNSNames != SourceCSR {
					t.Errorf("DNSNames source = %q, want %q", got.DNSNames, SourceCSR)
				}
			},
		},
		{
			name: "duration in the request",
			pcr:  map[string]string{testSignerName + "-duration": "2h"},
			check: func(t *testing.T, got FieldSources) {
				if got.Duration != SourcePCR {
					t.Errorf("Duration source = %q, want %q", got.Duration, SourcePCR)
				}
				if got.RefreshBefore != SourceDefault {
					t.Errorf("RefreshBefore source = %q, want %q", got.RefreshBefore, SourceDefault)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config, err := NewConfig(context.Background(), testPCR(tc.pcr), testPod(tc.pod), testCSR(tc.csr), tc.opts)
			if err != nil {
				t.Fatalf("NewConfig: %v", err)
			}
			tc.check(t, config.Sources)
		})
	}
}

func TestSuppliedAnnotations(t *testing.T) {
	cnKey := testSignerName + "-cn"
	durationKey := testSignerName + "-duration"

	cases := []struct {
		name     string
		pcr      *certificatesv1.PodCertificateRequest
		pod      *corev1.Pod
		allowPod bool
		want     map[string]string
	}{
		{
			name:     "request key wins over the same pod key",
			pcr:      testPCR(map[string]string{cnKey: "from-request"}),
			pod:      testPod(map[string]string{cnKey: "from-pod", durationKey: "2h"}),
			allowPod: true,
			want:     map[string]string{cnKey: "from-request", durationKey: "2h"},
		},
		{
			name:     "pod key absent when pod annotations are not allowed",
			pcr:      testPCR(map[string]string{cnKey: "from-request"}),
			pod:      testPod(map[string]string{durationKey: "2h"}),
			allowPod: false,
			want:     map[string]string{cnKey: "from-request"},
		},
		{
			name:     "key of another signer absent",
			pcr:      testPCR(map[string]string{testSignerName + "-client-cn": "x"}),
			pod:      testPod(map[string]string{testSignerName + "-client-eku": "client", "example.org/other-cn": "x", cnKey: "${pod.name}"}),
			allowPod: true,
			want:     map[string]string{cnKey: "${pod.name}"},
		},
		{
			name:     "nil pod",
			pcr:      testPCR(map[string]string{durationKey: "3h"}),
			pod:      nil,
			allowPod: true,
			want:     map[string]string{durationKey: "3h"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SuppliedAnnotations(tc.pcr, tc.pod, tc.allowPod)
			if !maps.Equal(got, tc.want) {
				t.Errorf("SuppliedAnnotations = %v, want %v", got, tc.want)
			}
		})
	}
}
