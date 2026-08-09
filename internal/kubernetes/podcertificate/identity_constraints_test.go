package podcertificate

import (
	"crypto/x509"
	"reflect"
	"strings"
	"testing"

	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/types"
)

// verifiedPCR returns a request whose verified fields (pod name/namespace/
// serviceAccountName) are populated, so identity values derived from them can
// be exercised.
func verifiedPCR(userAnnotations map[string]string) *capiv1beta1.PodCertificateRequest {
	pcr := testPCR(userAnnotations)
	pcr.Spec.ServiceAccountName = "mysa"
	pcr.Spec.PodUID = types.UID("abc-123")
	return pcr
}

// (1) + (4): By default, identity values that are not derived from verified PCR
// fields must be denied. A pod must not be able to mint a certificate for an
// identity (DNS name, CN, URI or IP) it cannot prove it owns.
func TestUnverifiedIdentitiesDeniedByDefault(t *testing.T) {
	cases := []struct {
		name        string
		annotations map[string]string
		opts        Options
	}{
		{"literal cn", map[string]string{testSignerName + "-cn": "evil.example.com"}, Options{}},
		{"literal san", map[string]string{testSignerName + "-san": "evil.example.com"}, Options{}},
		{"literal uri", map[string]string{testSignerName + "-uris": "spiffe://evil.example.com/x"}, Options{}},
		{"annotation ip-san", map[string]string{testSignerName + "-ip-san": "10.0.0.1"}, Options{}},
		{
			"interpolation with injected literal suffix",
			map[string]string{testSignerName + "-san": "${pod.name}.evil.example.com"},
			Options{EnableInterpolation: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcr := verifiedPCR(tc.annotations)
			if _, err := NewPodCertificateConfig(pcr, testPod(nil), tc.opts, nil, 0); err == nil {
				t.Fatalf("want denial for unverified identity %v, got nil", tc.annotations)
			}
		})
	}
}

// (2): Identity values built only from verified PCR fields are accepted, even
// with the constraint enabled (the default).
func TestVerifiedIdentitiesAccepted(t *testing.T) {
	pcr := verifiedPCR(map[string]string{
		testSignerName + "-cn":  "${pod.name}",
		testSignerName + "-san": "${pod.serviceAccountName}.${pod.namespace}",
	})

	config, err := NewPodCertificateConfig(pcr, testPod(nil), Options{EnableInterpolation: true}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if config.CommonName != "mypod" {
		t.Errorf("CommonName = %q, want verified pod name", config.CommonName)
	}
	if len(config.DNSNames) != 1 || config.DNSNames[0] != "mysa.myns" {
		t.Errorf("DNSNames = %v, want [mysa.myns]", config.DNSNames)
	}
}

// (3): The default extended key usage must be ServerAuth only; ClientAuth is an
// explicit opt-in via the eku annotation.
func TestDefaultEKUServerAuthOnly(t *testing.T) {
	config, err := NewPodCertificateConfig(testPCR(nil), testPod(nil), Options{}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if !reflect.DeepEqual(config.ExtKeyUsage, want) {
		t.Errorf("default ExtKeyUsage = %v, want ServerAuth only %v", config.ExtKeyUsage, want)
	}

	optIn, err := NewPodCertificateConfig(testPCR(map[string]string{testSignerName + "-eku": "client"}), testPod(nil), Options{}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if !reflect.DeepEqual(optIn.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Errorf("opt-in ExtKeyUsage = %v, want ClientAuth", optIn.ExtKeyUsage)
	}
}

// (5): A pod name longer than the 64-character RFC 5280 common name limit must
// still yield a configuration whose default CN passes validation (SAN-only or
// truncated), rather than an un-issuable request.
func TestLongPodNameYieldsValidDefaultCN(t *testing.T) {
	pod := testPod(nil)
	pod.Name = strings.Repeat("a", 65)
	pcr := testPCR(nil)
	pcr.Spec.PodName = pod.Name

	config, err := NewPodCertificateConfig(pcr, pod, Options{}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if len(config.CommonName) > 64 {
		t.Errorf("CommonName length = %d, want <= 64 for a long pod name", len(config.CommonName))
	}
	if err := config.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for a long pod name default CN", err)
	}
}
