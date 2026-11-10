package podcertificate

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testSignerName = "example.org/signer"

// testPublicKey is a fixed Ed25519 key. NewConfig requires a CSR carrying a
// public key, and these tests never sign anything with it.
var testPublicKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public()

// testCSR fills in testPublicKey (and its algorithm) on csr, or on an empty
// CSR when csr is nil, so each test spells out only the fields it exercises.
func testCSR(csr *CSR) *CSR {
	if csr == nil {
		csr = &CSR{}
	}
	if csr.PublicKey == nil {
		csr.PublicKey = testPublicKey
	}
	if csr.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
		csr.PublicKeyAlgorithm = x509.Ed25519
	}
	return csr
}

func testPod(annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "mypod",
			Namespace:   "myns",
			Annotations: annotations,
		},
	}
}

func testPCR(userAnnotations map[string]string) *certificatesv1.PodCertificateRequest {
	return &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "myns"},
		Spec: certificatesv1.PodCertificateRequestSpec{
			SignerName:                testSignerName,
			PodName:                   "mypod",
			UnverifiedUserAnnotations: userAnnotations,
		},
	}
}

func TestNewConfigDefaults(t *testing.T) {
	config, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), testCSR(nil), Options{})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}

	if config.CommonName != "mypod" {
		t.Errorf("CommonName = %q, want pod name", config.CommonName)
	}
	wantDNS := []string{"mypod.myns.pod.cluster.local", "mypod.myns.svc.cluster.local"}
	if len(config.DNSNames) != 2 || config.DNSNames[0] != wantDNS[0] || config.DNSNames[1] != wantDNS[1] {
		t.Errorf("DNSNames = %v, want %v", config.DNSNames, wantDNS)
	}
	if config.Duration != DefaultDuration {
		t.Errorf("Duration = %v, want %v", config.Duration, DefaultDuration)
	}
	if config.RefreshBefore != DefaultRefreshBefore {
		t.Errorf("RefreshBefore = %v, want %v", config.RefreshBefore, DefaultRefreshBefore)
	}
}

// The -cluster-fqdn flag must be honored in the default DNS names.
func TestNewConfigClusterFQDN(t *testing.T) {
	config, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), testCSR(nil), Options{ClusterFQDN: "corp.example.com"})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if config.DNSNames[0] != "mypod.myns.pod.corp.example.com" {
		t.Errorf("DNSNames[0] = %q, want cluster FQDN to be used", config.DNSNames[0])
	}
}

// unverifiedUserAnnotations must take precedence over pod annotations.
func TestNewConfigUserAnnotationsPrecedence(t *testing.T) {
	pod := testPod(map[string]string{testSignerName + "-cn": "from-pod"})
	pcr := testPCR(map[string]string{testSignerName + "-cn": "from-pcr"})

	// Literal values require the unverified-identities opt-in.
	config, err := NewConfig(context.Background(), pcr, pod, testCSR(nil),
		Options{AllowUnverifiedIdentities: true, AllowPodAnnotations: true})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if config.CommonName != "from-pcr" {
		t.Errorf("CommonName = %q, want value from unverifiedUserAnnotations", config.CommonName)
	}
}

// Pod annotations remain supported as a (deprecated) fallback while
// AllowPodAnnotations is set.
func TestNewConfigPodAnnotationFallback(t *testing.T) {
	pod := testPod(map[string]string{
		testSignerName + "-cn":       "custom-cn",
		testSignerName + "-san":      " foo.example.com , bar.example.com ",
		testSignerName + "-duration": "2h",
		testSignerName + "-refresh":  "30m",
		testSignerName + "-uris":     "spiffe://cluster/ns/myns/pod/mypod",
	})

	// These are literal (non-derived) values, allowed only with the opt-in.
	config, err := NewConfig(context.Background(), testPCR(nil), pod, testCSR(nil),
		Options{AllowUnverifiedIdentities: true, AllowPodAnnotations: true})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if config.CommonName != "custom-cn" {
		t.Errorf("CommonName = %q, want custom-cn", config.CommonName)
	}
	if len(config.DNSNames) != 2 || config.DNSNames[0] != "foo.example.com" || config.DNSNames[1] != "bar.example.com" {
		t.Errorf("DNSNames = %v, want trimmed entries", config.DNSNames)
	}
	if config.Duration != 2*time.Hour {
		t.Errorf("Duration = %v, want 2h", config.Duration)
	}
	if config.RefreshBefore != 30*time.Minute {
		t.Errorf("RefreshBefore = %v, want 30m", config.RefreshBefore)
	}
	if len(config.URIs) != 1 || config.URIs[0].Scheme != "spiffe" {
		t.Errorf("URIs = %v, want one spiffe URI", config.URIs)
	}
}

// Malformed values must be surfaced as errors instead of silently falling back
// to defaults.
func TestNewConfigMalformedValues(t *testing.T) {
	cases := []struct {
		name        string
		annotations map[string]string
	}{
		{"bad duration", map[string]string{testSignerName + "-duration": "not-a-duration"}},
		{"bad refresh", map[string]string{testSignerName + "-refresh": "soon"}},
		{"uri without scheme", map[string]string{testSignerName + "-uris": "no-scheme-here"}},
		{"empty san list", map[string]string{testSignerName + "-san": " , "}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewConfig(context.Background(), testPCR(tc.annotations), testPod(nil), testCSR(nil), Options{}); err == nil {
				t.Fatalf("want error for %v, got nil", tc.annotations)
			}
		})
	}
}

// Unrecognized keys in unverifiedUserAnnotations must be rejected, per the
// certificates v1 API contract for signers.
func TestNewConfigUnrecognizedUserAnnotation(t *testing.T) {
	pcr := testPCR(map[string]string{testSignerName + "-bogus": "value"})

	_, err := NewConfig(context.Background(), pcr, testPod(nil), testCSR(nil), Options{})
	if err == nil || !strings.Contains(err.Error(), "unrecognized") {
		t.Fatalf("err = %v, want unrecognized key error", err)
	}
}

// The maxExpirationSeconds of the request must clamp the default duration:
// kube-apiserver rejects issued certificates which outlive it.
func TestNewConfigMaxExpirationClampsDefault(t *testing.T) {
	pcr := testPCR(nil)
	maxExpirationSeconds := int32(7200)
	pcr.Spec.MaxExpirationSeconds = &maxExpirationSeconds

	config, err := NewConfig(context.Background(), pcr, testPod(nil), testCSR(nil), Options{})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if config.Duration != 2*time.Hour {
		t.Errorf("Duration = %v, want clamped to 2h", config.Duration)
	}
	if config.MaxExpiration != 2*time.Hour {
		t.Errorf("MaxExpiration = %v, want 2h", config.MaxExpiration)
	}
}

// A request without a parsed CSR has no public key to certify, so NewConfig
// must refuse it rather than build a config that can never be signed.
func TestNewConfigRequiresCSR(t *testing.T) {
	_, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), nil, Options{})
	if err == nil || !strings.Contains(err.Error(), "certificate signing request is required") {
		t.Fatalf("err = %v, want a missing-CSR error", err)
	}
}
