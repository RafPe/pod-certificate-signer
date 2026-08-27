package podcertificate

import (
	"strings"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testSignerName = "example.org/signer"

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

func TestNewPodCertificateConfigDefaults(t *testing.T) {
	config, err := NewPodCertificateConfig(testPCR(nil), testPod(nil), Options{}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
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
func TestNewPodCertificateConfigClusterFQDN(t *testing.T) {
	config, err := NewPodCertificateConfig(testPCR(nil), testPod(nil), Options{ClusterFQDN: "corp.example.com"}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if config.DNSNames[0] != "mypod.myns.pod.corp.example.com" {
		t.Errorf("DNSNames[0] = %q, want cluster FQDN to be used", config.DNSNames[0])
	}
}

// unverifiedUserAnnotations must take precedence over pod annotations.
func TestNewPodCertificateConfigUserAnnotationsPrecedence(t *testing.T) {
	pod := testPod(map[string]string{testSignerName + "-cn": "from-pod"})
	pcr := testPCR(map[string]string{testSignerName + "-cn": "from-pcr"})

	// Literal values require the unverified-identities opt-in.
	config, err := NewPodCertificateConfig(pcr, pod, Options{AllowUnverifiedIdentities: true}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if config.CommonName != "from-pcr" {
		t.Errorf("CommonName = %q, want value from unverifiedUserAnnotations", config.CommonName)
	}
}

// Pod annotations remain supported as a (deprecated) fallback.
func TestNewPodCertificateConfigPodAnnotationFallback(t *testing.T) {
	pod := testPod(map[string]string{
		testSignerName + "-cn":       "custom-cn",
		testSignerName + "-san":      " foo.example.com , bar.example.com ",
		testSignerName + "-duration": "2h",
		testSignerName + "-refresh":  "30m",
		testSignerName + "-uris":     "spiffe://cluster/ns/myns/pod/mypod",
	})

	// These are literal (non-derived) values, allowed only with the opt-in.
	config, err := NewPodCertificateConfig(testPCR(nil), pod, Options{AllowUnverifiedIdentities: true}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
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
func TestNewPodCertificateConfigMalformedValues(t *testing.T) {
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
			if _, err := NewPodCertificateConfig(testPCR(tc.annotations), testPod(nil), Options{}, nil, 0); err == nil {
				t.Fatalf("want error for %v, got nil", tc.annotations)
			}
		})
	}
}

// Unrecognized keys in unverifiedUserAnnotations must be rejected, per the
// certificates v1 API contract for signers.
func TestNewPodCertificateConfigUnrecognizedUserAnnotation(t *testing.T) {
	pcr := testPCR(map[string]string{testSignerName + "-bogus": "value"})

	_, err := NewPodCertificateConfig(pcr, testPod(nil), Options{}, nil, 0)
	if err == nil || !strings.Contains(err.Error(), "unrecognized") {
		t.Fatalf("err = %v, want unrecognized key error", err)
	}
}

// The maxExpirationSeconds of the request must clamp the default duration:
// kube-apiserver rejects issued certificates which outlive it.
func TestNewPodCertificateConfigMaxExpirationClampsDefault(t *testing.T) {
	pcr := testPCR(nil)
	maxExpirationSeconds := int32(7200)
	pcr.Spec.MaxExpirationSeconds = &maxExpirationSeconds

	config, err := NewPodCertificateConfig(pcr, testPod(nil), Options{}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if config.Duration != 2*time.Hour {
		t.Errorf("Duration = %v, want clamped to 2h", config.Duration)
	}
	if config.MaxExpiration != 2*time.Hour {
		t.Errorf("MaxExpiration = %v, want 2h", config.MaxExpiration)
	}
}

// An explicitly requested duration above maxExpirationSeconds must fail
// validation instead of being rejected by kube-apiserver on status update.
func TestValidateDurationExceedingMaxExpiration(t *testing.T) {
	pcr := testPCR(map[string]string{testSignerName + "-duration": "4h"})
	maxExpirationSeconds := int32(7200)
	pcr.Spec.MaxExpirationSeconds = &maxExpirationSeconds

	config, err := NewPodCertificateConfig(pcr, testPod(nil), Options{}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if err := config.Validate(); err == nil {
		t.Fatal("want validation error for duration above maxExpirationSeconds, got nil")
	}
}

func TestPodCertificateConfigValidate(t *testing.T) {
	valid := PodCertificateConfig{CommonName: "cn", Duration: time.Hour, RefreshBefore: 15 * time.Minute}

	cases := []struct {
		name    string
		mutate  func(c *PodCertificateConfig)
		wantErr bool
	}{
		{"valid", func(c *PodCertificateConfig) {}, false},
		{"missing common name", func(c *PodCertificateConfig) { c.CommonName = "" }, true},
		{"non-positive duration", func(c *PodCertificateConfig) { c.Duration = 0 }, true},
		{"duration below apiserver minimum", func(c *PodCertificateConfig) { c.Duration = 30 * time.Minute }, true},
		{"duration above max expiration", func(c *PodCertificateConfig) { c.MaxExpiration = 30 * time.Minute; c.Duration = time.Hour }, true},
		{"negative refresh", func(c *PodCertificateConfig) { c.RefreshBefore = -time.Minute }, true},
		{"refresh below apiserver margin", func(c *PodCertificateConfig) { c.RefreshBefore = 5 * time.Minute }, true},
		{"refresh not shorter than duration", func(c *PodCertificateConfig) { c.RefreshBefore = time.Hour }, true},
		{"refresh too close to duration", func(c *PodCertificateConfig) { c.RefreshBefore = 55 * time.Minute }, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := valid
			tc.mutate(&config)
			if err := config.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate() = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
