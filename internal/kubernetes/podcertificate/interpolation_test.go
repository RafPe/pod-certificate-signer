package podcertificate

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

// enabled: placeholders resolve from the verified PodCertificateRequest fields.
func TestInterpolationResolvesFromPCR(t *testing.T) {
	pcr := testPCR(map[string]string{
		testSignerName + "-cn":   "${pod.name}.${pod.namespace}.svc.${cluster.fqdn}",
		testSignerName + "-san":  "${pod.name}.${pod.namespace}.svc, ${pod.serviceAccountName}.${pod.namespace}",
		testSignerName + "-uris": "spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}",
	})
	pcr.Spec.ServiceAccountName = "mysa"
	pcr.Spec.PodUID = types.UID("abc-123")
	pcr.Spec.NodeName = types.NodeName("node-1")

	config, err := NewPodCertificateConfig(pcr, testPod(nil), Options{EnableInterpolation: true}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}

	if config.CommonName != "mypod.myns.svc.cluster.local" {
		t.Errorf("CommonName = %q, want interpolated value", config.CommonName)
	}
	wantSAN := []string{"mypod.myns.svc", "mysa.myns"}
	if len(config.DNSNames) != 2 || config.DNSNames[0] != wantSAN[0] || config.DNSNames[1] != wantSAN[1] {
		t.Errorf("DNSNames = %v, want %v", config.DNSNames, wantSAN)
	}
	if len(config.URIs) != 1 || config.URIs[0].String() != "spiffe://cluster.local/ns/myns/sa/mysa" {
		t.Errorf("URIs = %v, want interpolated SPIFFE ID", config.URIs)
	}
}

// disabled (default): values containing placeholders are rejected, never
// issued verbatim.
func TestInterpolationDisabledRejectsPlaceholders(t *testing.T) {
	pcr := testPCR(map[string]string{
		testSignerName + "-cn": "${pod.name}.${pod.namespace}",
	})

	_, err := NewPodCertificateConfig(pcr, testPod(nil), Options{}, nil, 0)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("err = %v, want interpolation-disabled error", err)
	}
}

// disabled: values without placeholders keep working unchanged.
func TestInterpolationDisabledPassesPlainValues(t *testing.T) {
	pcr := testPCR(map[string]string{
		testSignerName + "-cn": "plain-name.example.com",
	})

	// A plain literal value requires the unverified-identities opt-in.
	config, err := NewPodCertificateConfig(pcr, testPod(nil), Options{AllowUnverifiedIdentities: true}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if config.CommonName != "plain-name.example.com" {
		t.Errorf("CommonName = %q, want plain value untouched", config.CommonName)
	}
}

func TestInterpolate(t *testing.T) {
	vars := map[string]string{
		"pod.name":      "mypod",
		"pod.namespace": "myns",
	}

	cases := []struct {
		name    string
		value   string
		enabled bool
		want    string
		wantErr string
	}{
		{"no placeholders", "static.example.com", true, "static.example.com", ""},
		{"single variable", "${pod.name}", true, "mypod", ""},
		{"multiple variables", "${pod.name}.${pod.namespace}.svc", true, "mypod.myns.svc", ""},
		{"whitespace inside braces", "${ pod.name }", true, "mypod", ""},
		{"unknown variable", "${pod.hostIP}", true, "", "unknown interpolation variable"},
		{"unterminated placeholder", "${pod.name", true, "", "unterminated"},
		{"disabled with placeholder", "${pod.name}", false, "", "disabled"},
		{"disabled without placeholder", "static", false, "static", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := interpolate(tc.value, vars, tc.enabled)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("interpolate: %v", err)
			}
			if got != tc.want {
				t.Errorf("interpolate(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// The 64 character RFC 5280 common name limit must be enforced, since
// interpolated pod names can easily exceed it.
func TestValidateCommonNameLength(t *testing.T) {
	config := PodCertificateConfig{
		CommonName:    strings.Repeat("a", 65),
		Duration:      DefaultDuration,
		RefreshBefore: DefaultRefreshBefore,
	}
	if err := config.Validate(); err == nil || !strings.Contains(err.Error(), "64") {
		t.Fatalf("err = %v, want common name length error", err)
	}
}
