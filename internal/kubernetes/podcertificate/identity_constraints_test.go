package podcertificate

import (
	"crypto/x509"
	"reflect"
	"strings"
	"testing"

	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/types"
)

// verifiedPCR returns a request whose verified fields (pod name/namespace/
// serviceAccountName) are populated, so identity values derived from them can
// be exercised.
func verifiedPCR(userAnnotations map[string]string) *certificatesv1.PodCertificateRequest {
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

// The node name belongs to the kubelet and the pod UID is an opaque token;
// neither is an identity the workload owns, so both must be denied as a subject
// even though they are available for interpolation.
func TestNodeAndUIDNotClaimable(t *testing.T) {
	pcr := verifiedPCR(map[string]string{testSignerName + "-cn": "${node.name}"})
	pcr.Spec.NodeName = "node-1"
	if _, err := NewPodCertificateConfig(pcr, testPod(nil), Options{EnableInterpolation: true}, nil, 0); err == nil {
		t.Error("want denial for cn=${node.name}, got nil")
	}

	pcr = verifiedPCR(map[string]string{testSignerName + "-cn": "${pod.uid}"})
	if _, err := NewPodCertificateConfig(pcr, testPod(nil), Options{EnableInterpolation: true}, nil, 0); err == nil {
		t.Error("want denial for cn=${pod.uid}, got nil")
	}
}

// The service-account identity is claimable in its short DNS form and as a
// SPIFFE ID, never as a Kubernetes Service DNS name: <sa>.<ns>.svc is the shape
// of a Service record, and ServiceAccount and Service names are independent
// within a namespace. Allowing it would let a pod running as ServiceAccount
// "kubernetes" in "default" present a certificate for kubernetes.default.svc -
// the exact case the identity constraint exists to deny. The signer emits no
// service-account-derived DNS name of its own, so none is claimable. See
// docs/adr/0001-verified-identity-allowlist-boundary.md.
//
// This is a characterization test: it passes today and exists to lock the
// decision, so a future "just add .svc" patch turns red with a pointer to the
// reasoning rather than merging quietly.
func TestServiceAccountServiceDNSFormsDenied(t *testing.T) {
	for _, san := range []string{
		"${pod.serviceAccountName}.${pod.namespace}.svc",
		"${pod.serviceAccountName}.${pod.namespace}.svc.${cluster.fqdn}",
		"${pod.serviceAccountName}.${pod.namespace}.pod",
		"${pod.serviceAccountName}.${pod.namespace}.pod.${cluster.fqdn}",
	} {
		t.Run(san, func(t *testing.T) {
			pcr := verifiedPCR(map[string]string{testSignerName + "-san": san})
			if _, err := NewPodCertificateConfig(pcr, testPod(nil), Options{EnableInterpolation: true}, nil, 0); err == nil {
				t.Fatalf("want denial for san=%q, got nil", san)
			}
		})
	}
}

// The SPIFFE ID of the pod's service account is the supported way to carry
// per-pod workload identity (issue #87), and must be accepted under the default
// identity constraints - it is the form the ADR points operators at once the
// service-account Service DNS forms above are ruled out. See
// docs/adr/0001-verified-identity-allowlist-boundary.md.
func TestServiceAccountSPIFFEIDAccepted(t *testing.T) {
	pcr := verifiedPCR(map[string]string{
		testSignerName + "-uris": "spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}",
	})

	config, err := NewPodCertificateConfig(pcr, testPod(nil), Options{EnableInterpolation: true}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if len(config.URIs) != 1 || config.URIs[0].String() != "spiffe://cluster.local/ns/myns/sa/mysa" {
		t.Errorf("URIs = %v, want the service-account SPIFFE ID", config.URIs)
	}
}

// The pod's own canonical Kubernetes DNS forms are claimable because the signer
// emits them itself by default (defaultPodDNSNames) - the allowlist must contain
// everything the default path already puts into a certificate, or the annotation
// path would be stricter than doing nothing. This is the counterpart to
// TestServiceAccountServiceDNSFormsDenied: it pins rule (a) of
// docs/adr/0001-verified-identity-allowlist-boundary.md, and is what makes the
// asymmetry between the pod and service-account forms principled rather than an
// oversight.
func TestPodServiceDNSFormsAccepted(t *testing.T) {
	for san, want := range map[string]string{
		"${pod.name}.${pod.namespace}.svc":                 "mypod.myns.svc",
		"${pod.name}.${pod.namespace}.svc.${cluster.fqdn}": "mypod.myns.svc.cluster.local",
		"${pod.name}.${pod.namespace}.pod":                 "mypod.myns.pod",
		"${pod.name}.${pod.namespace}.pod.${cluster.fqdn}": "mypod.myns.pod.cluster.local",
	} {
		t.Run(san, func(t *testing.T) {
			pcr := verifiedPCR(map[string]string{testSignerName + "-san": san})
			config, err := NewPodCertificateConfig(pcr, testPod(nil), Options{EnableInterpolation: true}, nil, 0)
			if err != nil {
				t.Fatalf("NewPodCertificateConfig(san=%q): %v", san, err)
			}
			if len(config.DNSNames) != 1 || config.DNSNames[0] != want {
				t.Errorf("DNSNames = %v, want [%s]", config.DNSNames, want)
			}
		})
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

// (5): A pod name over the 63-character DNS label limit must not receive a
// truncated, collision-prone default SAN. At 64 characters the common name still
// carries the identity, so the certificate issues with no default DNS SANs. Past
// the 64-character CN limit as well, with no annotation to supply an identity,
// the configuration is denied at validation rather than issued without a
// verifiable subject.
func TestLongPodNameIdentityFallback(t *testing.T) {
	t.Run("64 chars: CN carries identity, config validates", func(t *testing.T) {
		name := strings.Repeat("a", 64)
		pod := testPod(nil)
		pod.Name = name
		pcr := testPCR(nil)
		pcr.Spec.PodName = name

		config, err := NewPodCertificateConfig(pcr, pod, Options{}, nil, 0)
		if err != nil {
			t.Fatalf("NewPodCertificateConfig: %v", err)
		}
		if config.CommonName != name {
			t.Errorf("CommonName = %q, want the 64-char pod name", config.CommonName)
		}
		if len(config.DNSNames) != 0 {
			t.Errorf("DNSNames = %v, want none for an over-long label", config.DNSNames)
		}
		if err := config.Validate(); err != nil {
			t.Errorf("Validate() = %v, want nil (the CN carries the identity)", err)
		}
	})

	t.Run("65 chars, no annotation: denied at validation", func(t *testing.T) {
		name := strings.Repeat("a", 65)
		pod := testPod(nil)
		pod.Name = name
		pcr := testPCR(nil)
		pcr.Spec.PodName = name

		config, err := NewPodCertificateConfig(pcr, pod, Options{}, nil, 0)
		if err != nil {
			t.Fatalf("NewPodCertificateConfig: %v", err)
		}
		if config.CommonName != "" {
			t.Errorf("CommonName = %q, want empty for a pod name over the CN limit", config.CommonName)
		}
		if err := config.Validate(); err == nil {
			t.Error("Validate() = nil, want denial when there is neither a CN nor a SAN")
		}
	})
}

// A pod name whose DNS label(s) exceed the 63-character RFC 1035 limit must not
// receive a truncated default SAN: truncation would give two pods sharing a
// 63-character prefix identical pod/svc SANs, so one could impersonate the
// other. Instead the default pod DNS SANs are omitted entirely and a warning is
// surfaced. Boundary: a 63-character label is kept; 64+ yields no default SANs.
func TestLongPodNameOmitsDefaultDNSSANs(t *testing.T) {
	cases := []struct {
		name        string
		podName     string
		wantSANs    bool
		wantWarning bool
	}{
		{"exactly 63 chars kept", strings.Repeat("a", 63), true, false},
		{"64 chars omitted", strings.Repeat("a", 64), false, true},
		{"65 chars omitted", strings.Repeat("a", 65), false, true},
		{"multi-label within limit kept", strings.Repeat("a", 40) + "." + strings.Repeat("b", 40), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pod := testPod(nil)
			pod.Name = tc.podName
			pcr := testPCR(nil)
			pcr.Spec.PodName = tc.podName

			config, err := NewPodCertificateConfig(pcr, pod, Options{}, nil, 0)
			if err != nil {
				t.Fatalf("NewPodCertificateConfig: %v", err)
			}
			// Whatever survives must be a valid label - no empty or >63 label.
			for _, dns := range config.DNSNames {
				for _, label := range strings.Split(dns, ".") {
					if len(label) == 0 || len(label) > 63 {
						t.Errorf("DNS name %q has invalid label %q (len %d)", dns, label, len(label))
					}
				}
			}
			if gotSANs := len(config.DNSNames) > 0; gotSANs != tc.wantSANs {
				t.Errorf("has default DNS SANs = %v (%v), want %v", gotSANs, config.DNSNames, tc.wantSANs)
			}
			gotWarning := false
			for _, w := range config.Warnings {
				if strings.Contains(w, "DNS label limit") {
					gotWarning = true
				}
			}
			if gotWarning != tc.wantWarning {
				t.Errorf("DNS-label warning surfaced = %v (%v), want %v", gotWarning, config.Warnings, tc.wantWarning)
			}
		})
	}
}

// Two distinct pods whose names share a 63-character prefix must not receive
// identical default SANs - the collision truncation would introduce, letting one
// pod's certificate impersonate the other. Each simply gets no default DNS SANs.
func TestLongPodNameNoDefaultSANCollision(t *testing.T) {
	prefix := strings.Repeat("a", 63)
	build := func(podName string) *PodCertificateConfig {
		pod := testPod(nil)
		pod.Name = podName
		pcr := testPCR(nil)
		pcr.Spec.PodName = podName
		config, err := NewPodCertificateConfig(pcr, pod, Options{}, nil, 0)
		if err != nil {
			t.Fatalf("NewPodCertificateConfig(%q): %v", podName, err)
		}
		return config
	}

	a := build(prefix + "x")
	b := build(prefix + "y")
	if len(a.DNSNames) != 0 || len(b.DNSNames) != 0 {
		t.Fatalf("want no default DNS SANs for over-long names, got a=%v b=%v", a.DNSNames, b.DNSNames)
	}
}
