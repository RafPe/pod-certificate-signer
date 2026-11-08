package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
)

// An empty --signer-name must be rejected fast, before the controller attempts
// any Kubernetes API calls, mirroring the required --ca-cert-path handling.
func TestValidateFlagsRequiresSignerName(t *testing.T) {
	if err := validateFlags("", podcertificate.Options{ClusterFQDN: "cluster.local"}); err == nil {
		t.Error("validateFlags(\"\") = nil, want error for empty signer name")
	}
	if err := validateFlags("example.org/signer", podcertificate.Options{ClusterFQDN: "cluster.local"}); err != nil {
		t.Errorf("validateFlags(%q) = %v, want nil", "example.org/signer", err)
	}
}

func TestValidateFlagsRejectsInvalidClusterFQDN(t *testing.T) {
	for _, clusterFQDN := range []string{
		strings.Repeat("a", 64) + ".example",
		"bad_fqdn.example",
		"a..example",
	} {
		t.Run(clusterFQDN, func(t *testing.T) {
			err := validateFlags("example.org/signer", podcertificate.Options{ClusterFQDN: clusterFQDN})
			if err == nil {
				t.Fatalf("validateFlags(clusterFQDN=%q) error = nil, want invalid DNS error", clusterFQDN)
			}
			if !strings.Contains(err.Error(), clusterFQDN) {
				t.Errorf("validateFlags(clusterFQDN=%q) error = %q, want offending value", clusterFQDN, err)
			}
		})
	}
}

// The manager must bypass the cache for Pods: the controller only does point
// Gets by name (and re-reads live via the APIReader for identity), so a
// cluster-wide pod informer wastes memory and forces list/watch RBAC the
// controller does not otherwise need.
func TestManagerOptionsDisablesPodCache(t *testing.T) {
	opts := managerOptions(k8sruntime.NewScheme(), context.Background(), managerConfig{})

	if opts.Client.Cache == nil {
		t.Fatal("Client.Cache is nil, want pod caching disabled via DisableFor")
	}

	found := false
	for _, obj := range opts.Client.Cache.DisableFor {
		if _, ok := obj.(*corev1.Pod); ok {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Client.Cache.DisableFor = %v, want it to include *corev1.Pod", opts.Client.Cache.DisableFor)
	}
}

// A leader shutting down must release its Lease rather than leave a follower to
// wait out the 15s LeaseDuration. Nothing else pins this, so without the
// assertion an edit to the options literal could revert the decision silently
// (docs/adr/0006-release-leader-lease-on-cancel.md).
func TestManagerOptionsReleasesLeaseOnCancel(t *testing.T) {
	opts := managerOptions(k8sruntime.NewScheme(), context.Background(), managerConfig{})

	if !opts.LeaderElectionReleaseOnCancel {
		t.Error("LeaderElectionReleaseOnCancel = false, want true: " +
			"see docs/adr/0006-release-leader-lease-on-cancel.md")
	}
}

// TestManagerOptionsSecuresMetricsByDefault asserts that, with the secure
// metrics toggle on, the metrics server is configured to require
// authentication and authorization (via controller-runtime's TokenReview /
// SubjectAccessReview filter) and to serve over HTTPS. This is the behaviour
// that rejects an unauthenticated scrape.
func TestManagerOptionsSecuresMetrics(t *testing.T) {
	opts := managerOptions(k8sruntime.NewScheme(), context.Background(), managerConfig{metricsSecure: true})

	if !opts.Metrics.SecureServing {
		t.Error("Metrics.SecureServing = false, want true so the endpoint is served over HTTPS")
	}
	if opts.Metrics.FilterProvider == nil {
		t.Error("Metrics.FilterProvider = nil, want the authn/authz filter so unauthenticated scrapes are rejected")
	}
}

// TestManagerOptionsInsecureMetricsEscapeHatch asserts that the insecure escape
// hatch turns the auth filter and HTTPS off, restoring the legacy plaintext,
// unauthenticated metrics endpoint for operators who opt into it.
func TestManagerOptionsInsecureMetricsEscapeHatch(t *testing.T) {
	opts := managerOptions(k8sruntime.NewScheme(), context.Background(), managerConfig{metricsSecure: false})

	if opts.Metrics.SecureServing {
		t.Error("Metrics.SecureServing = true, want false when the insecure escape hatch is set")
	}
	if opts.Metrics.FilterProvider != nil {
		t.Error("Metrics.FilterProvider is set, want nil when the insecure escape hatch is set")
	}
}

// stubHealth is a test double for the health surface consumed by the readyz
// check.
type stubHealth struct{ err error }

func (s stubHealth) HealthCheck() error { return s.err }

// TestReadyzCheck asserts that the readiness check passes when the CA reports
// healthy and fails when it reports a watcher/reload problem, so a replica that
// can no longer track CA rotations is removed from readiness.
func TestReadyzCheck(t *testing.T) {
	if err := readyzCheck(stubHealth{err: nil})(nil); err != nil {
		t.Errorf("readyz check = %v, want nil when the CA is healthy", err)
	}

	want := errors.New("ca watcher is down")
	if err := readyzCheck(stubHealth{err: want})(nil); err == nil {
		t.Error("readyz check must fail when the CA reports unhealthy")
	}
}

// Issue #87: per-pod SPIFFE-style identity must work on a default install, so
// ${...} interpolation ships on. It grants no new identity - a placeholder
// resolves only from apiserver-verified request fields, and the resolved value
// is still checked against the pod's verified identity by exact string equality
// (docs/adr/0001-verified-identity-allowlist-boundary.md,
// docs/adr/0002-annotation-interpolation-on-by-default.md).
//
// This is one half of the guarantee that examples/workload-pod.yaml issues out
// of the box. The other half is
// hygiene.TestWorkloadPodExampleIssuesUnderIdentityConstraints, which proves
// the example needs no --allow-unverified-identities once interpolation is on.
// That test pins EnableInterpolation itself and so cannot see this default
// regress; this test says nothing about the example. Neither is meaningful
// alone - do not remove or simplify one without the other.
func TestAnnotationInterpolationEnabledByDefault(t *testing.T) {
	if !defaultEnableAnnotationInterpolation {
		t.Error("defaultEnableAnnotationInterpolation = false, want true: " +
			"${...} interpolation ships on, see docs/adr/0002-annotation-interpolation-on-by-default.md")
	}
}

// The binary defaults and the chart defaults are independent copies of the
// same decisions. Almost nobody runs the binary directly - the chart is the
// shipped interface - so a flip that lands on only one side ships a posture
// the docs do not describe, and does it silently. Every security-relevant
// default is pinned here against its named binary constant.
func TestChartSecurityDefaultsMatchBinary(t *testing.T) {
	path := filepath.Join(chartDir(t), "values.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) = %v", path, err)
	}

	var values struct {
		Signer struct {
			EnableAnnotationInterpolation *bool `json:"enable_annotation_interpolation"`
			AllowUnverifiedIdentities     *bool `json:"allow_unverified_identities"`
			AllowPodAnnotations           *bool `json:"allow_pod_annotations"`
		} `json:"signer"`
		Metrics struct {
			Insecure *bool `json:"insecure"`
		} `json:"metrics"`
	}
	if err := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096).Decode(&values); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}

	cases := []struct {
		value  string
		got    *bool
		binary bool
	}{
		{"signer.enable_annotation_interpolation", values.Signer.EnableAnnotationInterpolation, defaultEnableAnnotationInterpolation},
		{"signer.allow_unverified_identities", values.Signer.AllowUnverifiedIdentities, defaultAllowUnverifiedIdentities},
		{"signer.allow_pod_annotations", values.Signer.AllowPodAnnotations, defaultAllowPodAnnotations},
		// metrics.insecure is the inverse of --metrics-secure.
		{"metrics.insecure", values.Metrics.Insecure, !defaultMetricsSecure},
	}
	for _, tc := range cases {
		if tc.got == nil {
			t.Errorf("%s does not set %s; the chart would fall back to the Go zero value", path, tc.value)
			continue
		}
		if *tc.got != tc.binary {
			t.Errorf("chart %s = %t, binary default = %t; the two must agree", tc.value, *tc.got, tc.binary)
		}
	}
}

// Flag defaults are registered on a private FlagSet here, so the shipped
// defaults and the help text are asserted against the real registration
// rather than against a side-channel constant.
func TestRegisterFlagsDefaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	f := registerFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	defaults := []struct {
		flag string
		got  bool
		want bool
	}{
		{"enable-annotation-interpolation", f.certOpts.EnableInterpolation, defaultEnableAnnotationInterpolation},
		{"allow-unverified-identities", f.certOpts.AllowUnverifiedIdentities, defaultAllowUnverifiedIdentities},
		{"metrics-secure", f.manager.metricsSecure, defaultMetricsSecure},
		{"allow-pod-annotations", f.certOpts.AllowPodAnnotations, defaultAllowPodAnnotations},
		// Kubelet CSR SANs are opt-in.
		{"honor-csr-sans", f.certOpts.HonorCSRSANs, false},
	}
	if f.certOpts.ClusterFQDN != podcertificate.DefaultClusterFQDN {
		t.Errorf("--cluster-fqdn defaults to %q, want %q", f.certOpts.ClusterFQDN, podcertificate.DefaultClusterFQDN)
	}
	for _, d := range defaults {
		if d.got != d.want {
			t.Errorf("--%s defaults to %t, want %t", d.flag, d.got, d.want)
		}
	}

	// Leader election has used a Lease for as long as the chart has granted
	// coordination.k8s.io RBAC; help text naming a ConfigMap sends an operator
	// debugging a stuck election to the wrong object.
	help := fs.Lookup("leader-election-id").Usage
	if !strings.Contains(help, "Lease") || strings.Contains(strings.ToLower(help), "configmap") {
		t.Errorf("--leader-election-id help = %q, want it to name the Lease", help)
	}
}
