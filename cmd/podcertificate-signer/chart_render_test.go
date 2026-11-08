package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot returns the repository root, located relative to this source file
// so the chart tests work from any working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// chartDir returns the path of the Helm chart under test.
func chartDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "charts", "pod-certificate-signer")
}

// helmCommand builds a helm invocation. It prefers a helm on PATH and
// otherwise runs the one pinned in internal/tools/go.mod through `go tool`,
// so the chart contract is checked on every run - including CI runners that
// have Go but no helm - rather than skipped wherever helm happens to be
// missing.
func helmCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	if helm, err := exec.LookPath("helm"); err == nil {
		return exec.Command(helm, args...)
	}
	toolsMod := filepath.Join(repoRoot(t), "internal", "tools", "go.mod")
	return exec.Command("go", append([]string{"tool", "-modfile", toolsMod, "helm"}, args...)...)
}

// renderChartResult runs `helm template` on the chart with the values the
// chart requires plus any extra --set values, and returns the rendered
// manifests together with the command's error, for tests that expect a
// render to fail.
func renderChartResult(t *testing.T, values ...string) (string, error) {
	t.Helper()
	args := make([]string, 0, 11+2*len(values))
	args = append(args,
		"template", "test", chartDir(t),
		"--namespace", "pcs-system",
		"--kube-version", "1.37.0",
		// A CA source is required (the chart fails fast otherwise).
		"--set", "signer.ca.secretRef.name=test-ca",
		"--set", "signer.name=example.org/signer",
	)
	for _, value := range values {
		args = append(args, "--set", value)
	}
	out, err := helmCommand(t, args...).CombinedOutput()
	return string(out), err
}

// renderChart is renderChartResult for tests that expect the render to
// succeed: a failed render fails the test.
func renderChart(t *testing.T, values ...string) string {
	t.Helper()
	out, err := renderChartResult(t, values...)
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return out
}

// The rendered Deployment must pass --cluster-fqdn and
// --health-probe-bind-address to the manager, so the corresponding chart
// values actually reach the controller instead of silently falling back to the
// binary defaults.
func TestDeploymentRendersConfiguredFlags(t *testing.T) {
	out := renderChart(t)
	for _, want := range []string{"--cluster-fqdn=", "--health-probe-bind-address="} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered Deployment is missing flag %q", want)
		}
	}
}

// TestDeploymentRendersAllowUnverifiedIdentities guards the Helm escape hatch
// for the identity-constraint default: the chart must expose
// --allow-unverified-identities so operators can opt out via values instead of
// hand-editing the container command.
func TestDeploymentRendersAllowUnverifiedIdentities(t *testing.T) {
	out := renderChart(t)
	if !strings.Contains(out, "--allow-unverified-identities=") {
		t.Fatalf("rendered deployment is missing the --allow-unverified-identities flag; the escape hatch is not wired into the chart:\n%s", out)
	}
}

// TestDeploymentRendersRequireCAHistory guards the switch that decides what an
// absent ClusterTrustBundle means. It ships off, because a first install has no
// bundle yet, and it is worth nothing unless an operator can turn it on through
// values: an installation whose bundle is deleted loses its previous-CA history
// permanently on the next restart, and this flag is what turns that into a
// startup failure instead.
func TestDeploymentRendersRequireCAHistory(t *testing.T) {
	if out := renderChart(t); !strings.Contains(out, "--require-ca-history=false") {
		t.Errorf("rendered Deployment does not carry --require-ca-history=false by default:\n%s", out)
	}

	out := renderChart(t, "signer.require_ca_history=true")
	if !strings.Contains(out, "--require-ca-history=true") {
		t.Errorf("signer.require_ca_history=true did not reach the controller flag:\n%s", out)
	}
}

// TestSecureMetricsRBAC guards the RBAC controller-runtime's metrics auth filter
// depends on: the controller ServiceAccount must be able to create TokenReviews
// (to authenticate the scraper's bearer token) and SubjectAccessReviews (to
// authorize it). Without these the secured endpoint fails every scrape closed.
func TestSecureMetricsRBAC(t *testing.T) {
	out := renderChart(t)
	for _, want := range []string{"tokenreviews", "subjectaccessreviews"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered ClusterRole is missing %q, required by the metrics authn/authz filter:\n%s", want, out)
		}
	}
}

// TestDeploymentRendersMetricsSecureFlag guards that the secure-by-default
// metrics endpoint is wired through the chart and that the metrics.insecure
// escape hatch flips the flag, so operators opt out via values rather than by
// hand-editing the container command.
func TestDeploymentRendersMetricsSecureFlag(t *testing.T) {
	secure := renderChart(t)
	if !strings.Contains(secure, "--metrics-secure=true") {
		t.Errorf("rendered Deployment must carry --metrics-secure=true by default:\n%s", secure)
	}

	insecure := renderChart(t, "metrics.insecure=true")
	if !strings.Contains(insecure, "--metrics-secure=false") {
		t.Errorf("metrics.insecure=true must render --metrics-secure=false:\n%s", insecure)
	}
}

// TestMetricsReaderClusterRoleRendered guards that the chart ships a
// metrics-reader ClusterRole granting GET on the /metrics nonResourceURL, which
// is what a Prometheus ServiceAccount must be bound to in order to scrape the
// now-authorized endpoint.
func TestMetricsReaderClusterRoleRendered(t *testing.T) {
	out := renderChart(t)
	if !strings.Contains(out, "metrics-reader") {
		t.Errorf("rendered manifests are missing the metrics-reader ClusterRole for scrapers:\n%s", out)
	}
	if !strings.Contains(out, "/metrics") {
		t.Errorf("metrics-reader ClusterRole must grant the /metrics nonResourceURL:\n%s", out)
	}
}

// TestNetworkPolicyOptional guards the optional metrics NetworkPolicy: absent by
// default, rendered when metrics.networkPolicy.enabled is set.
func TestNetworkPolicyOptional(t *testing.T) {
	if def := renderChart(t); strings.Contains(def, "kind: NetworkPolicy") {
		t.Errorf("NetworkPolicy must not render by default:\n%s", def)
	}
	on := renderChart(t, "metrics.networkPolicy.enabled=true")
	if !strings.Contains(on, "kind: NetworkPolicy") {
		t.Errorf("metrics.networkPolicy.enabled=true must render a NetworkPolicy:\n%s", on)
	}
	// The policy selects the controller pods for Ingress, which denies all
	// unlisted traffic - so it must keep the health/probe port open alongside
	// the restricted metrics port, or the kubelet probes get black-holed.
	for _, want := range []string{"port: http", "port: metrics"} {
		if !strings.Contains(on, want) {
			t.Errorf("NetworkPolicy must keep %q reachable; missing from:\n%s", want, on)
		}
	}
}

func TestDNSSANAdmissionPolicyDisabledByDefault(t *testing.T) {
	out := renderChart(t)
	if strings.Contains(out, "kind: ValidatingAdmissionPolicy") {
		t.Fatalf("renderChart() contains admission policy while disabled by default:\n%s", out)
	}
}

func TestDNSSANAdmissionPolicyRendersIndependently(t *testing.T) {
	out := renderChart(t,
		"admissionPolicies.dnsSANValidation.enabled=true",
		"admissionPolicies.dnsSANValidation.validationActions={Warn,Audit}",
		"admissionPolicies.dnsSANValidation.namespaceSelector.matchLabels.policy=enabled",
		"admissionPolicies.dnsSANValidation.objectSelector.matchLabels.certificate=required",
	)

	wants := []string{
		"kind: ValidatingAdmissionPolicy\n",
		"kind: ValidatingAdmissionPolicyBinding\n",
		"name: test-pod-certificate-signer-dns-san-validation",
		"podcertificate-signer.io/policy: dns-san-validation",
		"validationActions:\n    - Warn\n    - Audit",
		"policy: enabled",
		"certificate: required",
		"example.org/signer-san",
		"cluster.local",
		"format.dns1123Subdomain",
	}
	for _, want := range wants {
		if !strings.Contains(out, want) {
			t.Errorf("renderChart() output does not contain %q:\n%s", want, out)
		}
	}
}

func TestDNSSANAdmissionPolicyRejectsInvalidActions(t *testing.T) {
	tests := []struct {
		name   string
		action string
	}{
		{name: "unknown action", action: "Block"},
		{name: "deny and warn", action: "{Deny,Warn}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := renderChartResult(t,
				"admissionPolicies.dnsSANValidation.enabled=true",
				"admissionPolicies.dnsSANValidation.validationActions="+tt.action,
			)
			if err == nil {
				t.Fatalf("renderChart(validationActions=%s) error = nil, want schema rejection\n%s", tt.action, out)
			}
		})
	}
}

// TestDeploymentRendersInterpolationEnabledByDefault guards both directions of
// the chart's interpolation default (issue #87): an unmodified install must
// render the flag on, and setting the value to false must still render the
// opt-out rather than dropping the flag - the template writes it
// unconditionally, and a switch to a `{{- if }}` guard would silently restore
// the binary default instead of disabling interpolation.
func TestDeploymentRendersInterpolationEnabledByDefault(t *testing.T) {
	if got := renderChart(t); !strings.Contains(got, "--enable-annotation-interpolation=true") {
		t.Errorf("rendered Deployment does not carry --enable-annotation-interpolation=true; "+
			"the chart default must match the binary default:\n%s", got)
	}

	got := renderChart(t, "signer.enable_annotation_interpolation=false")
	if !strings.Contains(got, "--enable-annotation-interpolation=false") {
		t.Errorf("rendered Deployment does not carry --enable-annotation-interpolation=false when the "+
			"value is set to false; the opt-out does not reach the controller:\n%s", got)
	}
}
