package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestDeploymentRendersAllowUnverifiedIdentities guards the Helm escape hatch
// for the identity-constraint default introduced in this change: the chart must
// expose --allow-unverified-identities so operators can opt out via values
// instead of hand-editing the container command.
func TestDeploymentRendersAllowUnverifiedIdentities(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed; skipping chart render assertion")
	}
	out, err := exec.Command("helm", "template", "test", "../../charts/pod-certificate-signer", "--kube-version", "1.35.0",
		// A CA source is required (the chart fails fast otherwise).
		"--set", "signer.ca.secretRef.name=test-ca").CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "--allow-unverified-identities=") {
		t.Fatalf("rendered deployment is missing the --allow-unverified-identities flag; the escape hatch is not wired into the chart:\n%s", out)
	}
}

// renderChart runs `helm template` with the required CA value and returns the
// rendered manifests, skipping the test when helm is not installed.
func renderChart(t *testing.T, extraArgs ...string) string {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed; skipping chart render assertion")
	}
	args := append([]string{
		"template", "test", "../../charts/pod-certificate-signer",
		"--kube-version", "1.35.0",
		// A CA source is required (the chart fails fast otherwise).
		"--set", "signer.ca.secretRef.name=test-ca",
	}, extraArgs...)
	out, err := exec.Command("helm", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template failed: %v\n%s", err, out)
	}
	return string(out)
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

	insecure := renderChart(t, "--set", "metrics.insecure=true")
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
	on := renderChart(t, "--set", "metrics.networkPolicy.enabled=true")
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
