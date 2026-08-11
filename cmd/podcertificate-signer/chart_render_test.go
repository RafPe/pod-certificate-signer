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
