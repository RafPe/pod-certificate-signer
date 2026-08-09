package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// An empty --signer-name must be rejected fast, before the controller attempts
// any Kubernetes API calls, mirroring the required --ca-cert-path handling.
func TestValidateFlagsRequiresSignerName(t *testing.T) {
	if err := validateFlags(""); err == nil {
		t.Error("validateFlags(\"\") = nil, want error for empty signer name")
	}
	if err := validateFlags("example.org/signer"); err != nil {
		t.Errorf("validateFlags(%q) = %v, want nil", "example.org/signer", err)
	}
}

// The rendered Deployment must pass --cluster-fqdn and
// --health-probe-bind-address to the manager, so the corresponding chart
// values actually reach the controller instead of silently falling back to the
// binary defaults.
func TestDeploymentRendersConfiguredFlags(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skipf("helm not installed: %v", err)
	}

	out, err := exec.Command(
		"helm", "template", "podcertificate-signer", chartDir(t),
		"--kube-version", "1.36.0",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}

	for _, want := range []string{"--cluster-fqdn=", "--health-probe-bind-address="} {
		if !strings.Contains(string(out), want) {
			t.Errorf("rendered Deployment is missing flag %q", want)
		}
	}
}

func chartDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "charts", "podcertificate-signer")
}
