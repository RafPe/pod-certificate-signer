package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
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
		// A CA source is required (the chart fails fast otherwise).
		"--set", "signer.ca.secretRef.name=test-ca",
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

// The manager must bypass the cache for Pods: the controller only does point
// Gets by name (and re-reads live via the APIReader for identity), so a
// cluster-wide pod informer wastes memory and forces list/watch RBAC the
// controller does not otherwise need.
func TestManagerOptionsDisablesPodCache(t *testing.T) {
	opts := managerOptions(k8sruntime.NewScheme(), managerConfig{baseContext: context.Background()})

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
