package main

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
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
		"helm", "template", "pod-certificate-signer", chartDir(t),
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
	return filepath.Join(filepath.Dir(file), "..", "..", "charts", "pod-certificate-signer")
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

// TestManagerOptionsSecuresMetricsByDefault asserts that, with the secure
// metrics toggle on, the metrics server is configured to require
// authentication and authorization (via controller-runtime's TokenReview /
// SubjectAccessReview filter) and to serve over HTTPS. This is the behaviour
// that rejects an unauthenticated scrape.
func TestManagerOptionsSecuresMetrics(t *testing.T) {
	opts := managerOptions(k8sruntime.NewScheme(), managerConfig{
		baseContext:   context.Background(),
		metricsSecure: true,
	})

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
	opts := managerOptions(k8sruntime.NewScheme(), managerConfig{
		baseContext:   context.Background(),
		metricsSecure: false,
	})

	if opts.Metrics.SecureServing {
		t.Error("Metrics.SecureServing = true, want false when the insecure escape hatch is set")
	}
	if opts.Metrics.FilterProvider != nil {
		t.Error("Metrics.FilterProvider is set, want nil when the insecure escape hatch is set")
	}
}

// Compile-time guarantees that both CA runnables opt into controller-runtime's
// leader-election routing explicitly, rather than relying on the implicit
// "not a LeaderElectionRunnable ⇒ leader-gated" fallback.
var (
	_ manager.Runnable               = (*caWatchRunnable)(nil)
	_ manager.Runnable               = (*ctbPublisher)(nil)
	_ manager.LeaderElectionRunnable = (*caWatchRunnable)(nil)
	_ manager.LeaderElectionRunnable = (*ctbPublisher)(nil)
)

// leaderGated mirrors how controller-runtime's runnable group routes a
// Runnable: a runnable that does not implement LeaderElectionRunnable, or that
// reports NeedLeaderElection() == true, is confined to the leader-election
// group. Encoding the real rule here means the test guards the behaviour, not
// just a literal return value.
func leaderGated(r manager.Runnable) bool {
	ler, ok := r.(manager.LeaderElectionRunnable)
	return !ok || ler.NeedLeaderElection()
}

// TestCARunnablesLeaderElection asserts that the CA file watcher runs on every
// replica (so standby replicas keep their in-memory CA current and never sign
// or publish with a stale CA after promotion), while the ClusterTrustBundle
// publisher remains restricted to the elected leader.
func TestCARunnablesLeaderElection(t *testing.T) {
	watcher, publisher := newCARunnables(nil, nil, nil)

	if leaderGated(watcher) {
		t.Error("caWatchRunnable is leader-gated; want it to run on every replica so standby CAs stay current")
	}
	if !leaderGated(publisher) {
		t.Error("ctbPublisher is not leader-gated; want ClusterTrustBundle writes confined to the leader")
	}
}

// stubHealth is a test double for the CA health surface consumed by the readyz
// check.
type stubHealth struct{ err error }

func (s stubHealth) Healthy() error { return s.err }

// TestCAReadyzCheck asserts that the readiness check passes when the CA reports
// healthy and fails when it reports a watcher/reload problem, so a replica that
// can no longer track CA rotations is removed from readiness.
func TestCAReadyzCheck(t *testing.T) {
	if err := caReadyzCheck(stubHealth{err: nil})(nil); err != nil {
		t.Errorf("readyz check = %v, want nil when the CA is healthy", err)
	}

	want := errors.New("ca watcher is down")
	if err := caReadyzCheck(stubHealth{err: want})(nil); err == nil {
		t.Error("readyz check must fail when the CA reports unhealthy")
	}
}
