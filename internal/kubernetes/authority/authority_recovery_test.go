package authority

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// A failed reload must not discard the in-memory CA; a later good write must
// reload cleanly. Retaining the last-good CA keeps signing working across a
// transient bad update on disk.
func TestReloadRetainsLastGoodCAOnFailure(t *testing.T) {
	dir := t.TempDir()
	good := writeCA(t, dir, "good-ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Overwrite with a non-CA certificate: the reload must fail.
	nonCA, err := testutil.NewNonCA("not-a-ca.example.org", time.Hour)
	if err != nil {
		t.Fatalf("generate non-CA: %v", err)
	}
	if _, _, err := nonCA.WriteFiles(dir); err != nil {
		t.Fatalf("write non-CA files: %v", err)
	}

	if _, err := ca.load(); err == nil {
		t.Fatal("want error reloading a non-CA certificate")
	}
	if got := parseChain(t, ca.TrustBundlePEM()); len(got) == 0 || !got[0].Equal(good.Cert) {
		t.Fatal("must retain the last-good CA after a failed reload")
	}

	// A subsequent good write must reload.
	good2 := writeCA(t, dir, "good-ca-2.example.org", 24*time.Hour)
	if _, err := ca.load(); err != nil {
		t.Fatalf("reload after good write: %v", err)
	}
	if got := parseChain(t, ca.TrustBundlePEM()); !got[0].Equal(good2.Cert) {
		t.Fatal("must reload the new good CA")
	}
}

// A mismatched cert/key pair on disk (e.g. observed mid-rotation, before the
// key catches up) must be retried, not abandoned, so an eventually-consistent
// good pair is picked up.
func TestReloadWithRetryRecoversFromTransientBadPair(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "good-ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ca.reloadBackoff = 20 * time.Millisecond
	ca.reloadAttempts = 100

	// Write a mismatched pair: certificate of one CA, key of another. This
	// fails tls.LoadX509KeyPair's public/private key consistency check.
	a, err := testutil.NewCA("a.example.org", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA a: %v", err)
	}
	b, err := testutil.NewCA("b.example.org", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA b: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), a.CertPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), b.KeyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := ca.load(); err == nil {
		t.Fatal("want error for mismatched key pair")
	}

	// After a short delay a consistent good pair appears on disk.
	rotated, err := testutil.NewCA("recovered.example.org", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate rotated CA: %v", err)
	}
	go func() {
		time.Sleep(120 * time.Millisecond)
		_ = os.WriteFile(filepath.Join(dir, "tls.key"), rotated.KeyPEM, 0o600)
		_ = os.WriteFile(filepath.Join(dir, "tls.crt"), rotated.CertPEM, 0o600)
	}()

	ctx := context.Background()
	if _, err := ca.reloadWithRetry(ctx, log.FromContext(ctx)); err != nil {
		t.Fatalf("reloadWithRetry did not recover from a transient bad pair: %v", err)
	}
	if got := parseChain(t, ca.TrustBundlePEM()); !got[0].Equal(rotated.Cert) {
		t.Fatal("must load the recovered CA after retrying")
	}
}

// reloadWithRetry must give up (and stop looping) once ctx is canceled, rather
// than blocking forever on a permanently bad pair.
func TestReloadWithRetryHonorsContextCancellation(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "good-ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ca.reloadBackoff = 50 * time.Millisecond
	ca.reloadAttempts = 1_000_000

	// Permanently bad: a non-CA certificate.
	nonCA, err := testutil.NewNonCA("bad.example.org", time.Hour)
	if err != nil {
		t.Fatalf("generate non-CA: %v", err)
	}
	if _, _, err := nonCA.WriteFiles(dir); err != nil {
		t.Fatalf("write non-CA files: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := ca.reloadWithRetry(ctx, log.FromContext(ctx))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reloadWithRetry must return an error when it cannot reload before ctx is canceled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reloadWithRetry ignored context cancellation")
	}
}

// A closed fsnotify events channel must terminate the watch loop promptly and
// mark the CA unhealthy, rather than spinning on zero values.
func TestWatchLoopReturnsOnClosedEventsChannel(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	events := make(chan fsnotify.Event)
	errs := make(chan error) // open, never sends
	close(events)

	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- ca.watchLoop(ctx, log.FromContext(ctx), events, errs, nil) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("watchLoop must return an error when the events channel closes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchLoop spun on a closed events channel instead of returning")
	}
	if ca.Healthy() == nil {
		t.Error("Healthy must report the failure after the watch loop dies")
	}
}

// A closed fsnotify errors channel must likewise terminate the watch loop.
func TestWatchLoopReturnsOnClosedErrorsChannel(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	events := make(chan fsnotify.Event) // open, never sends
	errs := make(chan error)
	close(errs)

	ctx := context.Background()
	done := make(chan error, 1)
	go func() { done <- ca.watchLoop(ctx, log.FromContext(ctx), events, errs, nil) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("watchLoop must return an error when the errors channel closes")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watchLoop spun on a closed errors channel instead of returning")
	}
}

// A freshly-loaded CA with a live watch loop must report healthy.
func TestHealthyReportsNilForLiveCA(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := ca.Healthy(); err != nil {
		t.Errorf("Healthy = %v, want nil for a freshly-loaded CA", err)
	}
}
