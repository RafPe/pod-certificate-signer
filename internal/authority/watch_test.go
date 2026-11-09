package authority

import (
	"context"
	"testing"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// rewriteCA writes kp's files into dir again, byte for byte, so a watcher
// that missed an earlier write sees a fresh event for the same material.
func rewriteCA(t *testing.T, dir string, kp *testutil.KeyPair) {
	t.Helper()
	if _, _, err := kp.WriteFiles(dir); err != nil {
		t.Fatalf("rewrite CA files: %v", err)
	}
}

// Watch must reload the CA when the files change and notify the caller.
func TestWatchReloadsCA(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "ca-1.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notify := make(chan struct{}, 1)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- ca.Watch(ctx, notify)
	}()

	// There is no signal for "the directory watch is registered", so rather
	// than guess at a delay, keep rewriting the rotated material until the
	// watcher reports a change: a write that lands before the watch exists
	// produces no event, the next one does. The files are identical on every
	// pass, so whichever write is observed loads the same certificate.
	rotated := writeCA(t, dir, "ca-2.example.org", 24*time.Hour)
	deadline := time.After(15 * time.Second)
	retry := time.NewTicker(50 * time.Millisecond)
	defer retry.Stop()
waitForReload:
	for {
		select {
		case <-notify:
			break waitForReload
		case <-retry.C:
			rewriteCA(t, dir, rotated)
		case <-deadline:
			t.Fatal("timed out waiting for the CA reload notification")
		}
	}

	bundle := parseChain(t, ca.TrustBundlePEM())
	if !bundle[0].Equal(rotated.Cert) {
		t.Fatal("current CA must be the rotated certificate after reload")
	}

	cancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("Watch returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not return after context cancellation")
	}
}
