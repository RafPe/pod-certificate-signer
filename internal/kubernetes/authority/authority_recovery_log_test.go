package authority

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// reloadSucceededLine is the message test/e2e/ca_lifecycle_test.go greps for.
// Keep the two in step: the e2e suite has no other observable for "the CA is
// loadable again", so changing this string silently breaks that spec.
const reloadSucceededLine = "CA certificate reloaded successfully"

// captureLogger records messages at verbosity 0 - the production default, where
// V(1) is dropped. Asserting against it is what makes "the operator can see
// this" a property of the test rather than an assumption.
func captureLogger(lines *[]string) logr.Logger {
	return funcr.New(func(_, args string) {
		*lines = append(*lines, args)
	}, funcr.Options{Verbosity: 0})
}

// A reload that succeeds after a failure must announce itself even when the
// material did not change.
//
// Correcting a mismatched pair restores the *same* certificate, so the
// fingerprint gate added for periodic reconciliation reports "unchanged" and the
// only record would be a V(1) line - dropped at the default verbosity, leaving
// an operator who has just fixed the CA with no confirmation at all. That is
// also the property the e2e spec "a good write after a bad one must reload on
// its own" waits for; it timed out because this line was suppressed.
func TestReconcileAnnouncesRecoveryWithoutChange(t *testing.T) {
	dir := t.TempDir()
	good := writeCA(t, dir, "good-ca.example.org", 24*time.Hour)

	ca, err := New(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Break the pair: the good certificate with a foreign key. This is the
	// case that matters, because the certificate on disk never changes - so
	// recovery cannot be detected by comparing fingerprints.
	foreign, err := testutil.NewCA("foreign.example.org", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate foreign CA: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), foreign.KeyPEM, 0o600); err != nil {
		t.Fatalf("write foreign key: %v", err)
	}

	var lines []string
	logger := captureLogger(&lines)

	ca.reconcileOnce(logger, nil, "test")
	if ca.failureCount() == 0 {
		t.Fatal("the mismatched pair must record a reload failure, otherwise this test proves nothing")
	}

	// Restore the original key. The certificate is byte-identical to the one
	// already loaded, so load() reports changed=false.
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), good.KeyPEM, 0o600); err != nil {
		t.Fatalf("restore key: %v", err)
	}

	lines = nil
	ca.reconcileOnce(logger, nil, "test")

	if ca.failureCount() != 0 {
		t.Errorf("failureCount = %d, want 0: a successful reload must clear the streak", ca.failureCount())
	}
	if !containsLine(lines, reloadSucceededLine) {
		t.Errorf("recovery was not announced at the default verbosity; logged: %v", lines)
	}
}

// The converse: a routine unchanged reload must stay quiet, or the recovery
// line becomes noise on every tick and the e2e count-based assertion is
// meaningless.
func TestReconcileStaysQuietWhenNothingChangedAndNothingFailed(t *testing.T) {
	dir := t.TempDir()
	writeCA(t, dir, "good-ca.example.org", 24*time.Hour)

	ca, err := New(filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	var lines []string
	logger := captureLogger(&lines)

	ca.reconcileOnce(logger, nil, "test")

	if containsLine(lines, reloadSucceededLine) {
		t.Errorf("an unchanged reload after no failure must not announce itself; logged: %v", lines)
	}
}

func containsLine(lines []string, want string) bool {
	for _, line := range lines {
		if strings.Contains(line, want) {
			return true
		}
	}

	return false
}
