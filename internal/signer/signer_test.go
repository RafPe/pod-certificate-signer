package signer

import (
	"testing"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// newTestSigner builds a Signer over a freshly generated CA on disk.
func newTestSigner(t *testing.T, name string) *Signer {
	t.Helper()
	kp, err := testutil.NewCA("ca.example.org", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	certPath, keyPath, err := kp.WriteFiles(t.TempDir())
	if err != nil {
		t.Fatalf("write CA files: %v", err)
	}
	ca, err := authority.New(certPath, keyPath)
	if err != nil {
		t.Fatalf("authority.New: %v", err)
	}
	s, err := New(name, ca)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// A signer answers only for its own signer name: that comparison is what keeps
// a request addressed to another signer out of this controller's pipeline.
func TestSignerNameMatching(t *testing.T) {
	s := newTestSigner(t, "example.org/signer")

	if got := s.Name(); got != "example.org/signer" {
		t.Errorf("Name() = %q, want the configured signer name", got)
	}
	if !s.IsSignerNameMatching("example.org/signer") {
		t.Error("IsSignerNameMatching must accept the configured name")
	}
	for _, other := range []string{"example.org/other", "EXAMPLE.ORG/signer", ""} {
		if s.IsSignerNameMatching(other) {
			t.Errorf("IsSignerNameMatching(%q) = true, want an exact match only", other)
		}
	}
}
