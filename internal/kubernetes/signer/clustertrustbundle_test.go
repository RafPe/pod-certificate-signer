package signer

import (
	"strings"
	"testing"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// ClusterTrustBundle must derive the resource from the signer name and embed
// the full CA trust bundle, including previously known CAs.
func TestClusterTrustBundleObject(t *testing.T) {
	dir := t.TempDir()
	kp, err := testutil.NewCA("ca.example.org", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	certPath, keyPath, err := kp.WriteFiles(dir)
	if err != nil {
		t.Fatalf("write CA files: %v", err)
	}
	ca, err := authority.New(certPath, keyPath)
	if err != nil {
		t.Fatalf("authority.New: %v", err)
	}

	s, err := New("example.org/signer", ca)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bundle := s.ClusterTrustBundle()
	if bundle.Name != "example.org:signer:bundle" {
		t.Errorf("Name = %q, want example.org:signer:bundle", bundle.Name)
	}
	if bundle.Spec.SignerName != "example.org/signer" {
		t.Errorf("SignerName = %q, want example.org/signer", bundle.Spec.SignerName)
	}
	if bundle.Spec.TrustBundle != string(ca.TrustBundlePEM()) {
		t.Error("TrustBundle must match the CA trust bundle PEM")
	}
	if !strings.Contains(bundle.Spec.TrustBundle, string(kp.CertPEM)) {
		t.Error("TrustBundle must contain the CA certificate")
	}
}

// New must reject incomplete input.
func TestNewValidatesInput(t *testing.T) {
	if _, err := New("", nil); err == nil {
		t.Error("want error for empty signer name")
	}
	if _, err := New("example.org/signer", nil); err == nil {
		t.Error("want error for nil CA")
	}
}
