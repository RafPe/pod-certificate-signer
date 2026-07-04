package signer

import (
	"errors"
	"testing"
)

// ParsePKIXPublicKey must wrap the underlying x509 error so it can be unwrapped.
func TestParsePKIXPublicKeyWraps(t *testing.T) {
	_, _, err := ParsePKIXPublicKey([]byte("not-a-der-encoded-key"))
	if err == nil {
		t.Fatal("expected an error parsing junk input")
	}
	if errors.Unwrap(err) == nil {
		t.Fatal("error should wrap the underlying cause (%w), got an unwrappable error")
	}
}

// ParseCSRPublicKey must wrap the underlying x509 error so it can be unwrapped.
func TestParseCSRPublicKeyWraps(t *testing.T) {
	_, _, err := ParseCSRPublicKey([]byte("not-a-der-encoded-csr"))
	if err == nil {
		t.Fatal("expected an error parsing junk input")
	}
	if errors.Unwrap(err) == nil {
		t.Fatal("error should wrap the underlying cause (%w), got an unwrappable error")
	}
}

// ClusterTrustBundleName must follow the <domain>:<path>:<name> convention.
func TestClusterTrustBundleName(t *testing.T) {
	got := ClusterTrustBundleName("example.org/signer")
	want := "example.org:signer:bundle"
	if got != want {
		t.Fatalf("ClusterTrustBundleName = %q, want %q", got, want)
	}
}
