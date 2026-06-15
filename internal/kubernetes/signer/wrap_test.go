package signer

import (
	"errors"
	"testing"
)

// ParsePkixPublicKey must wrap the underlying x509 error so it can be unwrapped.
func TestParsePkixPublicKeyWraps(t *testing.T) {
	s := &Signer{} // zero value is fine: ParsePkixPublicKey does not touch the CA
	_, _, err := s.ParsePkixPublicKey([]byte("not-a-der-encoded-key"))
	if err == nil {
		t.Fatal("expected an error parsing junk input")
	}
	if errors.Unwrap(err) == nil {
		t.Fatal("error should wrap the underlying cause (%w), got an unwrappable error")
	}
}
