package controller

import (
	"errors"
	"testing"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	certificatesv1 "k8s.io/api/certificates/v1"
)

func TestTerminalError(t *testing.T) {
	base := errors.New("boom")
	err := failed(base)

	if err.Error() != "boom" {
		t.Fatalf("Error() = %q, want %q", err.Error(), "boom")
	}
	if !errors.Is(err, base) {
		t.Fatal("errors.Is should find the wrapped base error")
	}

	var te *TerminalError
	if !errors.As(err, &te) {
		t.Fatal("errors.As should match *TerminalError")
	}
	if te.Reason != outcome.SigningFailed {
		t.Fatalf("Reason = %q, want %q", te.Reason, outcome.SigningFailed)
	}
	if te.conditionType() != certificatesv1.PodCertificateRequestConditionTypeFailed {
		t.Fatalf("ConditionType = %q, want Failed", te.conditionType())
	}

	var none *TerminalError
	if errors.As(errors.New("plain"), &none) {
		t.Fatal("a plain error must NOT classify as *TerminalError")
	}
}

func TestDeniedConditionType(t *testing.T) {
	var te *TerminalError
	if !errors.As(denied(outcome.UnsupportedKeyType, errors.New("bad key")), &te) {
		t.Fatal("errors.As should match *TerminalError")
	}
	if te.conditionType() != certificatesv1.PodCertificateRequestConditionTypeDenied {
		t.Fatalf("ConditionType = %q, want Denied", te.conditionType())
	}
	if te.Reason != outcome.UnsupportedKeyType {
		t.Fatalf("Reason = %q, want %q", te.Reason, outcome.UnsupportedKeyType)
	}
}
