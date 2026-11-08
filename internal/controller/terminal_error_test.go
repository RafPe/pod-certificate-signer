package controller

import (
	"errors"
	"testing"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
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
	if te.Reason != metrics.ReasonSigningFailed {
		t.Fatalf("metrics.Reason = %q, want %q", te.Reason, metrics.ReasonSigningFailed)
	}
	if te.ConditionType != certificatesv1.PodCertificateRequestConditionTypeFailed {
		t.Fatalf("ConditionType = %q, want Failed", te.ConditionType)
	}

	var none *TerminalError
	if errors.As(errors.New("plain"), &none) {
		t.Fatal("a plain error must NOT classify as *TerminalError")
	}
}

func TestDeniedConditionType(t *testing.T) {
	var te *TerminalError
	if !errors.As(denied(metrics.ReasonUnsupportedKeyType, errors.New("bad key")), &te) {
		t.Fatal("errors.As should match *TerminalError")
	}
	if te.ConditionType != certificatesv1.PodCertificateRequestConditionTypeDenied {
		t.Fatalf("ConditionType = %q, want Denied", te.ConditionType)
	}
	if te.Reason != metrics.ReasonUnsupportedKeyType {
		t.Fatalf("metrics.Reason = %q, want %q", te.Reason, metrics.ReasonUnsupportedKeyType)
	}
}
