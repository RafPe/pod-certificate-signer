package controller

import (
	"errors"
	"testing"
)

func TestTerminalError(t *testing.T) {
	base := errors.New("boom")
	err := terminal(Reason("SigningFailed"), base)

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
	if te.Reason != Reason("SigningFailed") {
		t.Fatalf("Reason = %q, want %q", te.Reason, "SigningFailed")
	}

	var none *TerminalError
	if errors.As(errors.New("plain"), &none) {
		t.Fatal("a plain error must NOT classify as *TerminalError")
	}
}
