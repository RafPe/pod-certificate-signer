package controller

import (
	"errors"
	"fmt"
	"testing"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
)

// A CA-availability error surfaced by the signer must be classified TRANSIENT:
// process() returns a plain error (so controller-runtime requeues) that still
// carries authority.ErrCASignerUnusable. A request-specific signing error must
// stay terminal (*TerminalError -> Failed/SigningFailed, recorded on the PCR).
func TestProcessClassifiesSignerErrors(t *testing.T) {
	cases := []struct {
		name         string
		signErr      error
		wantTerminal bool
	}{
		{
			name:         "expired signer is transient",
			signErr:      fmt.Errorf("the signer has expired: NotAfter=x: %w", authority.ErrCASignerUnusable),
			wantTerminal: false,
		},
		{
			name:         "exceeds CA validity is transient",
			signErr:      fmt.Errorf("certificate validity period exceeds the signer CA validity: %w", authority.ErrCASignerUnusable),
			wantTerminal: false,
		},
		{
			name:         "request-specific error stays terminal",
			signErr:      errors.New("certificate not after is in the past"),
			wantTerminal: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubSigner{name: "example.org/signer", err: tc.signErr}
			r, pcr, ctx := newSigningHarness(t, stub)

			cert, err := r.process(ctx, pcr)
			if cert != nil {
				t.Fatalf("process() cert = %v, want nil", cert)
			}
			if !stub.called {
				t.Fatal("process() did not reach SignPodCertificate")
			}

			var te *TerminalError
			gotTerminal := errors.As(err, &te)
			if gotTerminal != tc.wantTerminal {
				t.Fatalf("process() terminal = %v (err = %v), want terminal = %v", gotTerminal, err, tc.wantTerminal)
			}
			if !tc.wantTerminal && !errors.Is(err, authority.ErrCASignerUnusable) {
				t.Fatalf("transient err = %v, want it to still wrap ErrCASignerUnusable", err)
			}
		})
	}
}
