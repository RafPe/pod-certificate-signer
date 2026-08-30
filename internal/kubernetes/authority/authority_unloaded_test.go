package authority

import (
	"errors"
	"testing"
	"time"
)

// unloadedAuthority builds a CertificateAuthority that holds no certificate,
// the state every construction path other than a fully successful New would
// leave behind. New fails closed today, so this is the seam that reaches the
// nil-certificate guards at all.
func unloadedAuthority(t *testing.T) *CertificateAuthority {
	t.Helper()
	return &CertificateAuthority{
		backDate: time.Minute,
		nowFunc:  time.Now,
	}
}

// Sign must fail closed, not panic, when the authority holds no certificate.
// The invariant "an authority always holds a certificate" is enforced only by
// New failing closed; any construction path that defers the first load would
// otherwise turn this call into a nil-pointer panic. The error is classified
// under ErrCASignerUnusable so callers treat it as "CA unusable, requeue",
// exactly like an expired signer.
func TestSignFailsClosedWhenNoCertificateLoaded(t *testing.T) {
	ca := unloadedAuthority(t)

	pc, err := ca.Sign(testConfig(t))
	if err == nil {
		t.Fatal("Sign() error = nil, want an error when no certificate is loaded")
	}
	if !errors.Is(err, ErrCASignerUnusable) {
		t.Errorf("Sign() error = %v, want errors.Is(err, ErrCASignerUnusable)", err)
	}
	if pc != nil {
		t.Errorf("Sign() = %v, want nil certificate on error", pc)
	}
}

// CertificateNotAfter runs on every metrics scrape via the CA collector, which
// is not a reconcile: a panic there takes down the scrape rather than being
// recovered. With no certificate it must report the zero time, which the
// collector already renders as a 0 gauge (see metrics.timestamp).
func TestCertificateNotAfterIsZeroWhenNoCertificateLoaded(t *testing.T) {
	ca := unloadedAuthority(t)

	if got := ca.CertificateNotAfter(); !got.IsZero() {
		t.Errorf("CertificateNotAfter() = %v, want the zero time", got)
	}
}

// With a certificate loaded, CertificateNotAfter reports its expiry. Pinned
// here because the method backs the ca_expiration_timestamp_seconds gauge and
// had no covering test at all.
func TestCertificateNotAfterReportsLoadedExpiry(t *testing.T) {
	dir := t.TempDir()
	kp := writeCA(t, dir, "ca.example.org", 24*time.Hour)
	ca, err := New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got, want := ca.CertificateNotAfter(), kp.Cert.NotAfter; !got.Equal(want) {
		t.Errorf("CertificateNotAfter() = %v, want %v", got, want)
	}
}
