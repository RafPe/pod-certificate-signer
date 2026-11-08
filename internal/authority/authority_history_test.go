package authority

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// subjects names the retained history in the order it is published, so a failed
// assertion says which CAs were kept rather than printing certificate structs.
func subjects(certs []*x509.Certificate) []string {
	names := make([]string, 0, len(certs))
	for _, cert := range certs {
		names = append(names, cert.Subject.CommonName)
	}

	return names
}

func wantHistory(t *testing.T, ca *CertificateAuthority, want ...string) {
	t.Helper()

	got := subjects(ca.previousCertificates)
	if len(got) != len(want) {
		t.Fatalf("history = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("history = %v, want %v", got, want)
		}
	}
}

// newCA generates a usable signing CA for history tests.
func newCA(t *testing.T, commonName string) *testutil.KeyPair {
	t.Helper()

	kp, err := testutil.NewCA(commonName, 24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA %s: %v", commonName, err)
	}

	return kp
}

// rotateTo points the authority at new material on disk and reloads it, the way
// a Secret update followed by a watch event or a reconcile tick does.
func rotateTo(t *testing.T, ca *CertificateAuthority, dir string, kp *testutil.KeyPair) {
	t.Helper()

	if _, _, err := kp.WriteFiles(dir); err != nil {
		t.Fatalf("write CA files: %v", err)
	}
	if _, err := ca.load(); err != nil {
		t.Fatalf("load after rotating to %s: %v", kp.Cert.Subject.CommonName, err)
	}
}

// The bound on the retained history is configuration, so a bundle read at
// startup must be trimmed to it like any other history. Without this a
// ClusterTrustBundle carrying more certificates than --max-previous-ca-certs -
// because it was edited, or written by a differently configured controller -
// became authoritative on the next restart and was republished unchanged.
//
// The options are deliberately passed with the bundle before the maximum: they
// are applied in order, so trimming inside WithPreviousCABundle would apply
// whatever bound happened to be set at that point rather than the configured
// one.
func TestBootstrappedHistoryIsTrimmedToTheConfiguredMaximum(t *testing.T) {
	dir := t.TempDir()
	current := newCA(t, "current")
	if _, _, err := current.WriteFiles(dir); err != nil {
		t.Fatalf("write CA files: %v", err)
	}

	older, old, recent := newCA(t, "older"), newCA(t, "old"), newCA(t, "recent")
	ca, err := New(dir+"/tls.crt", dir+"/tls.key",
		// The bundle as published: current CA first, then the history from
		// least to most recently active.
		WithPreviousCABundle([]*x509.Certificate{current.Cert, older.Cert, old.Cert, recent.Cert}),
		WithMaxPreviousCertificates(2),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wantHistory(t, ca, "old", "recent")
}

// A trust bundle is a cluster-scoped object the controller does not exclusively
// own. It cannot prove that an entry was ever its own CA, but it can refuse to
// carry certificates that could not have signed anything it issued, and refuse
// to spend a retention slot on an anchor no verifier would accept: entries that
// are not CAs, cannot sign certificates, have expired or are not yet valid are
// dropped instead of being adopted as history and republished.
func TestBootstrappedHistoryDropsUnusableEntries(t *testing.T) {
	dir := t.TempDir()
	current := newCA(t, "current")
	if _, _, err := current.WriteFiles(dir); err != nil {
		t.Fatalf("write CA files: %v", err)
	}

	notACA, err := testutil.NewNonCA("not-a-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate non-CA: %v", err)
	}
	expired, err := testutil.NewCA("expired", -time.Hour)
	if err != nil {
		t.Fatalf("generate expired CA: %v", err)
	}
	notYetValid, err := testutil.NewCAWithValidity("not-yet-valid",
		time.Now().Add(time.Hour), time.Now().Add(25*time.Hour))
	if err != nil {
		t.Fatalf("generate not-yet-valid CA: %v", err)
	}
	kept := newCA(t, "kept")

	ca, err := New(dir+"/tls.crt", dir+"/tls.key",
		WithPreviousCABundle([]*x509.Certificate{notACA.Cert, expired.Cert, notYetValid.Cert, kept.Cert}),
		WithMaxPreviousCertificates(4),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wantHistory(t, ca, "kept")
}

// The current CA is published from the current certificate, so a bundle that
// lists it (every bundle this controller writes does) must not also carry it as
// history: that would duplicate it in the trust bundle and spend a retention
// slot on a CA that needs none.
func TestBootstrappedHistoryDropsTheCurrentCA(t *testing.T) {
	dir := t.TempDir()
	current := newCA(t, "current")
	if _, _, err := current.WriteFiles(dir); err != nil {
		t.Fatalf("write CA files: %v", err)
	}
	previous := newCA(t, "previous")

	ca, err := New(dir+"/tls.crt", dir+"/tls.key",
		WithPreviousCABundle([]*x509.Certificate{current.Cert, previous.Cert}),
		WithMaxPreviousCertificates(2),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wantHistory(t, ca, "previous")
}

// Rotating back into a CA the history already holds must not cost a retention
// slot. A→B→C fills the two slots with A and B; flapping C→A→C then re-enters
// two certificates that are already known, and the CA that must not be lost is
// B, whose certificates can still be in the field.
//
// This is what ordering the history by identity and recency buys over ordering
// it by insertion: trimming before the current CA and the duplicates were
// removed evicted B here, silently breaking verification for workloads still
// holding a B-signed certificate.
func TestFlappingRotationDoesNotEvictAStillNeededCA(t *testing.T) {
	dir := t.TempDir()
	a, b, c := newCA(t, "A"), newCA(t, "B"), newCA(t, "C")
	if _, _, err := a.WriteFiles(dir); err != nil {
		t.Fatalf("write CA files: %v", err)
	}

	ca, err := New(dir+"/tls.crt", dir+"/tls.key", WithMaxPreviousCertificates(2))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rotateTo(t, ca, dir, b)
	wantHistory(t, ca, "A")
	rotateTo(t, ca, dir, c)
	wantHistory(t, ca, "A", "B")

	// The flap: back to A, then to C again.
	rotateTo(t, ca, dir, a)
	wantHistory(t, ca, "B", "C")
	rotateTo(t, ca, dir, c)
	wantHistory(t, ca, "B", "A")
}

// Re-observing a CA must move its entry rather than add a second one: the
// history is keyed by certificate identity, so a bundle listing the same CA
// twice, or a rotation returning to a known CA, cannot fill the window with
// duplicates of one anchor.
func TestHistoryHoldsEachCertificateOnce(t *testing.T) {
	dir := t.TempDir()
	current := newCA(t, "current")
	if _, _, err := current.WriteFiles(dir); err != nil {
		t.Fatalf("write CA files: %v", err)
	}
	previous, other := newCA(t, "previous"), newCA(t, "other")

	ca, err := New(dir+"/tls.crt", dir+"/tls.key",
		WithPreviousCABundle([]*x509.Certificate{previous.Cert, other.Cert, previous.Cert}),
		WithMaxPreviousCertificates(3),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The later occurrence is the more recent one, so "previous" ends up after
	// "other" rather than appearing twice.
	wantHistory(t, ca, "other", "previous")
}
