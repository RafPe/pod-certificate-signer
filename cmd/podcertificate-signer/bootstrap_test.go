package main

import (
	"context"
	"errors"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

const testSignerName = "example.org/signer"

// A missing ClusterTrustBundle must be reported as absence, distinctly from a
// failed read and distinctly from an empty history: retrying cannot make an
// absent object appear, and what absence means is a policy decision taken once,
// by loadPreviousCAHistory.
func TestFetchPreviousCAsNotFoundReportsAbsence(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).Build()

	certs, err := fetchPreviousCAs(context.Background(), c, testSignerName)
	if !errors.Is(err, errCAHistoryBundleAbsent) {
		t.Fatalf("fetchPreviousCAs err = %v, want it to wrap errCAHistoryBundleAbsent", err)
	}
	if len(certs) != 0 {
		t.Fatalf("history = %d certs, want 0 for a missing bundle", len(certs))
	}
}

// withFastBootstrapBackoff shortens the startup retry so a test that exercises
// the retry path does not spend its budget sleeping.
func withFastBootstrapBackoff(t *testing.T) {
	t.Helper()

	original := bootstrapBackoff
	bootstrapBackoff = wait.Backoff{Steps: 3, Duration: time.Millisecond, Factor: 1.0}
	t.Cleanup(func() { bootstrapBackoff = original })
}

// A missing bundle is the normal first-run state, so by default startup
// continues with an empty history rather than crash-looping every first
// install. It must not be retried: an absent object does not appear on the
// second read, and the retry budget exists for transient failures.
func TestLoadPreviousCAHistoryAbsentBundleStartsEmpty(t *testing.T) {
	withFastBootstrapBackoff(t)

	reads := 0
	c := fake.NewClientBuilder().
		WithScheme(clientgoscheme.Scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				reads++
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	certs, err := loadPreviousCAHistory(context.Background(), c, testSignerName, false)
	if err != nil {
		t.Fatalf("loadPreviousCAHistory err = %v, want nil so a first install can start", err)
	}
	if len(certs) != 0 {
		t.Fatalf("history = %d certs, want 0", len(certs))
	}
	if reads != 1 {
		t.Errorf("read the bundle %d times, want 1: absence must not consume the retry budget", reads)
	}
}

// An operator whose signer has already published its bundle knows that absence
// means the history was deleted, not that this is a first install. With
// --require-ca-history the controller refuses to start rather than publish a
// bundle that drops every retired CA.
func TestLoadPreviousCAHistoryAbsentBundleIsFatalWhenRequired(t *testing.T) {
	withFastBootstrapBackoff(t)

	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).Build()

	certs, err := loadPreviousCAHistory(context.Background(), c, testSignerName, true)
	if !errors.Is(err, errCAHistoryBundleAbsent) {
		t.Fatalf("loadPreviousCAHistory err = %v, want it to wrap errCAHistoryBundleAbsent", err)
	}
	if certs != nil {
		t.Fatalf("history = %v, want nil when startup fails closed", certs)
	}
}

// A transient read failure must exhaust the retry budget and then fail closed,
// whatever --require-ca-history says: an unreadable history is never the same
// as an empty one.
func TestLoadPreviousCAHistoryTransientErrorFailsClosed(t *testing.T) {
	withFastBootstrapBackoff(t)

	reads := 0
	c := fake.NewClientBuilder().
		WithScheme(clientgoscheme.Scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				reads++
				return errors.New("etcdserver: request timed out")
			},
		}).
		Build()

	if _, err := loadPreviousCAHistory(context.Background(), c, testSignerName, false); err == nil {
		t.Fatal("loadPreviousCAHistory err = nil, want the read failure so startup fails closed")
	}
	if reads != bootstrapBackoff.Steps {
		t.Errorf("read the bundle %d times, want %d retries before failing closed", reads, bootstrapBackoff.Steps)
	}
}

// A transient (non-NotFound) read error must be returned so startup can retry
// or fail closed, rather than silently returning an empty history that would
// overwrite the ClusterTrustBundle and drop previously-trusted CAs.
func TestFetchPreviousCAsTransientErrorIsReturned(t *testing.T) {
	wantErr := errors.New("etcdserver: request timed out")
	c := fake.NewClientBuilder().
		WithScheme(clientgoscheme.Scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return wantErr
			},
		}).
		Build()

	certs, err := fetchPreviousCAs(context.Background(), c, testSignerName)
	if err == nil {
		t.Fatal("fetchPreviousCAs must return an error on a transient read failure, not silently drop CA history")
	}
	if apierrors.IsNotFound(err) {
		t.Fatalf("transient error must not be reported as NotFound: %v", err)
	}
	if certs != nil {
		t.Fatalf("history = %v, want nil on error", certs)
	}
}

// An existing ClusterTrustBundle must be parsed into the previous-CA history so
// trust is retained across restarts.
func TestFetchPreviousCAsParsesExistingBundle(t *testing.T) {
	ca, err := testutil.NewCA("existing-ca.example.org", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	bundle := &certificatesv1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: signer.ClusterTrustBundleName(testSignerName)},
		Spec: certificatesv1.ClusterTrustBundleSpec{
			SignerName:  testSignerName,
			TrustBundle: string(ca.CertPEM),
		},
	}
	c := fake.NewClientBuilder().
		WithScheme(clientgoscheme.Scheme).
		WithObjects(bundle).
		Build()

	certs, err := fetchPreviousCAs(context.Background(), c, testSignerName)
	if err != nil {
		t.Fatalf("fetchPreviousCAs: %v", err)
	}
	if len(certs) != 1 || !certs[0].Equal(ca.Cert) {
		t.Fatalf("history = %v, want the single seeded CA", certs)
	}
}
