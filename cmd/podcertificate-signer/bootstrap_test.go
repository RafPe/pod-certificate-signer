package main

import (
	"context"
	"errors"
	"testing"
	"time"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

const testSignerName = "example.org/signer"

// A missing ClusterTrustBundle is the normal first-run state and must yield an
// empty history with no error, not an error.
func TestFetchPreviousCAsNotFoundIsEmptyHistory(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).Build()

	certs, err := fetchPreviousCAs(context.Background(), c, testSignerName)
	if err != nil {
		t.Fatalf("fetchPreviousCAs returned error for a missing bundle: %v", err)
	}
	if len(certs) != 0 {
		t.Fatalf("history = %d certs, want 0 for a missing bundle", len(certs))
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

	bundle := &certificatesv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: signer.ClusterTrustBundleName(testSignerName)},
		Spec: certificatesv1beta1.ClusterTrustBundleSpec{
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
