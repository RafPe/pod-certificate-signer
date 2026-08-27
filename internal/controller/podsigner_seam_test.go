package controller

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

// stubSigner is a test double for the podSigner seam on the reconciler. It
// records whether it was invoked and the configuration it received, so tests
// can assert the signing path was actually reached (and with which config).
type stubSigner struct {
	name      string
	cert      *podcertificate.PodCertificate
	err       error
	called    bool
	signings  int
	gotConfig *podcertificate.PodCertificateConfig
}

func (s *stubSigner) SignPodCertificate(cfg *podcertificate.PodCertificateConfig) (*podcertificate.PodCertificate, error) {
	s.called = true
	s.signings++
	s.gotConfig = cfg
	return s.cert, s.err
}

func (s *stubSigner) IsSignerNameMatching(n string) bool { return s.name == n }

func (s *stubSigner) Name() string { return s.name }

// newSigningHarness wires a reconciler to the given stub with a pod present and
// a PCR carrying a valid stub CSR, so process() runs the full pipeline
// and reaches SignPodCertificate. The returned context carries a discard logger
// (pcConfig.LogConfiguration reads it off the context on this path).
func newSigningHarness(t *testing.T, stub *stubSigner) (*PodCertificateRequestReconciler, *certificatesv1.PodCertificateRequest, context.Context) {
	t.Helper()

	csr, _ := newStubCSR(t)

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mypod", Namespace: "ns", UID: "pod-uid"}}
	pcr := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
		Spec: certificatesv1.PodCertificateRequestSpec{
			PodName:           "mypod",
			PodUID:            "pod-uid",
			StubPKCS10Request: csr,
		},
	}

	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pod).Build()
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub}
	ctx := logr.NewContext(context.Background(), logr.Discard())
	return r, pcr, ctx
}

// The reconciler's Signer field must be a consumer-side interface so tests can
// substitute a stub. With a stub returning a certificate, process() runs the
// full pipeline and hands back exactly that certificate.
func TestProcessReachesSigner(t *testing.T) {
	want := podcertificate.NewPodCertificate(
		nil, "pem-chain",
		&podcertificate.PodCertificateConfig{},
		time.Now(), time.Now().Add(time.Hour),
	)
	stub := &stubSigner{name: "example.org/signer", cert: want}
	r, pcr, ctx := newSigningHarness(t, stub)

	got, err := r.process(ctx, pcr)
	if err != nil {
		t.Fatalf("process() error = %v, want nil", err)
	}
	if !stub.called {
		t.Fatal("process() did not reach SignPodCertificate")
	}
	if got != want {
		t.Fatalf("process() cert = %v, want %v", got, want)
	}
}
