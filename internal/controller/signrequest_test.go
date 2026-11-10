package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
)

// stubSigner is a test double for the podSigner seam on the reconciler. It
// records whether it was invoked and the configuration it received, so tests
// can assert the signing path was actually reached (and with which config).
// name is the signer name the reconciler built around it answers for.
type stubSigner struct {
	name      string
	cert      *podcertificate.Certificate
	err       error
	called    bool
	signings  int
	gotConfig *podcertificate.Config
}

func (s *stubSigner) Sign(cfg *podcertificate.Config) (*podcertificate.Certificate, error) {
	s.called = true
	s.signings++
	s.gotConfig = cfg
	return s.cert, s.err
}

// newSigningHarness wires a reconciler to the given stub with a pod present and
// a PCR carrying a valid stub CSR, so signRequest() runs the full pipeline
// and reaches Sign. The returned context carries a discard logger
// for the config resolver.
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
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub, SignerName: stub.name}
	ctx := logr.NewContext(context.Background(), logr.Discard())
	return r, pcr, ctx
}

// The reconciler's Signer field must be a consumer-side interface so tests can
// substitute a stub. With a stub returning a certificate, signRequest() runs the
// full pipeline and hands back exactly that certificate.
func TestProcessReachesSigner(t *testing.T) {
	want := &podcertificate.Certificate{CertificateChain: "pem-chain", Config: &podcertificate.Config{}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	stub := &stubSigner{name: "example.org/signer", cert: want}
	r, pcr, ctx := newSigningHarness(t, stub)

	got, err := r.signRequest(ctx, pcr)
	if err != nil {
		t.Fatalf("signRequest() error = %v, want nil", err)
	}
	if !stub.called {
		t.Fatal("signRequest() did not reach SignPodCertificate")
	}
	if got != want {
		t.Fatalf("signRequest() cert = %v, want %v", got, want)
	}
}

// A pod name whose DNS label exceeds the 63-character limit gets no default pod
// DNS SANs, because truncating would let two pods sharing a prefix impersonate
// each other. The drop is not fatal - at 64 characters the common name still
// carries the identity, so the certificate issues - but the operator must be
// told, so signRequest() emits a Warning event explaining why the default SAN was
// dropped.
func TestProcessLongPodNameEmitsDefaultSANWarning(t *testing.T) {
	pcr, pod := livePCR(t, "uid-long", "uid-long")
	longName := strings.Repeat("a", 64)
	pcr.Spec.PodName = longName
	pod.Name = longName

	cache := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pod).Build()
	stub := &stubSigner{name: "example.org/signer", cert: stubCert()}
	rec := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{
		Client: cache, APIReader: cache, Log: logr.Discard(), Signer: stub, SignerName: stub.name, EventRecorder: rec,
	}
	ctx := logr.NewContext(context.Background(), logr.Discard())

	cert, err := r.signRequest(ctx, pcr)
	if err != nil {
		t.Fatalf("signRequest() error = %v, want nil (the CN carries the identity)", err)
	}
	if cert == nil {
		t.Fatal("signRequest() cert = nil, want the signed certificate")
	}

	select {
	case e := <-rec.Events:
		if !strings.Contains(e, corev1.EventTypeWarning) {
			t.Errorf("event = %q, want a %s event", e, corev1.EventTypeWarning)
		}
		if !strings.Contains(e, string(outcome.DefaultSANSkipped)) {
			t.Errorf("event = %q, want reason %s", e, outcome.DefaultSANSkipped)
		}
		if !strings.Contains(e, "DNS label limit") {
			t.Errorf("event = %q, want it to explain the DNS label limit", e)
		}
	default:
		t.Fatal("no event recorded, want one warning event for the skipped default SAN")
	}
}

// A CA-availability error surfaced by the signer must be classified TRANSIENT:
// signRequest() returns a plain error (so controller-runtime requeues) that still
// carries authority.ErrCASignerUnusable. A request-specific signing error must
// stay terminal (*terminalError -> Failed/SigningFailed, recorded on the PCR).
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

			cert, err := r.signRequest(ctx, pcr)
			if cert != nil {
				t.Fatalf("signRequest() cert = %v, want nil", cert)
			}
			if !stub.called {
				t.Fatal("signRequest() did not reach SignPodCertificate")
			}

			var te *terminalError
			gotTerminal := errors.As(err, &te)
			if gotTerminal != tc.wantTerminal {
				t.Fatalf("signRequest() terminal = %v (err = %v), want terminal = %v", gotTerminal, err, tc.wantTerminal)
			}
			if !tc.wantTerminal && !errors.Is(err, authority.ErrCASignerUnusable) {
				t.Fatalf("transient err = %v, want it to still wrap ErrCASignerUnusable", err)
			}
		})
	}
}

// livePCR returns a PCR carrying a valid stub CSR that expects the pod
// identified by requestUID, plus a pod object stamped with podUID.
func livePCR(t *testing.T, requestUID, podUID types.UID) (*certificatesv1.PodCertificateRequest, *corev1.Pod) {
	t.Helper()

	csr, _ := newStubCSR(t)

	pcr := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
		Spec: certificatesv1.PodCertificateRequestSpec{
			PodName:           "mypod",
			PodUID:            requestUID,
			StubPKCS10Request: csr,
		},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mypod", Namespace: "ns", UID: podUID}}
	return pcr, pod
}

func stubCert() *podcertificate.Certificate {
	return &podcertificate.Certificate{CertificateChain: "pem-chain", Config: &podcertificate.Config{}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
}

// When the manager cache misses but the pod exists on a live read, the
// controller must re-read via the APIReader and proceed to sign, instead of
// recording a terminal AssociatedPodNotFound on a cache/creation race.
func TestProcessCacheMissReadsLive(t *testing.T) {
	pcr, pod := livePCR(t, "uid-1", "uid-1")
	cache := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build() // pod absent from cache
	live := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pod).Build()
	stub := &stubSigner{name: "example.org/signer", cert: stubCert()}
	r := &PodCertificateRequestReconciler{Client: cache, APIReader: live, Log: logr.Discard(), Signer: stub, SignerName: stub.name}
	ctx := logr.NewContext(context.Background(), logr.Discard())

	cert, err := r.signRequest(ctx, pcr)
	if err != nil {
		t.Fatalf("signRequest() error = %v, want nil (live read should find the pod)", err)
	}
	if !stub.called {
		t.Fatal("signRequest() did not reach the signer after the live re-read")
	}
	if cert == nil {
		t.Fatal("signRequest() cert = nil, want the signed certificate")
	}
	// The config must be built from the pod found on the live read.
	if stub.gotConfig == nil || stub.gotConfig.CommonName != "mypod" {
		t.Fatalf("signed config = %+v, want CommonName %q from the live pod", stub.gotConfig, "mypod")
	}
}

// When the pod that exists has a UID different from the request's PodUID, the
// request is stale: the controller must drop it (errDropRequest) and must NOT sign
// with the wrong pod's identity.
func TestProcessStalePodUIDDropped(t *testing.T) {
	pcr, stalePod := livePCR(t, "uid-1", "uid-stale")
	cache := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(stalePod).Build()
	live := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(stalePod).Build()
	stub := &stubSigner{name: "example.org/signer", cert: stubCert()}
	// The drop path emits an event; see TestReconcileDroppedGonePodEmitsEvent.
	r := &PodCertificateRequestReconciler{
		Client: cache, APIReader: live, Log: logr.Discard(), Signer: stub, SignerName: stub.name, EventRecorder: events.NewFakeRecorder(10),
	}
	ctx := logr.NewContext(context.Background(), logr.Discard())

	cert, err := r.signRequest(ctx, pcr)
	if cert != nil || !errors.Is(err, errDropRequest) {
		t.Fatalf("got (%v, %v), want (nil, errDropRequest) for a UID-mismatched pod", cert, err)
	}
	if stub.called {
		t.Fatal("signer must not run for a UID-mismatched (stale) pod")
	}
}

func testPCR() *certificatesv1.PodCertificateRequest {
	return &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
		Spec:       certificatesv1.PodCertificateRequestSpec{PodName: "mypod"},
	}
}

// signRequest() must drop (errDropRequest) when the pod is absent from both the cache and
// a live read: the request is stale, not a terminal failure to sign.
func TestProcessPodNotFoundDropsAsStale(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	// The drop path emits an event; see TestReconcileDroppedGonePodEmitsEvent.
	r := &PodCertificateRequestReconciler{
		Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10),
	}

	cert, err := r.signRequest(context.Background(), testPCR())
	if cert != nil || !errors.Is(err, errDropRequest) {
		t.Fatalf("got (%v, %v), want (nil, errDropRequest) for a stale request", cert, err)
	}
}

// signRequest() must treat a non-NotFound pod GET error as transient (not terminal).
func TestProcessPodGetErrorIsTransient(t *testing.T) {
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return apierrors.NewServiceUnavailable("apiserver down")
			},
		}).
		Build()
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard()}

	cert, err := r.signRequest(context.Background(), testPCR())
	if cert != nil {
		t.Fatalf("cert = %v, want nil", cert)
	}
	if err == nil {
		t.Fatal("want a transient error, got nil")
	}
	var te *terminalError
	if errors.As(err, &te) {
		t.Fatalf("err = %v, must NOT be terminal", err)
	}
}

// signRequest() must drop (errDropRequest) when the associated pod is being deleted.
func TestProcessPodBeingDeletedSkips(t *testing.T) {
	now := metav1.Now()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:              "mypod",
		Namespace:         "ns",
		DeletionTimestamp: &now,
		Finalizers:        []string{"keep"}, // fake client requires a finalizer to retain DeletionTimestamp
	}}
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pod).Build()
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard()}

	cert, err := r.signRequest(context.Background(), testPCR())
	if cert != nil || !errors.Is(err, errDropRequest) {
		t.Fatalf("got (%v, %v), want (nil, errDropRequest)", cert, err)
	}
}

// requeueOrRecordTerminal: a terminal error writes a condition and does not requeue.
func TestRecordFailureTerminalWritesCondition(t *testing.T) {
	pcr := testPCR()
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		Build()
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10)}

	res, err := r.requeueOrRecordTerminal(context.Background(), pcr, failed(errors.New("x")))
	if err != nil {
		t.Fatalf("requeueOrRecordTerminal returned err = %v, want nil", err)
	}
	if res != (ctrl.Result{}) {
		t.Fatalf("result = %+v, want empty (no requeue)", res)
	}
	got := &certificatesv1.PodCertificateRequest{}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Conditions) != 1 {
		t.Fatalf("conditions = %d, want 1", len(got.Status.Conditions))
	}
}

// requeueOrRecordTerminal: a transient error is returned (requeue) and writes no condition.
func TestRecordFailureTransientRequeues(t *testing.T) {
	pcr := testPCR()
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		Build()
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10)}

	sentinel := errors.New("apiserver blip")
	if _, err := r.requeueOrRecordTerminal(context.Background(), pcr, sentinel); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel returned for requeue", err)
	}
	got := &certificatesv1.PodCertificateRequest{}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Conditions) != 0 {
		t.Fatalf("conditions = %d, want 0 (transient must not write)", len(got.Status.Conditions))
	}
}

// requeueOrRecordTerminal: when recording a terminal outcome fails because the status
// write itself errors, that write error is returned so the reconcile requeues
// (the Failed condition is never silently lost).
func TestRecordFailureWriteErrorRequeues(t *testing.T) {
	pcr := testPCR()
	writeErr := errors.New("status write failed")
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				return writeErr
			},
		}).
		Build()
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10)}

	if _, err := r.requeueOrRecordTerminal(context.Background(), pcr, failed(errors.New("boom"))); !errors.Is(err, writeErr) {
		t.Fatalf("err = %v, want the status-write error returned for requeue", err)
	}
}
