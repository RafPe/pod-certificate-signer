package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
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
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
)

// A terminal outcome must be counted once, under the outcome and reason the
// object records.
func TestTerminalOutcomesAreCounted(t *testing.T) {
	cases := []struct {
		name        string
		reason      outcome.ConditionReason
		wantOutcome outcome.Kind
	}{
		{"issued", outcome.CertificateIssued, outcome.Issued},
		{"denied", outcome.UnsupportedKeyType, outcome.Denied},
		{"failed", outcome.SigningFailed, outcome.Failed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcr := &certificatesv1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
			}
			cl := fake.NewClientBuilder().
				WithScheme(newTestScheme(t)).
				WithObjects(pcr).
				WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
				Build()
			r := &PodCertificateRequestReconciler{
				Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10),
			}

			before := outcomeCount(tc.wantOutcome, tc.reason)
			if _, err := r.recordOutcome(context.Background(), pcr,
				tc.wantOutcome, tc.reason, "message"); err != nil {
				t.Fatalf("recordOutcome: %v", err)
			}
			if got := outcomeCount(tc.wantOutcome, tc.reason) - before; got != 1 {
				t.Errorf("counter for {outcome=%q,reason=%q} moved by %v, want 1", tc.wantOutcome, tc.reason, got)
			}
		})
	}
}

// The counter must follow the write, not the intent. A reconcile whose status
// write was discarded (another writer recorded a terminal outcome first)
// announces nothing, so it must count nothing either - otherwise the issued
// rate includes certificates no request ever carried.
func TestOutcomeNotCountedWhenStatusWriteIsLost(t *testing.T) {
	pcr := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
	}
	key := client.ObjectKeyFromObject(pcr)
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, _ ...client.SubResourceUpdateOption) error {
				// A concurrent writer denies the request first; this
				// reconcile's write then loses on a conflict and, finding the
				// object terminal, gives up without persisting.
				concurrent := &certificatesv1.PodCertificateRequest{}
				if err := c.Get(ctx, key, concurrent); err != nil {
					return err
				}
				if len(concurrent.Status.Conditions) == 0 {
					concurrent.Status.Conditions = []metav1.Condition{{
						Type:               certificatesv1.PodCertificateRequestConditionTypeDenied,
						Status:             metav1.ConditionTrue,
						LastTransitionTime: metav1.Now(),
						Reason:             string(outcome.InvalidUserConfig),
						Message:            "denied by a concurrent writer",
					}}
					if err := c.Status().Update(ctx, concurrent); err != nil {
						return err
					}
				}
				return apierrors.NewConflict(
					certificatesv1.Resource("podcertificaterequests"), obj.GetName(), errors.New("resourceVersion mismatch"))
			},
		}).
		Build()
	r := &PodCertificateRequestReconciler{
		Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10),
	}

	before := outcomeCount(outcome.Issued, outcome.CertificateIssued)
	if _, err := r.recordOutcome(context.Background(), pcr,
		outcome.Issued, outcome.CertificateIssued, "issued"); err != nil {
		t.Fatalf("recordOutcome: %v", err)
	}
	if got := outcomeCount(outcome.Issued, outcome.CertificateIssued) - before; got != 0 {
		t.Errorf("issued counter moved by %v on a discarded status write, want 0", got)
	}
}

// The property the whole surface rests on: the number of time series does not
// move with the number of requests processed. If a per-request value ever
// reaches a label, this is the test that turns red.
func TestSeriesCountDoesNotGrowWithRequests(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	if err := metrics.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	before := seriesCount(t, reg)
	issuedBefore := outcomeCount(outcome.Issued, outcome.CertificateIssued)
	deniedBefore := outcomeCount(outcome.Denied, outcome.UnsupportedKeyType)
	requeuedBefore := requeueCount(outcome.CASignerUnusable)
	droppedBefore := dropCount()

	for i := range 50 {
		reconcileDistinctRequest(t, i)
	}
	after := seriesCount(t, reg)

	// Without this the assertion below would hold trivially for a run that
	// never reached a counter at all.
	for _, moved := range []struct {
		what  string
		delta float64
	}{
		{"issued", outcomeCount(outcome.Issued, outcome.CertificateIssued) - issuedBefore},
		{"denied", outcomeCount(outcome.Denied, outcome.UnsupportedKeyType) - deniedBefore},
		{"requeued", requeueCount(outcome.CASignerUnusable) - requeuedBefore},
		{"dropped", dropCount() - droppedBefore},
	} {
		if moved.delta == 0 {
			t.Errorf("the %s counter never moved, so this test proves nothing about its cardinality", moved.what)
		}
	}

	if after != before {
		t.Errorf("series count moved from %d to %d over 50 distinct requests; a label is carrying "+
			"per-request identity, which docs/adr/0005-bounded-metrics-surface.md forbids", before, after)
	}
	if before == 0 {
		t.Fatal("no series registered, so the assertion above proves nothing")
	}
}

// reconcileDistinctRequest drives one reconcile for a uniquely named request
// and pod, exercising an issued outcome, a denial, a drop and a requeue in
// rotation so every counter sees traffic.
func reconcileDistinctRequest(t *testing.T, i int) {
	t.Helper()

	name := fmt.Sprintf("pcr-%d", i)
	podName := fmt.Sprintf("pod-%d", i)
	uid := types.UID(fmt.Sprintf("uid-%d", i))
	const signerName = "example.org/signer"

	csr, _ := newStubCSR(t)

	pcr := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ns"},
		Spec: certificatesv1.PodCertificateRequestSpec{
			SignerName:        signerName,
			PodName:           podName,
			PodUID:            uid,
			StubPKCS10Request: csr,
		},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: "ns", UID: uid}}

	objects := []client.Object{pcr, pod}
	stub := &stubSigner{name: signerName, cert: stubCert()}
	switch i % 4 {
	case 1:
		// Denied: a CSR stub the signer cannot parse.
		pcr.Spec.StubPKCS10Request = []byte("not a certificate request")
	case 2:
		// Dropped: the pod is gone on the live read too.
		objects = []client.Object{pcr}
	case 3:
		// Requeued: the CA cannot cover the request today.
		stub.err = fmt.Errorf("cannot sign: %w", authority.ErrCASignerUnusable)
	}

	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(objects...).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		Build()
	r := &PodCertificateRequestReconciler{
		Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub, SignerName: stub.name, EventRecorder: events.NewFakeRecorder(10),
	}
	// The requeue case returns the error by design; every other case must not.
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pcr)})
	if err != nil && i%4 != 3 {
		t.Fatalf("Reconcile(%s) error = %v", name, err)
	}
}

func outcomeCount(kind outcome.Kind, reason outcome.ConditionReason) float64 {
	return promtestutil.ToFloat64(metrics.PodCertificateRequests.WithLabelValues(string(kind), string(reason)))
}

func requeueCount(reason outcome.NonTerminalReason) float64 {
	return promtestutil.ToFloat64(metrics.PodCertificateRequestRequeues.WithLabelValues(string(reason)))
}

func dropCount() float64 {
	return promtestutil.ToFloat64(metrics.PodCertificateRequestDrops.WithLabelValues(string(outcome.AssociatedPodGone)))
}

// seriesCount reports how many time series reg currently exposes.
func seriesCount(t *testing.T, reg prometheus.Gatherer) int {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	n := 0
	for _, mf := range families {
		n += len(mf.GetMetric())
	}

	return n
}
