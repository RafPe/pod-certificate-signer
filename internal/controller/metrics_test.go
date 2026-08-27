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

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
)

// The reason label is meant to grep identically against the object: a value
// read off a graph must be the string that was written into the condition. The
// metrics package cannot import this one (that is the import cycle the package
// exists to avoid), so the strings are duplicated there and pinned here.
func TestMetricReasonsMatchControllerConstants(t *testing.T) {
	pairs := []struct {
		metric string
		reason Reason
	}{
		{metrics.ReasonCertificateIssued, ReasonCertificateIssued},
		{metrics.ReasonUnsupportedKeyType, ReasonUnsupportedKeyType},
		{metrics.ReasonInvalidUserConfig, ReasonInvalidUserAnnotations},
		{metrics.ReasonSigningFailed, ReasonSigningFailed},
		{metrics.ReasonAssociatedPodGone, ReasonAssociatedPodGone},
	}
	for _, p := range pairs {
		if p.metric != string(p.reason) {
			t.Errorf("metric label value %q does not match the reason written onto the object, %q", p.metric, p.reason)
		}
	}
}

// TestIssuanceOutcomesExcludeTheDeadReason guards the one curation decision the
// table exists to make. ReasonAssociatedPodNotFound is declared and never used
// - a missing pod is dropped, not failed - so pre-initialising a pair for it
// would advertise a permanently-zero series for an outcome that cannot occur.
func TestIssuanceOutcomesExcludeTheDeadReason(t *testing.T) {
	for _, pair := range metrics.IssuanceOutcomes {
		if pair[1] == string(ReasonAssociatedPodNotFound) {
			t.Errorf("pre-initialised pair %v uses %s, which the reconciler never records",
				pair, ReasonAssociatedPodNotFound)
		}
	}
}

// A terminal outcome must be counted once, under the outcome and reason the
// object records.
func TestTerminalOutcomesAreCounted(t *testing.T) {
	cases := []struct {
		name          string
		conditionType string
		reason        Reason
		wantOutcome   string
	}{
		{"issued", certificatesv1.PodCertificateRequestConditionTypeIssued, ReasonCertificateIssued, metrics.OutcomeIssued},
		{"denied", certificatesv1.PodCertificateRequestConditionTypeDenied, ReasonUnsupportedKeyType, metrics.OutcomeDenied},
		{"failed", certificatesv1.PodCertificateRequestConditionTypeFailed, ReasonSigningFailed, metrics.OutcomeFailed},
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
			if err := r.recordOutcome(context.Background(), pcr,
				tc.conditionType, tc.reason, "message", corev1.EventTypeNormal); err != nil {
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
						Reason:             string(ReasonInvalidUserAnnotations),
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

	before := outcomeCount(metrics.OutcomeIssued, ReasonCertificateIssued)
	if err := r.recordOutcome(context.Background(), pcr,
		certificatesv1.PodCertificateRequestConditionTypeIssued, ReasonCertificateIssued, "issued", corev1.EventTypeNormal); err != nil {
		t.Fatalf("recordOutcome: %v", err)
	}
	if got := outcomeCount(metrics.OutcomeIssued, ReasonCertificateIssued) - before; got != 0 {
		t.Errorf("issued counter moved by %v on a discarded status write, want 0", got)
	}
}

// A requeue is classified, never counted as an outcome: the CA-unusable case is
// the silent hang, and it must be separable from ordinary transient noise.
func TestRequeuesAreClassified(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantReason string
	}{
		{"ca unusable", fmt.Errorf("cannot sign: %w", authority.ErrCASignerUnusable), metrics.ReasonCASignerUnusable},
		{"anything else", errors.New("etcdserver: request timed out"), metrics.ReasonTransient},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// recordFailure announces CA-unusable requeues as an event, so the
			// reconciler needs a recorder even though this test asserts the metric.
			r := &PodCertificateRequestReconciler{Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10)}
			ctx := logr.NewContext(context.Background(), logr.Discard())

			before := requeueCount(tc.wantReason)
			if _, err := r.recordFailure(ctx, &certificatesv1.PodCertificateRequest{}, tc.err); err == nil {
				t.Fatal("recordFailure() error = nil, want the transient error returned for requeue")
			}
			if got := requeueCount(tc.wantReason) - before; got != 1 {
				t.Errorf("requeue counter for %q moved by %v, want 1", tc.wantReason, got)
			}
		})
	}
}

// A drop writes no status, so the counter is the only aggregate record that a
// pod went without its credential.
func TestDropsAreCounted(t *testing.T) {
	r := &PodCertificateRequestReconciler{EventRecorder: events.NewFakeRecorder(10)}

	before := dropCount()
	r.recordPodGone(&certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
	}, "pod is gone")
	if got := dropCount() - before; got != 1 {
		t.Errorf("drop counter moved by %v, want 1", got)
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
	issuedBefore := outcomeCount(metrics.OutcomeIssued, ReasonCertificateIssued)
	deniedBefore := outcomeCount(metrics.OutcomeDenied, ReasonUnsupportedKeyType)
	requeuedBefore := requeueCount(metrics.ReasonCASignerUnusable)
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
		{"issued", outcomeCount(metrics.OutcomeIssued, ReasonCertificateIssued) - issuedBefore},
		{"denied", outcomeCount(metrics.OutcomeDenied, ReasonUnsupportedKeyType) - deniedBefore},
		{"requeued", requeueCount(metrics.ReasonCASignerUnusable) - requeuedBefore},
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
		Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub, EventRecorder: events.NewFakeRecorder(10),
	}
	// The requeue case returns the error by design; every other case must not.
	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pcr)})
	if err != nil && i%4 != 3 {
		t.Fatalf("Reconcile(%s) error = %v", name, err)
	}
}

func outcomeCount(outcome string, reason Reason) float64 {
	return promtestutil.ToFloat64(metrics.PodCertificateRequests.WithLabelValues(outcome, string(reason)))
}

func requeueCount(reason string) float64 {
	return promtestutil.ToFloat64(metrics.PodCertificateRequestRequeues.WithLabelValues(reason))
}

func dropCount() float64 {
	return promtestutil.ToFloat64(metrics.PodCertificateRequestDrops.WithLabelValues(metrics.ReasonAssociatedPodGone))
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
