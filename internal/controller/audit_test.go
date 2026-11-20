package controller

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/recorder"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/audit"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
)

// fakeAuditRecorder is an audit.Recorder that keeps every record and whether
// the context it was given was already done.
type fakeAuditRecorder struct {
	mu      sync.Mutex
	records []audit.Record
	ctxErrs []error
}

func (f *fakeAuditRecorder) Record(ctx context.Context, rec audit.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, rec)
	f.ctxErrs = append(f.ctxErrs, ctx.Err())
}

func (f *fakeAuditRecorder) snapshot() []audit.Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]audit.Record(nil), f.records...)
}

const (
	auditSignerName = "example.org/signer"
	auditRequestUID = "request-uid"
)

// auditHarness is a reconciler with audit on, over a stored request and its
// live pod. The status writes go through funcs. The pod has a controller
// ownerReference, so a record that carries workload.owner proves the live pod
// reached the builder.
type auditHarness struct {
	r      *PodCertificateRequestReconciler
	rec    *fakeAuditRecorder
	stub   *stubSigner
	events *events.FakeRecorder
	key    client.ObjectKey
}

func newAuditHarness(t *testing.T, funcs interceptor.Funcs, edit func(*certificatesv1.PodCertificateRequest, *corev1.Pod)) *auditHarness {
	t.Helper()
	pcr, pod := livePCR(t, "pod-uid", "pod-uid")
	pcr.UID = auditRequestUID
	pcr.Spec.SignerName = auditSignerName
	pcr.Spec.ServiceAccountName = "sa"
	pcr.Spec.ServiceAccountUID = "sa-uid"
	isController := true
	pod.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "rs", UID: "rs-uid", Controller: &isController,
	}}
	if edit != nil {
		edit(pcr, pod)
	}

	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr, pod).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		WithInterceptorFuncs(funcs).
		Build()
	builder, err := audit.NewBuilder(auditSignerName, audit.DefaultOptions())
	if err != nil {
		t.Fatalf("NewBuilder() error = %v", err)
	}
	rec := &fakeAuditRecorder{}
	stub := &stubSigner{name: auditSignerName, cert: stubCert()}
	evs := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{
		Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub, SignerName: auditSignerName,
		EventRecorder: evs, Audit: rec, AuditRecords: builder,
	}
	return &auditHarness{r: r, rec: rec, stub: stub, events: evs, key: client.ObjectKeyFromObject(pcr)}
}

func (h *auditHarness) reconcile(ctx context.Context) error {
	_, err := h.r.Reconcile(ctx, ctrl.Request{NamespacedName: h.key})
	return err
}

// assertEvents fails unless records carry exactly want, in order, as
// event/reason pairs.
func assertEvents(t *testing.T, records []audit.Record, want ...[2]string) {
	t.Helper()
	got := make([][2]string, 0, len(records))
	for _, rec := range records {
		got = append(got, [2]string{string(rec.Event), rec.Reason})
	}
	if len(got) != len(want) {
		t.Fatalf("records = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("records = %v, want %v", got, want)
		}
	}
}

var (
	signedPair    = [2]string{string(audit.EventSigned), string(outcome.CertificateIssued)}
	publishedPair = [2]string{string(audit.EventPublished), audit.ReasonStatusWritten}
	deniedPair    = [2]string{string(audit.EventDenied), string(outcome.UnsupportedKeyType)}
)

// eventReasons drains rec and returns each event it holds as its type and
// reason, for example "Normal CertificateIssued".
func eventReasons(rec *events.FakeRecorder) []string {
	var got []string
	for {
		select {
		case e := <-rec.Events:
			fields := strings.Fields(e)
			got = append(got, strings.Join(fields[:min(2, len(fields))], " "))
		default:
			return got
		}
	}
}

// assertAnnounced fails unless h emitted exactly the events want, as type and
// reason, and the outcome counter of kind and reason is delta above before.
// Audit is on in h, so this checks that audit changes no event and no metric.
func assertAnnounced(t *testing.T, h *auditHarness, kind outcome.Kind, reason outcome.ConditionReason,
	before, delta float64, want ...string) {
	t.Helper()
	if got := eventReasons(h.events); !slices.Equal(got, want) {
		t.Errorf("events = %q, want %q", got, want)
	}
	if got := outcomeCount(kind, reason) - before; got != delta {
		t.Errorf("outcome counter {%s,%s} moved by %v, want %v", kind, reason, got, delta)
	}
}

// denyByCSR makes signRequest deny the request after it read the pod: the
// stub CSR does not parse.
func denyByCSR(pcr *certificatesv1.PodCertificateRequest, _ *corev1.Pod) {
	pcr.Spec.StubPKCS10Request = []byte("not a CSR")
}

// The signed record is written before the status write that publishes the
// certificate, so a certificate the API server accepted always has its full
// record. The published record names the same certificate.
func TestAuditIssuedEmitsSignedThenPublished(t *testing.T) {
	var atWrite int
	var h *auditHarness
	h = newAuditHarness(t, interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			atWrite = len(h.rec.snapshot())
			return c.Status().Update(ctx, obj, opts...)
		},
	}, nil)
	before := outcomeCount(outcome.Issued, outcome.CertificateIssued)

	if err := h.reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	assertAnnounced(t, h, outcome.Issued, outcome.CertificateIssued, before, 1, "Normal CertificateIssued")
	if atWrite != 1 {
		t.Errorf("records at the status write = %d, want 1: the signed record comes first", atWrite)
	}
	records := h.rec.snapshot()
	assertEvents(t, records, signedPair, publishedPair)
	want := audit.Fingerprint(h.stub.cert.Leaf)
	for i, rec := range records {
		if rec.Certificate == nil || rec.Certificate.Fingerprint != want {
			t.Errorf("record %d certificate = %+v, want fingerprint %s", i, rec.Certificate, want)
		}
	}
	if records[0].Workload == nil || records[0].Workload.Owner == nil || records[0].Issuer == nil {
		t.Errorf("signed record = %+v, want the workload with its owner and the issuer", records[0])
	}
	if records[1].Workload != nil || records[1].Issuer != nil {
		t.Errorf("published record = %+v, want no workload and no issuer", records[1])
	}
}

// The Issued condition message carries the same serial and fingerprint as the
// signed record of the same reconcile, so the API server audit log and the
// record join on the same two values.
func TestAuditIssuedMessageMatchesSignedRecord(t *testing.T) {
	h := newAuditHarness(t, interceptor.Funcs{}, nil)

	if err := h.reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	records := h.rec.snapshot()
	assertEvents(t, records, signedPair, publishedPair)
	stored := &certificatesv1.PodCertificateRequest{}
	if err := h.r.Get(context.Background(), h.key, stored); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(stored.Status.Conditions) != 1 {
		t.Fatalf("conditions = %+v, want a single Issued condition", stored.Status.Conditions)
	}
	signed := records[0].Certificate
	want := "certificate issued: serial=" + signed.SerialHex + " fingerprint=" + signed.Fingerprint
	if got := stored.Status.Conditions[0].Message; got != want {
		t.Errorf("condition message = %q, want %q: the serial and fingerprint of the signed record", got, want)
	}
}

// Each result of the Issued status write has its own follow-up record. The
// follow-up is emitted also when the write returns an error and the reconcile
// requeues.
func TestAuditFollowUpByWriteResult(t *testing.T) {
	gr := schema.GroupResource{Group: "certificates.k8s.io", Resource: "podcertificaterequests"}
	var supersededWrites int
	cases := []struct {
		name    string
		funcs   interceptor.Funcs
		want    [2]string
		wantErr bool
	}{
		{"persisted", interceptor.Funcs{}, publishedPair, false},
		{"superseded", concurrentTerminal(terminalStatus(certificatesv1.PodCertificateRequestConditionTypeDenied, ""), &supersededWrites),
			[2]string{string(audit.EventSuperseded), audit.ReasonOtherWriterWon}, false},
		{"gone", failWrite(apierrors.NewNotFound(gr, "pcr")),
			[2]string{string(audit.EventSuperseded), audit.ReasonRequestGone}, false},
		{"rejected", failWrite(apierrors.NewBadRequest("bad")),
			[2]string{string(audit.EventSuperseded), audit.ReasonWriteRejected}, true},
		{"unknown", failWrite(context.DeadlineExceeded),
			[2]string{string(audit.EventUnknown), audit.ReasonWriteAmbiguous}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuditHarness(t, tc.funcs, nil)
			before := outcomeCount(outcome.Issued, outcome.CertificateIssued)

			err := h.reconcile(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("Reconcile() error = %v, want error %t", err, tc.wantErr)
			}
			assertEvents(t, h.rec.snapshot(), signedPair, tc.want)
			// Only a persisted write is announced and counted.
			if tc.want == publishedPair {
				assertAnnounced(t, h, outcome.Issued, outcome.CertificateIssued, before, 1, "Normal CertificateIssued")
			} else {
				assertAnnounced(t, h, outcome.Issued, outcome.CertificateIssued, before, 0)
			}
		})
	}
}

// A write the API server committed but answered with a timeout may be in
// place, so its follow-up is unknown and never superseded.
func TestAuditCommitThenTimeoutIsUnknown(t *testing.T) {
	var writes int
	h := newAuditHarness(t, writeThen(context.DeadlineExceeded, &writes), nil)

	if err := h.reconcile(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Reconcile() error = %v, want context.DeadlineExceeded", err)
	}
	assertEvents(t, h.rec.snapshot(), signedPair, [2]string{string(audit.EventUnknown), audit.ReasonWriteAmbiguous})
}

// A conflict re-read that finds a replacement request must not move the
// follow-up onto the replacement: the certificate was signed for the original
// request UID.
//
// This is a regression guard. Today the follow-up comes from the signed
// record, and the re-read never reaches pcr. The test fails if a future change
// copies the conflict re-read into pcr and the follow-up takes it from there.
func TestAuditFollowUpKeepsOriginalRequestUID(t *testing.T) {
	replacement := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns", UID: "new-request-uid"},
		Spec:       certificatesv1.PodCertificateRequestSpec{PodName: "other-pod", PodUID: "other-pod-uid"},
	}
	var writes int
	h := newAuditHarness(t, replacePCR(replacement, &writes), nil)

	if err := h.reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	records := h.rec.snapshot()
	assertEvents(t, records, signedPair, [2]string{string(audit.EventSuperseded), audit.ReasonRequestGone})
	for i, rec := range records {
		if rec.Request.UID != auditRequestUID {
			t.Errorf("record %d request uid = %q, want %q", i, rec.Request.UID, auditRequestUID)
		}
	}
}

// A denial and a failure each have one record, written after the persisted
// status write. It identifies the pod and its ServiceAccount and has no
// certificate.
func TestAuditDeniedAndFailed(t *testing.T) {
	cases := []struct {
		name      string
		edit      func(*certificatesv1.PodCertificateRequest, *corev1.Pod)
		signErr   error
		want      [2]string
		kind      outcome.Kind
		wantEvent string
	}{
		{"denied", denyByCSR, nil, deniedPair, outcome.Denied, "Warning UnsupportedKeyType"},
		{"failed", nil, errors.New("sign broke"), [2]string{string(audit.EventFailed), string(outcome.SigningFailed)},
			outcome.Failed, "Warning SigningFailed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			atWrite := -1
			var h *auditHarness
			h = newAuditHarness(t, interceptor.Funcs{
				SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
					atWrite = len(h.rec.snapshot())
					return c.Status().Update(ctx, obj, opts...)
				},
			}, tc.edit)
			if tc.signErr != nil {
				h.stub.cert, h.stub.err = nil, tc.signErr
			}
			reason := outcome.ConditionReason(tc.want[1])
			before := outcomeCount(tc.kind, reason)

			if err := h.reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			assertAnnounced(t, h, tc.kind, reason, before, 1, tc.wantEvent)
			if atWrite != 0 {
				t.Errorf("records at the status write = %d, want 0: the record follows the write", atWrite)
			}
			records := h.rec.snapshot()
			assertEvents(t, records, tc.want)
			rec := records[0]

			stored := &certificatesv1.PodCertificateRequest{}
			if err := h.r.Get(context.Background(), h.key, stored); err != nil {
				t.Fatalf("get: %v", err)
			}
			if rec.Message == "" || rec.Message != stored.Status.Conditions[0].Message {
				t.Errorf("message = %q, want the condition message %q", rec.Message, stored.Status.Conditions[0].Message)
			}
			if rec.Request.UID != auditRequestUID {
				t.Errorf("request uid = %q, want %q", rec.Request.UID, auditRequestUID)
			}
			w := rec.Workload
			if w == nil {
				t.Fatal("workload = nil, want the pod identity")
			}
			if w.Pod != (audit.ObjectRef{Name: "mypod", UID: "pod-uid"}) {
				t.Errorf("workload.pod = %+v", w.Pod)
			}
			if w.ServiceAccount != (audit.ObjectRef{Name: "sa", UID: "sa-uid"}) {
				t.Errorf("workload.serviceAccount = %+v", w.ServiceAccount)
			}
			if w.Owner == nil || w.Owner.UID != "rs-uid" {
				t.Errorf("workload.owner = %+v, want the pod's controller: the live pod must reach the record", w.Owner)
			}
			if rec.Certificate != nil || rec.Issuer != nil {
				t.Errorf("certificate = %+v, issuer = %+v, want neither", rec.Certificate, rec.Issuer)
			}
		})
	}
}

// A terminal outcome that is not in place after the write has no record: the
// reconcile lost the race, the request is gone, or the write is not known to
// be committed.
func TestAuditTerminalLostRaceEmitsNothing(t *testing.T) {
	var writes, supersededWrites int
	cases := []struct {
		name    string
		funcs   interceptor.Funcs
		wantErr bool
	}{
		{"superseded", concurrentTerminal(terminalStatus(certificatesv1.PodCertificateRequestConditionTypeFailed, ""), &supersededWrites), false},
		{"gone", replacePCR(nil, &writes), false},
		{"rejected", failWrite(apierrors.NewBadRequest("bad")), true},
		{"unknown", failWrite(context.DeadlineExceeded), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuditHarness(t, tc.funcs, denyByCSR)
			before := outcomeCount(outcome.Denied, outcome.UnsupportedKeyType)

			if err := h.reconcile(context.Background()); (err != nil) != tc.wantErr {
				t.Fatalf("Reconcile() error = %v, want error %t", err, tc.wantErr)
			}
			assertAnnounced(t, h, outcome.Denied, outcome.UnsupportedKeyType, before, 0)
			if records := h.rec.snapshot(); len(records) != 0 {
				t.Errorf("records = %+v, want none", records)
			}
		})
	}
}

// A dropped request was never signed and has no outcome, so it has no record.
func TestAuditDroppedRequestEmitsNothing(t *testing.T) {
	now := metav1.Now()
	cases := []struct {
		name string
		edit func(*certificatesv1.PodCertificateRequest, *corev1.Pod)
	}{
		{"pod gone", func(_ *certificatesv1.PodCertificateRequest, pod *corev1.Pod) { pod.Name = "another-pod" }},
		{"pod replaced", func(_ *certificatesv1.PodCertificateRequest, pod *corev1.Pod) { pod.UID = "replacement-pod-uid" }},
		{"pod being deleted", func(_ *certificatesv1.PodCertificateRequest, pod *corev1.Pod) {
			pod.DeletionTimestamp = &now
			pod.Finalizers = []string{"keep"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuditHarness(t, interceptor.Funcs{}, tc.edit)

			if err := h.reconcile(context.Background()); err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if h.stub.called {
				t.Fatal("signer ran for a dropped request")
			}
			if records := h.rec.snapshot(); len(records) != 0 {
				t.Errorf("records = %+v, want none", records)
			}
		})
	}
}

// Audit is off unless both the recorder and the builder are set. Off, every
// path runs as before and records nothing.
func TestAuditOffEmitsNothingAndDoesNotPanic(t *testing.T) {
	gr := schema.GroupResource{Group: "certificates.k8s.io", Resource: "podcertificaterequests"}
	paths := []struct {
		name    string
		funcs   interceptor.Funcs
		edit    func(*certificatesv1.PodCertificateRequest, *corev1.Pod)
		wantErr bool
	}{
		{"issued", interceptor.Funcs{}, nil, false},
		{"issued, write unknown", failWrite(context.DeadlineExceeded), nil, true},
		{"issued, request gone", failWrite(apierrors.NewNotFound(gr, "pcr")), nil, false},
		{"denied", interceptor.Funcs{}, denyByCSR, false},
	}
	for _, mode := range []string{"both nil", "builder nil"} {
		for _, p := range paths {
			t.Run(mode+"/"+p.name, func(t *testing.T) {
				h := newAuditHarness(t, p.funcs, p.edit)
				h.r.AuditRecords = nil
				if mode == "both nil" {
					h.r.Audit = nil
				}

				if err := h.reconcile(context.Background()); (err != nil) != p.wantErr {
					t.Fatalf("Reconcile() error = %v, want error %t", err, p.wantErr)
				}
				if records := h.rec.snapshot(); len(records) != 0 {
					t.Errorf("records = %+v, want none", records)
				}
			})
		}
	}
}

// A shutdown that cancels the reconcile context during the status write must
// not lose the follow-up: it is recorded with a context that is not done.
func TestAuditFollowUpAfterCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h := newAuditHarness(t, interceptor.Funcs{
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			cancel()
			return context.Canceled
		},
	}, nil)

	if err := h.reconcile(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Reconcile() error = %v, want context.Canceled", err)
	}
	assertEvents(t, h.rec.snapshot(), signedPair, [2]string{string(audit.EventUnknown), audit.ReasonWriteAmbiguous})
	h.rec.mu.Lock()
	defer h.rec.mu.Unlock()
	if err := h.rec.ctxErrs[1]; err != nil {
		t.Errorf("follow-up context error = %v, want nil: the follow-up must outlive the reconcile context", err)
	}
}

// signRequest returns the live pod whenever it read one that matches the
// request and is not being deleted, so a denial or failure record can carry
// it. A dropped request returns no pod.
func TestSignRequestReturnsPod(t *testing.T) {
	now := metav1.Now()
	failPodRead := interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*corev1.Pod); ok {
				return errors.New("pod read broke")
			}
			return c.Get(ctx, key, obj, opts...)
		},
	}
	cases := []struct {
		name    string
		funcs   interceptor.Funcs
		edit    func(*certificatesv1.PodCertificateRequest, *corev1.Pod)
		signErr error
		wantPod bool
	}{
		{"signed", interceptor.Funcs{}, nil, nil, true},
		{"denied", interceptor.Funcs{}, denyByCSR, nil, true},
		{"failed", interceptor.Funcs{}, nil, errors.New("sign broke"), true},
		{"CA unusable", interceptor.Funcs{}, nil, caUnusableErr(), true},
		{"pod replaced", interceptor.Funcs{}, func(_ *certificatesv1.PodCertificateRequest, pod *corev1.Pod) { pod.UID = "other" }, nil, false},
		{"pod not found", interceptor.Funcs{}, func(_ *certificatesv1.PodCertificateRequest, pod *corev1.Pod) { pod.Name = "another-pod" }, nil, false},
		{"pod being deleted", interceptor.Funcs{}, func(_ *certificatesv1.PodCertificateRequest, pod *corev1.Pod) {
			pod.DeletionTimestamp = &now
			pod.Finalizers = []string{"keep"}
		}, nil, false},
		{"pod read error", failPodRead, nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuditHarness(t, tc.funcs, tc.edit)
			if tc.signErr != nil {
				h.stub.cert, h.stub.err = nil, tc.signErr
			}
			pcr := &certificatesv1.PodCertificateRequest{}
			if err := h.r.Get(context.Background(), h.key, pcr); err != nil {
				t.Fatalf("get: %v", err)
			}

			pod, _, _ := h.r.signRequest(logr.NewContext(context.Background(), logr.Discard()), pcr)
			if (pod != nil) != tc.wantPod {
				t.Fatalf("pod = %v, want a pod %t", pod, tc.wantPod)
			}
			if pod != nil && pod.UID != pcr.Spec.PodUID {
				t.Errorf("pod uid = %q, want %q", pod.UID, pcr.Spec.PodUID)
			}
		})
	}
}

// The constructor refuses a recorder without a builder and a builder without
// a recorder: half of the pair would turn audit off without a word.
func TestNewReconcilerRejectsHalfAnAuditPair(t *testing.T) {
	builder, err := audit.NewBuilder(auditSignerName, audit.DefaultOptions())
	if err != nil {
		t.Fatalf("NewBuilder() error = %v", err)
	}
	cases := []struct {
		name     string
		recorder audit.Recorder
		builder  *audit.Builder
	}{
		{"recorder only", &fakeAuditRecorder{}, nil},
		{"builder only", nil, builder},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPodCertificateRequestReconciler(nil, "c", auditSignerName, &stubSigner{},
				podcertificate.Options{}, tc.recorder, tc.builder)
			if err == nil {
				t.Fatal("NewPodCertificateRequestReconciler() error = nil, want an error for half an audit pair")
			}
		})
	}
}

// A shutdown that cancels the reconcile context must not lose the signed
// record or a denied record: each is recorded with a context that is not done.
// The signed row cancels after the pod read, before the signing. The denied
// row cancels after the status write, before its record.
func TestAuditRecordsOutliveCancelledContext(t *testing.T) {
	cancelAfterPodRead := func(cancel context.CancelFunc) interceptor.Funcs {
		return interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				err := c.Get(ctx, key, obj, opts...)
				if _, ok := obj.(*corev1.Pod); ok {
					cancel()
				}
				return err
			},
		}
	}
	cancelAfterStatusWrite := func(cancel context.CancelFunc) interceptor.Funcs {
		return interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				err := c.Status().Update(ctx, obj, opts...)
				cancel()
				return err
			},
		}
	}
	cases := []struct {
		name  string
		funcs func(context.CancelFunc) interceptor.Funcs
		edit  func(*certificatesv1.PodCertificateRequest, *corev1.Pod)
		// want lists the records. The first is the one the row checks.
		want [][2]string
	}{
		{"signed", cancelAfterPodRead, nil, [][2]string{signedPair, publishedPair}},
		{"denied", cancelAfterStatusWrite, denyByCSR, [][2]string{deniedPair}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h := newAuditHarness(t, tc.funcs(cancel), tc.edit)

			if err := h.reconcile(ctx); err != nil {
				t.Fatalf("Reconcile() error = %v", err)
			}
			if ctx.Err() == nil {
				t.Fatal("the reconcile context is not done: the row did not cancel it")
			}
			assertEvents(t, h.rec.snapshot(), tc.want...)
			h.rec.mu.Lock()
			defer h.rec.mu.Unlock()
			if err := h.rec.ctxErrs[0]; err != nil {
				t.Errorf("%s record context error = %v, want nil: the record must outlive the reconcile context", tc.want[0][0], err)
			}
		})
	}
}

// fakeManager is the part of ctrl.Manager that the reconciler constructor
// reads. Any other method panics.
type fakeManager struct {
	ctrl.Manager
	cl client.Client
}

func (m fakeManager) GetClient() client.Client    { return m.cl }
func (m fakeManager) GetAPIReader() client.Reader { return m.cl }
func (m fakeManager) GetEventRecorder(string) recorder.EventRecorder {
	return events.NewFakeRecorder(1)
}

// The constructor accepts both audit values together, and both nil. It hands
// them to the reconciler as given, so audit is on exactly when both are set.
func TestNewReconcilerTakesTheAuditPair(t *testing.T) {
	builder, err := audit.NewBuilder(auditSignerName, audit.DefaultOptions())
	if err != nil {
		t.Fatalf("NewBuilder() error = %v", err)
	}
	mgr := fakeManager{cl: fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()}
	cases := []struct {
		name        string
		recorder    audit.Recorder
		builder     *audit.Builder
		wantAuditOn bool
	}{
		{"both set", &fakeAuditRecorder{}, builder, true},
		{"both nil", nil, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewPodCertificateRequestReconciler(mgr, "c", auditSignerName, &stubSigner{},
				podcertificate.Options{}, tc.recorder, tc.builder)
			if err != nil {
				t.Fatalf("NewPodCertificateRequestReconciler() error = %v", err)
			}
			if r.Audit != tc.recorder || r.AuditRecords != tc.builder {
				t.Errorf("reconciler audit = (%v, %v), want (%v, %v)", r.Audit, r.AuditRecords, tc.recorder, tc.builder)
			}
			if r.auditOn() != tc.wantAuditOn {
				t.Errorf("auditOn() = %t, want %t", r.auditOn(), tc.wantAuditOn)
			}
		})
	}
}
