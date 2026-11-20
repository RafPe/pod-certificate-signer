package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// 49.1: the outcome event must announce a result that was actually persisted.
// When the status write fails, recordOutcome must surface the error and record
// no event, so a failed write is not advertised (and re-advertised on every
// requeue) as a done deal.
func TestRecordOutcomeNoEventWhenStatusWriteFails(t *testing.T) {
	pcr := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
	}
	// A non-conflict error: rejected outright, never retried.
	writeErr := apierrors.NewBadRequest("status rejected")
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(_ context.Context, _ client.Client, _ string, _ client.Object, _ ...client.SubResourceUpdateOption) error {
				return writeErr
			},
		}).
		Build()
	rec := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: rec}

	_, err := r.recordOutcome(context.Background(), pcr,
		outcome.Issued, outcome.CertificateIssued, "issued")
	if err == nil {
		t.Fatal("recordOutcome() error = nil, want the status write error to propagate")
	}
	select {
	case e := <-rec.Events:
		t.Fatalf("recorded event %q, want none: the event must follow a successful status write", e)
	default:
	}
}

// 49.2: a single status-write conflict must be resolved inside one reconcile.
// A 409 propagating out of Reconcile re-runs the signer next pass, minting a
// second certificate and serial for a status that was discarded. recordOutcome
// must re-read and retry the write instead, so the reconcile succeeds, the
// status is persisted once, and the signer runs exactly once.
func TestReconcileRetriesStatusConflict(t *testing.T) {
	const signerName = "example.org/signer"
	pcr, pod := livePCR(t, "conflict-uid", "conflict-uid")
	pcr.Spec.SignerName = signerName // otherwise Reconcile returns early and nothing is written
	pcr.UID = "request-uid"          // the conflict re-read must match a real UID, not two empty ones

	var updateAttempts, successfulWrites int
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr, pod).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				updateAttempts++
				if updateAttempts == 1 {
					return apierrors.NewConflict(
						schema.GroupResource{Group: "certificates.k8s.io", Resource: "podcertificaterequests"},
						obj.GetName(), errors.New("resourceVersion mismatch"))
				}
				if err := c.Status().Update(ctx, obj, opts...); err != nil {
					return err
				}
				successfulWrites++
				return nil
			},
		}).
		Build()

	stub := &stubSigner{name: signerName, cert: stubCert()}
	rec := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{
		Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub, SignerName: stub.name, EventRecorder: rec,
	}

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pcr)})
	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil (a one-time status conflict must be retried, not propagated)", err)
	}
	if res != (ctrl.Result{}) {
		t.Errorf("Reconcile() result = %+v, want empty (no requeue)", res)
	}
	if stub.signings != 1 {
		t.Errorf("signer ran %d times, want 1 (a retried conflict must not re-sign)", stub.signings)
	}
	if successfulWrites != 1 {
		t.Errorf("successful status writes = %d, want exactly 1", successfulWrites)
	}

	got := &certificatesv1.PodCertificateRequest{}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Status.Conditions) != 1 || got.Status.Conditions[0].Type != certificatesv1.PodCertificateRequestConditionTypeIssued {
		t.Fatalf("conditions = %+v, want a single Issued condition persisted", got.Status.Conditions)
	}
	select {
	case <-rec.Events:
	default:
		t.Error("no Issued event recorded after the successful write")
	}
}

// 49.2 (concurrency): when the conflict is caused by another writer that
// recorded a terminal outcome first, the retry must not overwrite that outcome
// with this reconcile's stale result. A PodCertificateRequest is immutable once
// terminal, so this reconcile lost the race: it must leave the winning outcome
// in place and announce nothing.
func TestReconcileConflictPreservesConcurrentTerminalOutcome(t *testing.T) {
	const signerName = "example.org/signer"
	pcr, pod := livePCR(t, "race-uid", "race-uid")
	pcr.Spec.SignerName = signerName
	pcr.UID = "request-uid" // the conflict re-read must match a real UID, not two empty ones

	key := client.ObjectKeyFromObject(pcr)
	var updateAttempts int
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr, pod).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				updateAttempts++
				if updateAttempts == 1 {
					// A concurrent writer denies the request, then this
					// reconcile's write loses the race with a conflict.
					concurrent := &certificatesv1.PodCertificateRequest{}
					if err := c.Get(ctx, key, concurrent); err != nil {
						return err
					}
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
					return apierrors.NewConflict(
						schema.GroupResource{Group: "certificates.k8s.io", Resource: "podcertificaterequests"},
						obj.GetName(), errors.New("resourceVersion mismatch"))
				}
				return c.Status().Update(ctx, obj, opts...)
			},
		}).
		Build()

	stub := &stubSigner{name: signerName, cert: stubCert()}
	rec := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{
		Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub, SignerName: stub.name, EventRecorder: rec,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile() error = %v, want nil (losing the race to a terminal outcome is not a failure)", err)
	}

	got := &certificatesv1.PodCertificateRequest{}
	if err := cl.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Status.Conditions) != 1 ||
		got.Status.Conditions[0].Type != certificatesv1.PodCertificateRequestConditionTypeDenied {
		t.Fatalf("persisted conditions = %+v, want the concurrent Denied outcome preserved, not overwritten by this reconcile's Issued",
			got.Status.Conditions)
	}
	select {
	case e := <-rec.Events:
		t.Errorf("recorded event %q, want none: a reconcile that lost the race must announce nothing", e)
	default:
	}
}

// newTestScheme builds a scheme with the types the controller tests need.
// Shared by the other controller unit tests in this package.
func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := certificatesv1.AddToScheme(scheme); err != nil {
		t.Fatalf("add certificatesv1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	return scheme
}

// recordTerminal must write the condition carried by the TerminalError, clear
// any certificate fields, and emit a warning event with the error text.
func TestRecordTerminal(t *testing.T) {
	scheme := newTestScheme(t)

	cases := []struct {
		name     string
		err      error
		wantType string
	}{
		{"failed clears fields", failed(errors.New("sign broke")), "Failed"},
		{"denied clears fields", denied(outcome.UnsupportedKeyType, errors.New("bad key")), "Denied"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcr := &certificatesv1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
				Status:     certificatesv1.PodCertificateRequestStatus{CertificateChain: "preexisting"},
			}
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
				Build()
			rec := events.NewFakeRecorder(10)
			r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: rec}

			var te *terminalError
			if !errors.As(tc.err, &te) {
				t.Fatalf("test error is not terminal: %v", tc.err)
			}
			if _, err := r.recordTerminal(context.Background(), pcr, te); err != nil {
				t.Fatalf("recordTerminal: %v", err)
			}

			got := &certificatesv1.PodCertificateRequest{}
			if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
				t.Fatalf("get: %v", err)
			}
			if len(got.Status.Conditions) != 1 {
				t.Fatalf("conditions = %d, want 1", len(got.Status.Conditions))
			}
			cond := got.Status.Conditions[0]
			if cond.Type != tc.wantType {
				t.Errorf("condition type = %s, want %s", cond.Type, tc.wantType)
			}
			if cond.Reason != string(te.reason) {
				t.Errorf("condition reason = %s, want %s", cond.Reason, te.reason)
			}
			if cond.Message != te.err.Error() {
				t.Errorf("condition message = %q, want the error text %q", cond.Message, te.err.Error())
			}
			if got.Status.CertificateChain != "" {
				t.Error("certificate fields must be cleared on a terminal failure")
			}
			select {
			case e := <-rec.Events:
				if !strings.Contains(e, corev1.EventTypeWarning) {
					t.Errorf("event = %q, want a warning", e)
				}
			default:
				t.Error("no event recorded")
			}
		})
	}
}

// recordIssued must keep the certificate fields, set the Issued condition and
// emit a normal event.
func TestRecordIssued(t *testing.T) {
	pcr := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
	}
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		Build()
	rec := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: rec}

	now := time.Now()
	cert := &podcertificate.Certificate{CertificateChain: "pem-chain", Config: &podcertificate.Config{Duration: time.Hour, RefreshBefore: 15 * time.Minute}, NotBefore: now, NotAfter: now.Add(time.Hour)}

	if _, err := r.recordIssued(context.Background(), pcr, cert); err != nil {
		t.Fatalf("recordIssued: %v", err)
	}

	got := &certificatesv1.PodCertificateRequest{}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Status.Conditions) != 1 || got.Status.Conditions[0].Type != certificatesv1.PodCertificateRequestConditionTypeIssued {
		t.Fatalf("conditions = %+v, want a single Issued condition", got.Status.Conditions)
	}
	if got.Status.CertificateChain != "pem-chain" {
		t.Errorf("certificate chain = %q, want pem-chain", got.Status.CertificateChain)
	}
	if got.Status.NotBefore == nil || got.Status.NotAfter == nil || got.Status.BeginRefreshAt == nil {
		t.Error("notBefore, notAfter and beginRefreshAt must all be set on issuance")
	}
	select {
	case e := <-rec.Events:
		if !strings.Contains(e, corev1.EventTypeNormal) {
			t.Errorf("event = %q, want a normal event", e)
		}
	default:
		t.Error("no event recorded")
	}
}

// A denial message carries the requester's own annotation text, so it must
// reach the event verbatim: a % in it is data, not a format verb.
func TestRecordTerminalEventMessageIsNotAFormat(t *testing.T) {
	pcr := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
	}
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		Build()
	rec := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: rec}

	const message = `annotation "example.org/signer-cn": value "100%d of %s" is not a verified identity`
	if _, err := r.recordTerminal(context.Background(), pcr, denied(outcome.InvalidUserConfig, errors.New(message)).(*terminalError)); err != nil {
		t.Fatalf("recordTerminal: %v", err)
	}

	select {
	case got := <-rec.Events:
		if !strings.Contains(got, message) {
			t.Errorf("event = %q, want it to carry the message verbatim: %q", got, message)
		}
	default:
		t.Fatal("no event was emitted")
	}
}

// The terminal condition type decides whether a request is still the
// reconciler's to act on: any of the three terminal types wins, regardless of
// where it sits among non-terminal conditions, and a request without one is
// still open.
func TestTerminalConditionType(t *testing.T) {
	cond := func(conditionType string) metav1.Condition {
		return metav1.Condition{Type: conditionType, Status: metav1.ConditionTrue}
	}
	cases := []struct {
		name       string
		conditions []metav1.Condition
		want       string
	}{
		{"no conditions", nil, ""},
		{"issued", []metav1.Condition{cond(certificatesv1.PodCertificateRequestConditionTypeIssued)}, certificatesv1.PodCertificateRequestConditionTypeIssued},
		{"denied", []metav1.Condition{cond(certificatesv1.PodCertificateRequestConditionTypeDenied)}, certificatesv1.PodCertificateRequestConditionTypeDenied},
		{"failed", []metav1.Condition{cond(certificatesv1.PodCertificateRequestConditionTypeFailed)}, certificatesv1.PodCertificateRequestConditionTypeFailed},
		{"non-terminal only", []metav1.Condition{cond("SomethingElse")}, ""},
		{"terminal after non-terminal", []metav1.Condition{cond("SomethingElse"), cond(certificatesv1.PodCertificateRequestConditionTypeDenied)}, certificatesv1.PodCertificateRequestConditionTypeDenied},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcr := &certificatesv1.PodCertificateRequest{Status: certificatesv1.PodCertificateRequestStatus{Conditions: tc.conditions}}
			if got := terminalConditionType(&pcr.Status); got != tc.want {
				t.Errorf("terminalConditionType() = %q, want %q", got, tc.want)
			}
			if got, want := isTerminal(pcr), tc.want != ""; got != want {
				t.Errorf("isTerminal() = %t, want %t", got, want)
			}
		})
	}
}

// Each outcome kind maps to its own condition type; only issuance is a
// Normal event.
func TestConditionFor(t *testing.T) {
	for _, tc := range []struct {
		kind          outcome.Kind
		wantCondition string
		wantEvent     string
	}{
		{outcome.Issued, certificatesv1.PodCertificateRequestConditionTypeIssued, corev1.EventTypeNormal},
		{outcome.Denied, certificatesv1.PodCertificateRequestConditionTypeDenied, corev1.EventTypeWarning},
		{outcome.Failed, certificatesv1.PodCertificateRequestConditionTypeFailed, corev1.EventTypeWarning},
	} {
		condition, event := conditionFor(tc.kind)
		if condition != tc.wantCondition || event != tc.wantEvent {
			t.Errorf("conditionFor(%q) = %q, %q, want %q, %q", tc.kind, condition, event, tc.wantCondition, tc.wantEvent)
		}
	}
}

// replacePCR is a SubResourceUpdate interceptor that simulates a request
// deleted between the reconcile's read and its status write. The first write
// deletes the stored request, creates replacement in its place when it is not
// nil, and returns the conflict kube-apiserver returns for the stale UID. Any
// later write goes through, so a retry onto the replacement is observable.
func replacePCR(replacement *certificatesv1.PodCertificateRequest, writes *int) interceptor.Funcs {
	return interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			*writes++
			if *writes > 1 {
				return c.Status().Update(ctx, obj, opts...)
			}
			old := &certificatesv1.PodCertificateRequest{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(obj), old); err != nil {
				return err
			}
			if err := c.Delete(ctx, old); err != nil {
				return err
			}
			if replacement != nil {
				if err := c.Create(ctx, replacement.DeepCopy()); err != nil {
					return err
				}
			}
			return apierrors.NewConflict(
				schema.GroupResource{Group: "certificates.k8s.io", Resource: "podcertificaterequests"},
				obj.GetName(), errors.New("precondition failed: UID in precondition does not match UID in object meta"))
		},
	}
}

// A status write that conflicts because the request was deleted, and possibly
// replaced by a new request with the same namespace and name, must not apply
// this reconcile's outcome to whatever the re-read returns. The outcome was
// computed for the old request, so the reconcile ends without a write, without
// an event, without an outcome metric and without an error, and the caller's
// request still describes the old request. The replacement is reconciled
// through its own create event.
func TestRecordOutcomeConflictOnReplacedRequest(t *testing.T) {
	const (
		oldUID = types.UID("old-request-uid")
		newUID = types.UID("new-request-uid")
	)
	replacement := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns", UID: newUID},
		Spec:       certificatesv1.PodCertificateRequestSpec{PodName: "other-pod", PodUID: "other-pod-uid"},
	}
	type recordFunc func(context.Context, *PodCertificateRequestReconciler, *certificatesv1.PodCertificateRequest) (writeResult, error)
	var issue recordFunc = func(ctx context.Context, r *PodCertificateRequestReconciler, pcr *certificatesv1.PodCertificateRequest) (writeResult, error) {
		return r.recordIssued(ctx, pcr, stubCert())
	}
	var deny recordFunc = func(ctx context.Context, r *PodCertificateRequestReconciler, pcr *certificatesv1.PodCertificateRequest) (writeResult, error) {
		te := denied(outcome.InvalidUserConfig, errors.New("not a verified identity")).(*terminalError)
		return r.recordTerminal(ctx, pcr, te)
	}

	cases := []struct {
		name        string
		replacement *certificatesv1.PodCertificateRequest
		record      recordFunc
		kind        outcome.Kind
		reason      outcome.ConditionReason
		wantLog     []string
	}{
		{"denied onto a replacement", replacement, deny, outcome.Denied, outcome.InvalidUserConfig, []string{string(oldUID), string(newUID)}},
		{"issued onto a replacement", replacement, issue, outcome.Issued, outcome.CertificateIssued, []string{string(oldUID), string(newUID)}},
		{"denied onto a deleted request", nil, deny, outcome.Denied, outcome.InvalidUserConfig, []string{string(oldUID)}},
		{"issued onto a deleted request", nil, issue, outcome.Issued, outcome.CertificateIssued, []string{string(oldUID)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcr := &certificatesv1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns", UID: oldUID},
				Spec:       certificatesv1.PodCertificateRequestSpec{PodName: "mypod", PodUID: "mypod-uid"},
			}
			var writes int
			cl := fake.NewClientBuilder().
				WithScheme(newTestScheme(t)).
				WithObjects(pcr).
				WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
				WithInterceptorFuncs(replacePCR(tc.replacement, &writes)).
				Build()
			if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), pcr); err != nil {
				t.Fatalf("get: %v", err)
			}
			rec := events.NewFakeRecorder(10)
			var lines []string
			r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard(), EventRecorder: rec}
			ctx := logr.NewContext(context.Background(), captureLogger(&lines))
			before := outcomeCount(tc.kind, tc.reason)

			res, err := tc.record(ctx, r, pcr)
			if err != nil {
				t.Fatalf("record error = %v, want nil: a request that is gone needs no requeue", err)
			}
			if res != writeGone {
				t.Errorf("result = %v, want writeGone: the outcome belongs to no live request", res)
			}
			if writes != 1 {
				t.Errorf("status writes = %d, want 1: no write may follow the conflict", writes)
			}
			if pcr.UID != oldUID {
				t.Errorf("caller's request UID = %q, want %q: the caller must not be handed another request", pcr.UID, oldUID)
			}
			select {
			case e := <-rec.Events:
				t.Errorf("recorded event %q, want none", e)
			default:
			}
			if got := outcomeCount(tc.kind, tc.reason) - before; got != 0 {
				t.Errorf("outcome metric moved by %v, want 0", got)
			}

			if n := countLinesContaining(lines, tc.wantLog...); n != 1 {
				t.Errorf("log lines naming %v = %d, want 1; log = %q", tc.wantLog, n, lines)
			}

			if tc.replacement != nil {
				got := &certificatesv1.PodCertificateRequest{}
				if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
					t.Fatalf("get replacement: %v", err)
				}
				if len(got.Status.Conditions) != 0 || got.Status.CertificateChain != "" {
					t.Errorf("replacement status = %+v, want it untouched", got.Status)
				}
			}
		})
	}
}

// conflictErr is the 409 kube-apiserver returns for a status write against a
// stale resourceVersion.
func conflictErr(name string) error {
	return apierrors.NewConflict(
		schema.GroupResource{Group: "certificates.k8s.io", Resource: "podcertificaterequests"},
		name, errors.New("resourceVersion mismatch"))
}

// writeThen is a SubResourceUpdate interceptor that applies the write to the
// fake store and then returns err, as a client does when the API server
// commits the write but the response is lost or reported as a failure.
func writeThen(err error, writes *int) interceptor.Funcs {
	return interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			*writes++
			if uerr := c.Status().Update(ctx, obj, opts...); uerr != nil {
				return uerr
			}
			return err
		},
	}
}

// failWrite is a SubResourceUpdate interceptor that writes nothing and
// returns err.
func failWrite(err error) interceptor.Funcs {
	return interceptor.Funcs{
		SubResourceUpdate: func(context.Context, client.Client, string, client.Object, ...client.SubResourceUpdateOption) error {
			return err
		},
	}
}

// concurrentTerminal is a SubResourceUpdate interceptor whose first write
// loses to another writer: it stores the terminal status that writer
// recorded, then returns a conflict. Any later write goes through. writes
// counts this reconcile's writes, not the other writer's.
func concurrentTerminal(winner certificatesv1.PodCertificateRequestStatus, writes *int) interceptor.Funcs {
	return interceptor.Funcs{
		SubResourceUpdate: func(ctx context.Context, c client.Client, _ string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
			*writes++
			if *writes > 1 {
				return c.Status().Update(ctx, obj, opts...)
			}
			concurrent := &certificatesv1.PodCertificateRequest{}
			if err := c.Get(ctx, client.ObjectKeyFromObject(obj), concurrent); err != nil {
				return err
			}
			winner.DeepCopyInto(&concurrent.Status)
			if err := c.Status().Update(ctx, concurrent); err != nil {
				return err
			}
			return conflictErr(obj.GetName())
		},
	}
}

// terminalStatus returns a request status carrying one terminal condition of
// conditionType and the certificate chain chain.
func terminalStatus(conditionType, chain string) certificatesv1.PodCertificateRequestStatus {
	return certificatesv1.PodCertificateRequestStatus{
		CertificateChain: chain,
		Conditions: []metav1.Condition{{
			Type:               conditionType,
			Status:             metav1.ConditionTrue,
			LastTransitionTime: metav1.Now(),
			Reason:             "ConcurrentWriter",
			Message:            "recorded by a concurrent writer",
		}},
	}
}

// drainEvents returns the number of events rec holds, without blocking.
func drainEvents(rec *events.FakeRecorder) int {
	n := 0
	for {
		select {
		case <-rec.Events:
			n++
		default:
			return n
		}
	}
}

// statusWriteFixture builds a reconciler over a stored request with a UID. The
// status writes go through funcs, and the conflict re-read goes through a
// separate reader with readFuncs, so a test can fail the re-read without
// failing its own setup read.
func statusWriteFixture(t *testing.T, funcs, readFuncs interceptor.Funcs) (*PodCertificateRequestReconciler, *events.FakeRecorder, client.Client, *certificatesv1.PodCertificateRequest) {
	t.Helper()
	pcr := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns", UID: "request-uid"},
		Spec:       certificatesv1.PodCertificateRequestSpec{PodName: "mypod", PodUID: "mypod-uid"},
	}
	store := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		Build()
	cl := interceptor.NewClient(store, funcs)
	reader := interceptor.NewClient(store, readFuncs)
	if err := store.Get(context.Background(), client.ObjectKeyFromObject(pcr), pcr); err != nil {
		t.Fatalf("get: %v", err)
	}
	rec := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: reader, Log: logr.Discard(), EventRecorder: rec}
	return r, rec, store, pcr
}

// Each way a status write can end maps to one writeResult, and only a
// persisted write is announced with an event and counted in the outcome
// metric. The next step decides from the result whether this reconcile's
// outcome is in place, lost to another writer, belongs to no live request,
// was refused, or may or may not be committed.
func TestStatusWriteResult(t *testing.T) {
	replacement := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns", UID: "new-request-uid"},
		Spec:       certificatesv1.PodCertificateRequestSpec{PodName: "other-pod", PodUID: "other-pod-uid"},
	}
	gr := schema.GroupResource{Group: "certificates.k8s.io", Resource: "podcertificaterequests"}
	issued := certificatesv1.PodCertificateRequestConditionTypeIssued
	deniedType := certificatesv1.PodCertificateRequestConditionTypeDenied
	var ownWrites, otherWrites, deniedWrites, deniedOntoIssuedWrites, deletedWrites, replacedWrites int
	invalid := apierrors.NewInvalid(schema.GroupKind{Group: "certificates.k8s.io", Kind: "PodCertificateRequest"}, "pcr",
		field.ErrorList{field.Required(field.NewPath("status", "certificateChain"), "")})

	cases := []struct {
		name      string
		funcs     interceptor.Funcs
		readFuncs interceptor.Funcs
		// deny records a Denied outcome in place of the Issued one.
		deny       bool
		want       writeResult
		wantErr    error
		wantErrIs  func(error) bool
		wantEvents int
		// writes counts the status writes of this reconcile. When it is set,
		// the row asserts it equals wantWrites.
		writes     *int
		wantWrites int
	}{
		{name: "update succeeds", want: writePersisted, wantEvents: 1},
		{name: "conflict, own Issued chain in place", funcs: concurrentTerminal(terminalStatus(issued, "pem-chain"), &ownWrites),
			want: writePersisted, wantEvents: 1, writes: &ownWrites, wantWrites: 1},
		{name: "conflict, another Issued chain in place", funcs: concurrentTerminal(terminalStatus(issued, "other-chain"), &otherWrites),
			want: writeSuperseded, writes: &otherWrites, wantWrites: 1},
		{name: "conflict, Denied in place", funcs: concurrentTerminal(terminalStatus(deniedType, ""), &deniedWrites),
			want: writeSuperseded, writes: &deniedWrites, wantWrites: 1},
		// The re-read chain equals the cleared chain of the denial, so only the
		// Issued type of the desired status tells the two apart.
		{name: "Denied, conflict, Issued in place", funcs: concurrentTerminal(terminalStatus(issued, ""), &deniedOntoIssuedWrites),
			deny: true, want: writeSuperseded, writes: &deniedOntoIssuedWrites, wantWrites: 1},
		{name: "conflict, request deleted", funcs: replacePCR(nil, &deletedWrites),
			want: writeGone, writes: &deletedWrites, wantWrites: 1},
		{name: "conflict, request replaced", funcs: replacePCR(replacement, &replacedWrites),
			want: writeGone, writes: &replacedWrites, wantWrites: 1},
		{name: "update not found", funcs: failWrite(apierrors.NewNotFound(gr, "pcr")), want: writeGone},
		{name: "update invalid", funcs: failWrite(invalid), want: writeRejected, wantErrIs: apierrors.IsInvalid},
		{name: "update forbidden", funcs: failWrite(apierrors.NewForbidden(gr, "pcr", errors.New("no"))),
			want: writeRejected, wantErrIs: apierrors.IsForbidden},
		{name: "update bad request", funcs: failWrite(apierrors.NewBadRequest("bad")),
			want: writeRejected, wantErrIs: apierrors.IsBadRequest},
		{name: "update unauthorized", funcs: failWrite(apierrors.NewUnauthorized("who")),
			want: writeRejected, wantErrIs: apierrors.IsUnauthorized},
		{name: "update timeout", funcs: failWrite(context.DeadlineExceeded), want: writeUnknown, wantErr: context.DeadlineExceeded},
		{name: "update cancelled", funcs: failWrite(context.Canceled), want: writeUnknown, wantErr: context.Canceled},
		{name: "update server timeout", funcs: failWrite(apierrors.NewServerTimeout(gr, "update", 1)),
			want: writeUnknown, wantErrIs: apierrors.IsServerTimeout},
		{name: "update internal error", funcs: failWrite(apierrors.NewInternalError(errors.New("etcd"))),
			want: writeUnknown, wantErrIs: apierrors.IsInternalError},
		{name: "update too many requests", funcs: failWrite(apierrors.NewTooManyRequests("slow down", 1)),
			want: writeUnknown, wantErrIs: apierrors.IsTooManyRequests},
		{
			name: "conflict, re-read fails", funcs: failWrite(conflictErr("pcr")),
			readFuncs: interceptor.Funcs{Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return apierrors.NewForbidden(gr, "pcr", errors.New("no"))
			}},
			want: writeUnknown, wantErrIs: apierrors.IsForbidden,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, rec, _, pcr := statusWriteFixture(t, tc.funcs, tc.readFuncs)
			kind, reason := outcome.Issued, outcome.CertificateIssued
			if tc.deny {
				kind, reason = outcome.Denied, outcome.InvalidUserConfig
			}
			before := outcomeCount(kind, reason)

			var got writeResult
			var err error
			if tc.deny {
				te := denied(outcome.InvalidUserConfig, errors.New("not a verified identity")).(*terminalError)
				got, err = r.recordTerminal(context.Background(), pcr, te)
			} else {
				got, err = r.recordIssued(context.Background(), pcr, stubCert())
			}
			if got != tc.want {
				t.Errorf("result = %v, want %v", got, tc.want)
			}
			switch {
			case tc.wantErrIs != nil && !tc.wantErrIs(err):
				t.Errorf("error = %v, want the API error of the write", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Errorf("error = %v, want %v", err, tc.wantErr)
			case tc.wantErr == nil && tc.wantErrIs == nil && err != nil:
				t.Errorf("error = %v, want nil", err)
			}
			if n := drainEvents(rec); n != tc.wantEvents {
				t.Errorf("events = %d, want %d", n, tc.wantEvents)
			}
			if delta := outcomeCount(kind, reason) - before; delta != float64(tc.wantEvents) {
				t.Errorf("outcome metric moved by %v, want %d", delta, tc.wantEvents)
			}
			if tc.writes != nil && *tc.writes != tc.wantWrites {
				t.Errorf("status writes = %d, want %d", *tc.writes, tc.wantWrites)
			}
		})
	}
}

// A writeResult prints as its name, so a failed comparison is readable.
func TestWriteResultString(t *testing.T) {
	for result, want := range map[writeResult]string{
		writePersisted:  "writePersisted",
		writeSuperseded: "writeSuperseded",
		writeGone:       "writeGone",
		writeRejected:   "writeRejected",
		writeUnknown:    "writeUnknown",
		writeResult(42): "writeResult(42)",
	} {
		if got := result.String(); got != want {
			t.Errorf("writeResult(%d).String() = %q, want %q", int(result), got, want)
		}
	}
}

// A 404 on the status write means the request is gone. The reconcile ends
// without an error, so it is not requeued, and the requeue counter does not
// move.
func TestReconcileStatusWriteNotFoundDoesNotRequeue(t *testing.T) {
	pcr, pod := livePCR(t, "pod-uid", "pod-uid")
	pcr.Spec.SignerName = "example.org/signer"
	pcr.UID = "request-uid"
	gr := schema.GroupResource{Group: "certificates.k8s.io", Resource: "podcertificaterequests"}
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr, pod).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		WithInterceptorFuncs(failWrite(apierrors.NewNotFound(gr, pcr.Name))).
		Build()
	stub := &stubSigner{name: pcr.Spec.SignerName, cert: stubCert()}
	r := &PodCertificateRequestReconciler{
		Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub, SignerName: stub.name, EventRecorder: events.NewFakeRecorder(10),
	}
	transientBefore := requeueCount(outcome.Transient)
	caBefore := requeueCount(outcome.CASignerUnusable)

	res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pcr)})
	if err != nil {
		t.Fatalf("Reconcile() error = %v, want nil: a request that is gone needs no requeue", err)
	}
	if res != (ctrl.Result{}) {
		t.Errorf("Reconcile() result = %+v, want empty", res)
	}
	if !stub.called {
		t.Fatal("signer did not run, so the status write was never reached")
	}
	if delta := requeueCount(outcome.Transient) - transientBefore; delta != 0 {
		t.Errorf("transient requeue counter moved by %v, want 0", delta)
	}
	if delta := requeueCount(outcome.CASignerUnusable) - caBefore; delta != 0 {
		t.Errorf("CA-unusable requeue counter moved by %v, want 0", delta)
	}
}

// A write the API server committed but whose response reports a timeout may
// or may not be in place as far as this reconcile can tell, so it is neither
// announced nor counted, even though the store holds it.
func TestStatusWriteCommitThenTimeout(t *testing.T) {
	var writes int
	r, rec, store, pcr := statusWriteFixture(t, writeThen(context.DeadlineExceeded, &writes), interceptor.Funcs{})
	before := outcomeCount(outcome.Issued, outcome.CertificateIssued)

	got, err := r.recordIssued(context.Background(), pcr, stubCert())
	if got != writeUnknown {
		t.Errorf("result = %v, want writeUnknown", got)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, want context.DeadlineExceeded", err)
	}
	if n := drainEvents(rec); n != 0 {
		t.Errorf("events = %d, want 0", n)
	}
	if delta := outcomeCount(outcome.Issued, outcome.CertificateIssued) - before; delta != 0 {
		t.Errorf("outcome metric moved by %v, want 0", delta)
	}
	stored := &certificatesv1.PodCertificateRequest{}
	if err := store.Get(context.Background(), client.ObjectKeyFromObject(pcr), stored); err != nil {
		t.Fatalf("get: %v", err)
	}
	if terminalConditionType(&stored.Status) != certificatesv1.PodCertificateRequestConditionTypeIssued {
		t.Errorf("stored conditions = %+v, want the committed Issued condition", stored.Status.Conditions)
	}
}

// A client retry after a lost response can meet a 409 from this reconcile's
// own committed write. The re-read then shows this reconcile's Issued chain,
// so the write counts as persisted and is announced once, with no second
// write.
func TestStatusWriteOwnCommitSeenAsConflict(t *testing.T) {
	var writes int
	r, rec, _, pcr := statusWriteFixture(t, writeThen(conflictErr("pcr"), &writes), interceptor.Funcs{})
	before := outcomeCount(outcome.Issued, outcome.CertificateIssued)

	got, err := r.recordIssued(context.Background(), pcr, stubCert())
	if err != nil {
		t.Fatalf("error = %v, want nil", err)
	}
	if got != writePersisted {
		t.Errorf("result = %v, want writePersisted", got)
	}
	if writes != 1 {
		t.Errorf("status writes = %d, want 1", writes)
	}
	if n := drainEvents(rec); n != 1 {
		t.Errorf("events = %d, want 1", n)
	}
	if delta := outcomeCount(outcome.Issued, outcome.CertificateIssued) - before; delta != 1 {
		t.Errorf("outcome metric moved by %v, want 1", delta)
	}
}

// captureLogger records the log lines written at verbosity 0, the production
// default.
func captureLogger(lines *[]string) logr.Logger {
	return funcr.New(func(_, args string) {
		*lines = append(*lines, args)
	}, funcr.Options{Verbosity: 0})
}

// countLinesContaining counts the log lines that contain every one of needles.
func countLinesContaining(lines []string, needles ...string) int {
	n := 0
	for _, line := range lines {
		all := true
		for _, needle := range needles {
			all = all && strings.Contains(line, needle)
		}
		if all {
			n++
		}
	}
	return n
}
