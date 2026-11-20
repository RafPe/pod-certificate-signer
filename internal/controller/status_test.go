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
			if err := r.recordTerminal(context.Background(), pcr, te); err != nil {
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
	if err := r.recordTerminal(context.Background(), pcr, denied(outcome.InvalidUserConfig, errors.New(message)).(*terminalError)); err != nil {
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
	type recordFunc func(context.Context, *PodCertificateRequestReconciler, *certificatesv1.PodCertificateRequest) (bool, error)
	var issue recordFunc = func(ctx context.Context, r *PodCertificateRequestReconciler, pcr *certificatesv1.PodCertificateRequest) (bool, error) {
		return r.recordIssued(ctx, pcr, stubCert())
	}
	var deny recordFunc = func(ctx context.Context, r *PodCertificateRequestReconciler, pcr *certificatesv1.PodCertificateRequest) (bool, error) {
		te := denied(outcome.InvalidUserConfig, errors.New("not a verified identity")).(*terminalError)
		return false, r.recordTerminal(ctx, pcr, te)
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

			persisted, err := tc.record(ctx, r, pcr)
			if err != nil {
				t.Fatalf("record error = %v, want nil: a request that is gone needs no requeue", err)
			}
			if persisted {
				t.Error("persisted = true, want false: the outcome was not written")
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
