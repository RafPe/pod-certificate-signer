package controller

import (
	"context"
	"errors"
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

	err := r.recordOutcome(context.Background(), pcr,
		certificatesv1.PodCertificateRequestConditionTypeIssued, ReasonCertificateIssued, "issued", corev1.EventTypeNormal)
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
		Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub, EventRecorder: rec,
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
						Reason:             string(ReasonInvalidUserAnnotations),
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
		Client: cl, APIReader: cl, Log: logr.Discard(), Signer: stub, EventRecorder: rec,
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
