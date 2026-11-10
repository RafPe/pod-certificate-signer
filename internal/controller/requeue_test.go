package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// requeueOrRecordTerminal: a terminal error writes a condition and does not requeue.
func TestRequeueOrRecordTerminalWritesTerminalCondition(t *testing.T) {
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
func TestRequeueOrRecordTerminalRequeuesTransient(t *testing.T) {
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
func TestRequeueOrRecordTerminalRequeuesOnWriteError(t *testing.T) {
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

// A requeue is classified, never counted as an outcome: the CA-unusable case is
// the silent hang, and it must be separable from ordinary transient noise.
func TestRequeuesAreClassified(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantReason outcome.NonTerminalReason
	}{
		{"ca unusable", fmt.Errorf("cannot sign: %w", authority.ErrCASignerUnusable), outcome.CASignerUnusable},
		{"anything else", errors.New("etcdserver: request timed out"), outcome.Transient},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// requeueOrRecordTerminal announces CA-unusable requeues as an event, so the
			// reconciler needs a recorder even though this test asserts the metric.
			r := &PodCertificateRequestReconciler{Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10)}
			ctx := logr.NewContext(context.Background(), logr.Discard())

			before := requeueCount(tc.wantReason)
			if _, err := r.requeueOrRecordTerminal(ctx, &certificatesv1.PodCertificateRequest{}, tc.err); err == nil {
				t.Fatal("requeueOrRecordTerminal() error = nil, want the transient error returned for requeue")
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
	r.warnPodGone(&certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
	}, "pod is gone")
	if got := dropCount() - before; got != 1 {
		t.Errorf("drop counter moved by %v, want 1", got)
	}
}
