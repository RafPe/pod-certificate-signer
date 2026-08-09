package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/go-logr/logr"
	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func testPCR() *capiv1beta1.PodCertificateRequest {
	return &capiv1beta1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
		Spec:       capiv1beta1.PodCertificateRequestSpec{PodName: "mypod"},
	}
}

// process() must drop (nil, nil) when the pod is absent from both the cache and
// a live read: the request is stale, not a terminal failure to sign.
func TestProcessPodNotFoundDropsAsStale(t *testing.T) {
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build()
	r := &PodCertificateRequestReconciler{Client: cl, APIReader: cl, Log: logr.Discard()}

	cert, err := r.process(context.Background(), testPCR())
	if cert != nil || err != nil {
		t.Fatalf("got (%v, %v), want (nil, nil) drop for a stale request", cert, err)
	}
}

// process() must treat a non-NotFound pod GET error as transient (not terminal).
func TestProcessPodGetErrorIsTransient(t *testing.T) {
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				return apierrors.NewServiceUnavailable("apiserver down")
			},
		}).
		Build()
	r := &PodCertificateRequestReconciler{Client: cl, Log: logr.Discard()}

	cert, err := r.process(context.Background(), testPCR())
	if cert != nil {
		t.Fatalf("cert = %v, want nil", cert)
	}
	if err == nil {
		t.Fatal("want a transient error, got nil")
	}
	var te *TerminalError
	if errors.As(err, &te) {
		t.Fatalf("err = %v, must NOT be terminal", err)
	}
}

// process() must skip (nil, nil) when the associated pod is being deleted.
func TestProcessPodBeingDeletedSkips(t *testing.T) {
	now := metav1.Now()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name:              "mypod",
		Namespace:         "ns",
		DeletionTimestamp: &now,
		Finalizers:        []string{"keep"}, // fake client requires a finalizer to retain DeletionTimestamp
	}}
	cl := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pod).Build()
	r := &PodCertificateRequestReconciler{Client: cl, Log: logr.Discard()}

	cert, err := r.process(context.Background(), testPCR())
	if cert != nil || err != nil {
		t.Fatalf("got (%v, %v), want (nil, nil)", cert, err)
	}
}

// recordFailure: a terminal error writes a condition and does not requeue.
func TestRecordFailureTerminalWritesCondition(t *testing.T) {
	pcr := testPCR()
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&capiv1beta1.PodCertificateRequest{}).
		Build()
	r := &PodCertificateRequestReconciler{Client: cl, Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10)}

	res, err := r.recordFailure(context.Background(), pcr, failed(ReasonSigningFailed, errors.New("x")))
	if err != nil {
		t.Fatalf("recordFailure returned err = %v, want nil", err)
	}
	if res != (ctrl.Result{}) {
		t.Fatalf("result = %+v, want empty (no requeue)", res)
	}
	got := &capiv1beta1.PodCertificateRequest{}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Conditions) != 1 {
		t.Fatalf("conditions = %d, want 1", len(got.Status.Conditions))
	}
}

// recordFailure: a transient error is returned (requeue) and writes no condition.
func TestRecordFailureTransientRequeues(t *testing.T) {
	pcr := testPCR()
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&capiv1beta1.PodCertificateRequest{}).
		Build()
	r := &PodCertificateRequestReconciler{Client: cl, Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10)}

	sentinel := errors.New("apiserver blip")
	if _, err := r.recordFailure(context.Background(), pcr, sentinel); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel returned for requeue", err)
	}
	got := &capiv1beta1.PodCertificateRequest{}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
		t.Fatal(err)
	}
	if len(got.Status.Conditions) != 0 {
		t.Fatalf("conditions = %d, want 0 (transient must not write)", len(got.Status.Conditions))
	}
}

// recordFailure: when recording a terminal outcome fails because the status
// write itself errors, that write error is returned so the reconcile requeues
// (the Failed condition is never silently lost).
func TestRecordFailureWriteErrorRequeues(t *testing.T) {
	pcr := testPCR()
	writeErr := errors.New("status write failed")
	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr).
		WithStatusSubresource(&capiv1beta1.PodCertificateRequest{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, c client.Client, subResourceName string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				return writeErr
			},
		}).
		Build()
	r := &PodCertificateRequestReconciler{Client: cl, Log: logr.Discard(), EventRecorder: events.NewFakeRecorder(10)}

	if _, err := r.recordFailure(context.Background(), pcr, failed(ReasonSigningFailed, errors.New("boom"))); !errors.Is(err, writeErr) {
		t.Fatalf("err = %v, want the status-write error returned for requeue", err)
	}
}
