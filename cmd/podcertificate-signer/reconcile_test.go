package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// newTestPublisher builds a ctbPublisher backed by a real CA and signer, and
// the given client, with fast retry/tick settings suitable for tests.
func newTestPublisher(t *testing.T, c client.Client) *ctbPublisher {
	t.Helper()

	dir := t.TempDir()
	kp, err := testutil.NewCA("ca.example.org", 24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	if _, _, err := kp.WriteFiles(dir); err != nil {
		t.Fatalf("write CA files: %v", err)
	}
	ca, err := authority.New(dir+"/tls.crt", dir+"/tls.key")
	if err != nil {
		t.Fatalf("authority.New: %v", err)
	}
	s, err := signer.New(testSignerName, ca)
	if err != nil {
		t.Fatalf("signer.New: %v", err)
	}

	return &ctbPublisher{
		client:   c,
		signer:   s,
		ca:       ca,
		events:   make(chan struct{}),
		interval: time.Hour,
		backoff:  wait.Backoff{Steps: 8, Duration: time.Millisecond, Factor: 2.0},
		failures: prometheus.NewCounter(prometheus.CounterOpts{Name: "test_ctb_publish_failures_total"}),
	}
}

// A publish that fails transiently must be retried (with backoff) until it
// succeeds, rather than being abandoned after a single attempt.
func TestReconcileRetriesTransientFailure(t *testing.T) {
	var getCalls atomic.Int32
	c := fake.NewClientBuilder().
		WithScheme(clientgoscheme.Scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if getCalls.Add(1) <= 2 {
					return errors.New("etcdserver: leader changed")
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	p := newTestPublisher(t, c)
	ctx := context.Background()
	if !p.reconcile(ctx, log.FromContext(ctx)) {
		t.Fatal("reconcile should have run")
	}

	if got := getCalls.Load(); got < 3 {
		t.Errorf("Get was called %d times, want >= 3 (transient failures retried)", got)
	}
	if err := p.Healthy(); err != nil {
		t.Errorf("Healthy = %v, want nil after a successful retry", err)
	}
	if got := promtestutil.ToFloat64(p.failures); got != 0 {
		t.Errorf("ctb_publish_failures_total = %v, want 0 after eventual success", got)
	}
}

// The publisher must re-publish on a periodic tick, independent of any fsnotify
// event, so drift in the ClusterTrustBundle is repaired even when the CA files
// never change.
func TestReconcileTickerRepairsDrift(t *testing.T) {
	var getCalls atomic.Int32
	c := fake.NewClientBuilder().
		WithScheme(clientgoscheme.Scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				getCalls.Add(1)
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	p := newTestPublisher(t, c)
	p.interval = 20 * time.Millisecond // drift-repair tick, no events ever fire

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- p.Start(ctx) }()

	// Initial publish plus at least one drift-repair tick, with no event sent.
	deadline := time.After(2 * time.Second)
	for getCalls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatalf("ticker did not repair drift: Get called %d times, want >= 2", getCalls.Load())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// Only one publish may run at a time: a reconcile triggered while another is in
// flight must be skipped (coalesced), not run concurrently.
func TestReconcileSingleFlight(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	c := fake.NewClientBuilder().
		WithScheme(clientgoscheme.Scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				entered <- struct{}{}
				<-release
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	p := newTestPublisher(t, c)
	ctx := context.Background()

	ran := make(chan bool, 1)
	go func() { ran <- p.reconcile(ctx, log.FromContext(ctx)) }()

	<-entered // first reconcile is inside the publish, holding the single-flight lock
	if p.reconcile(ctx, log.FromContext(ctx)) {
		t.Error("a concurrent reconcile must be skipped while a publish is in flight")
	}

	close(release)
	if got := <-ran; !got {
		t.Error("the first reconcile should report that it ran")
	}
}

// A publish that keeps failing must be surfaced: the publisher becomes
// unhealthy (failing readiness) and the ctb_publish_failures_total counter is
// incremented.
func TestReconcilePersistentFailureSurfaced(t *testing.T) {
	c := fake.NewClientBuilder().
		WithScheme(clientgoscheme.Scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return errors.New("etcdserver: request timed out")
			},
		}).
		Build()

	p := newTestPublisher(t, c)
	ctx := context.Background()
	p.reconcile(ctx, log.FromContext(ctx))

	if p.Healthy() == nil {
		t.Error("Healthy must report an error after a persistent publish failure")
	}
	if got := promtestutil.ToFloat64(p.failures); got < 1 {
		t.Errorf("ctb_publish_failures_total = %v, want >= 1 after persistent failure", got)
	}
}

// A successful publish after a failure must clear the unhealthy state.
func TestReconcileClearsHealthOnSuccess(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	c := fake.NewClientBuilder().
		WithScheme(clientgoscheme.Scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if fail.Load() {
					return errors.New("transient")
				}
				return cl.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	p := newTestPublisher(t, c)
	p.backoff = wait.Backoff{Steps: 2, Duration: time.Millisecond}
	ctx := context.Background()

	p.reconcile(ctx, log.FromContext(ctx))
	if p.Healthy() == nil {
		t.Fatal("Healthy must report an error while publishing keeps failing")
	}

	fail.Store(false)
	p.reconcile(ctx, log.FromContext(ctx))
	if err := p.Healthy(); err != nil {
		t.Errorf("Healthy = %v, want nil after a successful publish", err)
	}
}
