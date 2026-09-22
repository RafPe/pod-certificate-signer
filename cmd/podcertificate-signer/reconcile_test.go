package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	signermetrics "github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

// newTestPublisher builds a ctbPublisher backed by a real CA and signer, and
// the given client, with the production tick and retry settings. Tests that
// hit a retry or a tick must run inside a synctest bubble.
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
		interval: ctbDriftRepairInterval,
		backoff:  ctbPublishBackoff,
		// A throwaway vector rather than the package-level one, so each test
		// counts only its own publishes.
		publishes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_clustertrustbundle_publish_attempts_total",
		}, []string{"result"}),
	}
}

// A publish that fails transiently must be retried (with backoff) until it
// succeeds, rather than being abandoned after a single attempt.
func TestReconcileRetriesTransientFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		ctx := t.Context()
		if !p.reconcile(ctx, log.FromContext(ctx)) {
			t.Fatal("reconcile should have run")
		}

		if got := getCalls.Load(); got != 3 {
			t.Errorf("Get was called %d times, want 3 (two transient failures, then success)", got)
		}
		if err := p.Healthy(); err != nil {
			t.Errorf("Healthy = %v, want nil after a successful retry", err)
		}
		if got := publishCount(p, signermetrics.ResultFailed); got != 0 {
			t.Errorf("publish attempts {result=failed} = %v, want 0 after eventual success", got)
		}
		if got := publishCount(p, signermetrics.ResultCreated); got != 1 {
			t.Errorf("publish attempts {result=created} = %v, want 1 after the first successful publish", got)
		}
	})
}

// publishCount reports the publisher's attempt counter for one result.
func publishCount(p *ctbPublisher, result string) float64 {
	return promtestutil.ToFloat64(p.publishes.WithLabelValues(result))
}

// The publisher must re-publish on a periodic tick, independent of any fsnotify
// event, so drift in the ClusterTrustBundle is repaired even when the CA files
// never change.
func TestReconcileTickerRepairsDrift(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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

		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		done := make(chan error, 1)
		go func() { done <- p.Start(ctx) }()

		// The startup publish, then exactly two drift-repair ticks with no
		// event ever sent. The half interval keeps the second tick
		// unambiguously before the sleep returns.
		time.Sleep(2*p.interval + p.interval/2)
		synctest.Wait()
		if got := getCalls.Load(); got != 3 {
			t.Errorf("Get called %d times after the startup publish and two ticks, want 3", got)
		}

		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Start() = %v, want nil on context cancellation", err)
			}
		case <-time.After(time.Second):
			t.Error("Start() did not return within a fake second of context cancellation")
		}
	})
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
// unhealthy (failing readiness) and the publish attempt counter records a
// failed result.
func TestReconcilePersistentFailureSurfaced(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(clientgoscheme.Scheme).
			WithInterceptorFuncs(interceptor.Funcs{
				Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
					return errors.New("etcdserver: request timed out")
				},
			}).
			Build()

		p := newTestPublisher(t, c)
		ctx := t.Context()
		p.reconcile(ctx, log.FromContext(ctx))

		if p.Healthy() == nil {
			t.Error("Healthy must report an error after a persistent publish failure")
		}
		if got := publishCount(p, signermetrics.ResultFailed); got != 1 {
			t.Errorf("publish attempts {result=failed} = %v, want 1 after the retry budget is exhausted", got)
		}
	})
}

// A publish that changed nothing must still be counted, so a leader that has
// stopped publishing is distinguishable from one that is publishing
// successfully - the ambiguity the failure-only counter could not resolve.
func TestReconcileCountsUnchangedPublish(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(clientgoscheme.Scheme).Build()

	p := newTestPublisher(t, c)
	ctx := context.Background()
	p.reconcile(ctx, log.FromContext(ctx))
	p.reconcile(ctx, log.FromContext(ctx))

	if got := publishCount(p, signermetrics.ResultCreated); got != 1 {
		t.Errorf("publish attempts {result=created} = %v, want 1", got)
	}
	if got := publishCount(p, signermetrics.ResultUnchanged); got != 1 {
		t.Errorf("publish attempts {result=unchanged} = %v, want 1 on a republish of the same bundle", got)
	}
}

// A successful publish after a failure must clear the unhealthy state.
func TestReconcileClearsHealthOnSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
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
		ctx := t.Context()

		p.reconcile(ctx, log.FromContext(ctx))
		if p.Healthy() == nil {
			t.Fatal("Healthy must report an error while publishing keeps failing")
		}

		fail.Store(false)
		p.reconcile(ctx, log.FromContext(ctx))
		if err := p.Healthy(); err != nil {
			t.Errorf("Healthy = %v, want nil after a successful publish", err)
		}
	})
}
