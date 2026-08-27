package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
)

const caUnusableSignerName = "example.org/signer"

// caUnusableErr is the shape authority.Sign returns for a CA whose remaining
// validity cannot cover the requested lifetime - the realistic trigger, since
// the signer backdates notBefore by a minute and a 24h CA therefore cannot sign
// a default 24h certificate at all.
func caUnusableErr() error {
	return fmt.Errorf("certificate validity period exceeds the signer CA validity: notAfter=x, caNotAfter=y: %w",
		authority.ErrCASignerUnusable)
}

// caUnusableHarness wires a reconciler over a request whose pod exists, with a
// signer that fails the way an unusable CA does, and a clock the test advances.
func caUnusableHarness(t *testing.T, signErr error, clock *time.Time) (
	*PodCertificateRequestReconciler, *certificatesv1.PodCertificateRequest, *events.FakeRecorder, client.Client,
) {
	t.Helper()

	pcr, pod := livePCR(t, "uid-1", "uid-1")
	pcr.UID = types.UID("pcr-uid-1")
	pcr.Spec.SignerName = caUnusableSignerName

	cl := fake.NewClientBuilder().
		WithScheme(newTestScheme(t)).
		WithObjects(pcr, pod).
		WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
		Build()
	rec := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{
		Client:        cl,
		APIReader:     cl,
		Log:           logr.Discard(),
		Signer:        &stubSigner{name: caUnusableSignerName, err: signErr},
		EventRecorder: rec,
	}
	r.caUnusableEvents.nowFunc = func() time.Time { return *clock }

	return r, pcr, rec, cl
}

// reconcileOnce runs a full Reconcile and asserts it requeued (returned the
// transient error) rather than recording a terminal outcome.
func reconcileRequeues(t *testing.T, r *PodCertificateRequestReconciler, pcr *certificatesv1.PodCertificateRequest) {
	t.Helper()

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pcr)})
	if err == nil {
		t.Fatal("Reconcile() error = nil, want the transient error so controller-runtime requeues")
	}
	if !errors.Is(err, authority.ErrCASignerUnusable) {
		t.Fatalf("Reconcile() error = %v, want it to still wrap ErrCASignerUnusable", err)
	}
}

// A CA that cannot sign the request is recoverable, so the reconcile requeues
// and writes no condition - which leaves `kubectl describe` empty while the pod
// hangs in ContainerCreating. The warning event is the only operator-visible
// signal, so it must be emitted, must not be accompanied by a terminal
// condition, and must not repeat on every requeue.
func TestReconcileCASignerUnusableEmitsThrottledWarning(t *testing.T) {
	clock := time.Now()
	r, pcr, rec, cl := caUnusableHarness(t, caUnusableErr(), &clock)

	reconcileRequeues(t, r, pcr)

	select {
	case e := <-rec.Events:
		if !strings.Contains(e, corev1.EventTypeWarning) {
			t.Errorf("event = %q, want a %s event", e, corev1.EventTypeWarning)
		}
		if !strings.Contains(e, "CASignerUnusable") {
			t.Errorf("event = %q, want reason CASignerUnusable", e)
		}
		if !strings.Contains(e, "exceeds the signer CA validity") {
			t.Errorf("event = %q, want it to carry the signing error", e)
		}
	default:
		t.Fatal("no event recorded, want one warning event for the unusable CA")
	}

	// The requeue must stay recoverable: a condition would make the request
	// immutable, so a later CA rotation could never satisfy it.
	got := &certificatesv1.PodCertificateRequest{}
	if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
		t.Fatalf("get PodCertificateRequest: %v", err)
	}
	if len(got.Status.Conditions) != 0 {
		t.Errorf("Reconcile() wrote conditions = %+v, want none (the wait must not be terminal)", got.Status.Conditions)
	}

	// Requeues keep arriving while the CA stays unusable; the event must not.
	for range 3 {
		reconcileRequeues(t, r, pcr)
	}
	select {
	case e := <-rec.Events:
		t.Fatalf("second event = %q, want the warning rate-limited across requeues", e)
	default:
	}

	// Once the window has passed the condition is re-announced, so an operator
	// who arrives late still sees it.
	clock = clock.Add(defaultEventThrottleInterval)
	reconcileRequeues(t, r, pcr)
	select {
	case e := <-rec.Events:
		if !strings.Contains(e, "CASignerUnusable") {
			t.Errorf("event after the window = %q, want reason CASignerUnusable", e)
		}
	default:
		t.Error("no event after the rate-limit window elapsed, want the warning repeated")
	}
}

// Only the CA-unusable case is announced. Every other transient error is the
// controller's own retry loop working as intended (an API read failure, a
// conflicted write), and an event for those would be noise on an object whose
// reconcile is about to succeed.
func TestReconcileOtherTransientErrorsEmitNoEvent(t *testing.T) {
	clock := time.Now()
	r, pcr, rec, _ := caUnusableHarness(t, caUnusableErr(), &clock)

	// A transient error that is not the CA (a failed API read, say) is routed
	// through the same branch, so assert on that branch directly.
	ctx := logr.NewContext(context.Background(), logr.Discard())
	if _, err := r.recordFailure(ctx, pcr, errors.New("etcdserver: request timed out")); err == nil {
		t.Fatal("recordFailure() error = nil, want the transient error returned so the reconcile requeues")
	}

	select {
	case e := <-rec.Events:
		t.Errorf("event = %q, want no event for a transient error unrelated to the CA", e)
	default:
	}
}

// The rate limit is per request, not global: a second request hitting the same
// unusable CA must still get its own event, or the first stuck workload would
// mask every other one.
func TestEventThrottleIsPerObject(t *testing.T) {
	now := time.Now()
	throttle := eventThrottle{nowFunc: func() time.Time { return now }}

	if !throttle.allow("uid-a") {
		t.Fatal("first event for uid-a was throttled, want it emitted")
	}
	if !throttle.allow("uid-b") {
		t.Fatal("first event for uid-b was throttled, want each object its own budget")
	}
	if throttle.allow("uid-a") {
		t.Error("second event for uid-a inside the window was emitted, want it throttled")
	}

	// Entries drop out of the map once their window has passed, so the throttle
	// does not grow with every request the controller has ever seen.
	now = now.Add(defaultEventThrottleInterval)
	if !throttle.allow("uid-a") {
		t.Error("event for uid-a after the window was throttled, want it emitted")
	}
	if len(throttle.last) != 1 {
		t.Errorf("throttle holds %d entries, want only the one seen inside the current window", len(throttle.last))
	}
}
