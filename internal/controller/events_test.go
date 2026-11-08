package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
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
// signer that fails the way an unusable CA does.
func caUnusableHarness(t *testing.T, signErr error) (
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

	return r, pcr, rec, cl
}

// reconcileOnce runs a full Reconcile and asserts it requeued (returned the
// transient error) rather than recording a terminal outcome.
func reconcileRequeues(t *testing.T, r *PodCertificateRequestReconciler, pcr *certificatesv1.PodCertificateRequest) {
	t.Helper()

	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pcr)})
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
	synctest.Test(t, func(t *testing.T) {
		r, pcr, rec, cl := caUnusableHarness(t, caUnusableErr())

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
		if err := cl.Get(t.Context(), client.ObjectKeyFromObject(pcr), got); err != nil {
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
		time.Sleep(defaultEventThrottleInterval)
		reconcileRequeues(t, r, pcr)
		select {
		case e := <-rec.Events:
			if !strings.Contains(e, "CASignerUnusable") {
				t.Errorf("event after the window = %q, want reason CASignerUnusable", e)
			}
		default:
			t.Error("no event after the rate-limit window elapsed, want the warning repeated")
		}
	})
}

// Only the CA-unusable case is announced. Every other transient error is the
// controller's own retry loop working as intended (an API read failure, a
// conflicted write), and an event for those would be noise on an object whose
// reconcile is about to succeed.
func TestReconcileOtherTransientErrorsEmitNoEvent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		r, pcr, rec, _ := caUnusableHarness(t, caUnusableErr())

		// A transient error that is not the CA (a failed API read, say) is routed
		// through the same branch, so assert on that branch directly.
		ctx := logr.NewContext(t.Context(), logr.Discard())
		if _, err := r.recordFailure(ctx, pcr, errors.New("etcdserver: request timed out")); err == nil {
			t.Fatal("recordFailure() error = nil, want the transient error returned so the reconcile requeues")
		}

		select {
		case e := <-rec.Events:
			t.Errorf("event = %q, want no event for a transient error unrelated to the CA", e)
		default:
		}
	})
}

// The rate limit is per request, not global: a second request hitting the same
// unusable CA must still get its own event, or the first stuck workload would
// mask every other one.
func TestEventThrottleIsPerObject(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var throttle eventThrottle

		if !throttle.allow("uid-a") {
			t.Fatal("first event for uid-a was throttled, want it emitted")
		}
		if !throttle.allow("uid-b") {
			t.Fatal("first event for uid-b was throttled, want each object its own budget")
		}
		if throttle.allow("uid-a") {
			t.Error("second event for uid-a inside the window was emitted, want it throttled")
		}

		// Entries drop out of the map once their window has passed, so the
		// throttle does not grow with every object it has ever seen.
		time.Sleep(defaultEventThrottleInterval)
		if !throttle.allow("uid-a") {
			t.Error("event for uid-a after the window was throttled, want it emitted")
		}
		if len(throttle.last) != 1 {
			t.Errorf("throttle holds %d entries, want only the one seen inside the current window", len(throttle.last))
		}
	})
}

// Dropping a request whose pod is confirmed gone leaves no trace in the PCR
// status (that would be a terminal outcome, which #29 deliberately removed), so
// the only operator-visible breadcrumb is an event. Reconcile must emit exactly
// one warning event and write no condition, on both confirmed-gone paths: the
// pod absent from a live read, and a live read that confirms a pod UID other
// than the one the request asked for. The two paths share a reason but carry
// different notes, because a replaced pod is not a missing one: the note names
// both the requested and the observed UID so an operator need not read the logs.
func TestReconcileDroppedGonePodEmitsEvent(t *testing.T) {
	const (
		signerName = "example.org/signer"
		// The reason as operators see it on the event, not via the constant.
		wantReason = "AssociatedPodGone"
	)

	cases := []struct {
		name string
		// livePodUID stamps the pod visible to both the cached and the live
		// read; empty means no pod exists at all.
		livePodUID types.UID
		wantNote   string
	}{
		{
			name:     "pod absent on the live read",
			wantNote: "associated pod ns/mypod (uid uid-1) not found; dropping request",
		},
		{
			name:       "live read confirms a different pod UID",
			livePodUID: "uid-stale",
			wantNote:   "associated pod ns/mypod was replaced (request uid uid-1, live uid uid-stale); dropping request",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcr, pod := livePCR(t, "uid-1", tc.livePodUID)
			pcr.Spec.SignerName = signerName

			var pods []client.Object
			if tc.livePodUID != "" {
				pods = append(pods, pod)
			}
			cache := fake.NewClientBuilder().
				WithScheme(newTestScheme(t)).
				WithObjects(append([]client.Object{pcr}, pods...)...).
				WithStatusSubresource(&certificatesv1.PodCertificateRequest{}).
				Build()
			live := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pods...).Build()

			stub := &stubSigner{name: signerName, cert: stubCert()}
			rec := events.NewFakeRecorder(10)
			r := &PodCertificateRequestReconciler{
				Client: cache, APIReader: live, Log: logr.Discard(), Signer: stub, EventRecorder: rec,
			}

			res, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(pcr)})
			if err != nil {
				t.Fatalf("Reconcile() error = %v, want nil (a gone pod is dropped, not retried)", err)
			}
			if res != (ctrl.Result{}) {
				t.Errorf("Reconcile() result = %+v, want empty (no requeue)", res)
			}
			if stub.called {
				t.Error("signer must not run for a request whose pod is gone")
			}

			got := &certificatesv1.PodCertificateRequest{}
			if err := cache.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
				t.Fatalf("get PodCertificateRequest: %v", err)
			}
			if len(got.Status.Conditions) != 0 {
				t.Errorf("Reconcile() wrote conditions = %+v, want none (the drop must not be terminal)", got.Status.Conditions)
			}

			select {
			case e := <-rec.Events:
				if !strings.Contains(e, corev1.EventTypeWarning) {
					t.Errorf("event = %q, want a %s event", e, corev1.EventTypeWarning)
				}
				if !strings.Contains(e, wantReason) {
					t.Errorf("event = %q, want reason %s", e, wantReason)
				}
				if !strings.Contains(e, tc.wantNote) {
					t.Errorf("event = %q, want it to contain %q", e, tc.wantNote)
				}
			default:
				t.Fatal("no event recorded, want one warning event for the dropped request")
			}
			select {
			case e := <-rec.Events:
				t.Errorf("second event = %q, want exactly one event on the drop", e)
			default:
			}
		})
	}
}
