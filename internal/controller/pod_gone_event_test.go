package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

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
				WithStatusSubresource(&capiv1beta1.PodCertificateRequest{}).
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

			got := &capiv1beta1.PodCertificateRequest{}
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
