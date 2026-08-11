package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// A pod name whose DNS label exceeds the 63-character limit gets no default pod
// DNS SANs, because truncating would let two pods sharing a prefix impersonate
// each other. The drop is not fatal - at 64 characters the common name still
// carries the identity, so the certificate issues - but the operator must be
// told, so process() emits a Warning event explaining why the default SAN was
// dropped.
func TestProcessLongPodNameEmitsDefaultSANWarning(t *testing.T) {
	pcr, pod := livePCR(t, "uid-1", "uid-1")
	longName := strings.Repeat("a", 64)
	pcr.Spec.PodName = longName
	pod.Name = longName

	cache := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pod).Build()
	stub := &stubSigner{name: "example.org/signer", cert: stubCert()}
	rec := events.NewFakeRecorder(10)
	r := &PodCertificateRequestReconciler{
		Client: cache, APIReader: cache, Log: logr.Discard(), Signer: stub, EventRecorder: rec,
	}
	ctx := logr.NewContext(context.Background(), logr.Discard())

	cert, err := r.process(ctx, pcr)
	if err != nil {
		t.Fatalf("process() error = %v, want nil (the CN carries the identity)", err)
	}
	if cert == nil {
		t.Fatal("process() cert = nil, want the signed certificate")
	}

	select {
	case e := <-rec.Events:
		if !strings.Contains(e, corev1.EventTypeWarning) {
			t.Errorf("event = %q, want a %s event", e, corev1.EventTypeWarning)
		}
		if !strings.Contains(e, string(ReasonDefaultSANSkipped)) {
			t.Errorf("event = %q, want reason %s", e, ReasonDefaultSANSkipped)
		}
		if !strings.Contains(e, "DNS label limit") {
			t.Errorf("event = %q, want it to explain the DNS label limit", e)
		}
	default:
		t.Fatal("no event recorded, want one warning event for the skipped default SAN")
	}
}
