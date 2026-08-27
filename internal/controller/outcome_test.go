package controller

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

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
		{"denied clears fields", denied(ReasonUnsupportedKeyType, errors.New("bad key")), "Denied"},
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
			r := &PodCertificateRequestReconciler{Client: cl, Log: logr.Discard(), EventRecorder: rec}

			var te *TerminalError
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
			if cond.Reason != string(te.Reason) {
				t.Errorf("condition reason = %s, want %s", cond.Reason, te.Reason)
			}
			if cond.Message != te.Err.Error() {
				t.Errorf("condition message = %q, want the error text %q", cond.Message, te.Err.Error())
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
	r := &PodCertificateRequestReconciler{Client: cl, Log: logr.Discard(), EventRecorder: rec}

	now := time.Now()
	cert := podcertificate.NewPodCertificate(
		nil,
		"pem-chain",
		&podcertificate.PodCertificateConfig{Duration: time.Hour, RefreshBefore: 15 * time.Minute},
		now,
		now.Add(time.Hour),
	)

	if err := r.recordIssued(context.Background(), pcr, cert); err != nil {
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
