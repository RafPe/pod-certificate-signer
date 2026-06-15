package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// newTestScheme builds a scheme with the types the controller tests need.
// Shared by the other controller unit tests in this package.
func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := capiv1beta1.AddToScheme(scheme); err != nil {
		t.Fatalf("add capiv1beta1: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1: %v", err)
	}
	return scheme
}

func TestOutcomesTable(t *testing.T) {
	want := map[Reason]struct {
		condType  string
		eventType string
		clears    bool
	}{
		ReasonAssociatedPodNotFound:           {"Failed", corev1.EventTypeWarning, true},
		ReasonUnsupportedKeyType:              {"Denied", corev1.EventTypeWarning, true},
		ReasonCertificateConfigurationInvalid: {"Failed", corev1.EventTypeWarning, true},
		ReasonSigningFailed:                   {"Failed", corev1.EventTypeWarning, true},
		ReasonSigningDenied:                   {"Denied", corev1.EventTypeWarning, true},
		ReasonCertificateIssued:               {"Issued", corev1.EventTypeNormal, false},
	}

	if len(outcomes) != len(want) {
		t.Fatalf("outcomes has %d entries, want %d", len(outcomes), len(want))
	}
	for reason, exp := range want {
		o, ok := outcomes[reason]
		if !ok {
			t.Fatalf("missing outcome for reason %q", reason)
		}
		if o.ConditionType != exp.condType {
			t.Errorf("%s: ConditionType=%s want %s", reason, o.ConditionType, exp.condType)
		}
		if o.eventType() != exp.eventType {
			t.Errorf("%s: eventType=%s want %s", reason, o.eventType(), exp.eventType)
		}
		clears := o.ConditionType != capiv1beta1.PodCertificateRequestConditionTypeIssued
		if clears != exp.clears {
			t.Errorf("%s: clears=%v want %v", reason, clears, exp.clears)
		}
	}
}

func TestApplyOutcome(t *testing.T) {
	scheme := newTestScheme(t)

	cases := []struct {
		name        string
		reason      Reason
		wantType    string
		wantEvent   string
		wantCleared bool
	}{
		{"failure clears fields", ReasonSigningFailed, "Failed", corev1.EventTypeWarning, true},
		{"denied clears fields", ReasonUnsupportedKeyType, "Denied", corev1.EventTypeWarning, true},
		{"issued keeps fields", ReasonCertificateIssued, "Issued", corev1.EventTypeNormal, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcr := &capiv1beta1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
				Status:     capiv1beta1.PodCertificateRequestStatus{CertificateChain: "preexisting"},
			}
			cl := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(pcr).
				WithStatusSubresource(&capiv1beta1.PodCertificateRequest{}).
				Build()
			rec := events.NewFakeRecorder(10)
			r := &PodCertificateRequestReconciler{Client: cl, Log: logr.Discard(), EventRecorder: rec}

			if err := r.applyOutcome(context.Background(), pcr, tc.reason); err != nil {
				t.Fatalf("applyOutcome: %v", err)
			}

			got := &capiv1beta1.PodCertificateRequest{}
			if err := cl.Get(context.Background(), client.ObjectKeyFromObject(pcr), got); err != nil {
				t.Fatalf("get: %v", err)
			}
			if len(got.Status.Conditions) != 1 {
				t.Fatalf("conditions = %d, want 1", len(got.Status.Conditions))
			}
			if got.Status.Conditions[0].Type != tc.wantType {
				t.Errorf("condition type = %s, want %s", got.Status.Conditions[0].Type, tc.wantType)
			}
			if got.Status.Conditions[0].Reason != string(tc.reason) {
				t.Errorf("condition reason = %s, want %s", got.Status.Conditions[0].Reason, tc.reason)
			}
			if cleared := got.Status.CertificateChain == ""; cleared != tc.wantCleared {
				t.Errorf("cleared = %v, want %v", cleared, tc.wantCleared)
			}
			select {
			case e := <-rec.Events:
				if !strings.Contains(e, tc.wantEvent) {
					t.Errorf("event = %q, want to contain %s", e, tc.wantEvent)
				}
			default:
				t.Error("no event recorded")
			}
		})
	}
}
