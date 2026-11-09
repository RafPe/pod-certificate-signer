package controller

import (
	"testing"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The terminal condition type decides whether a request is still the
// reconciler's to act on: any of the three terminal types wins, regardless of
// where it sits among non-terminal conditions, and a request without one is
// still open.
func TestTerminalConditionType(t *testing.T) {
	cond := func(conditionType string) metav1.Condition {
		return metav1.Condition{Type: conditionType, Status: metav1.ConditionTrue}
	}
	cases := []struct {
		name       string
		conditions []metav1.Condition
		want       string
	}{
		{"no conditions", nil, ""},
		{"issued", []metav1.Condition{cond(certificatesv1.PodCertificateRequestConditionTypeIssued)}, certificatesv1.PodCertificateRequestConditionTypeIssued},
		{"denied", []metav1.Condition{cond(certificatesv1.PodCertificateRequestConditionTypeDenied)}, certificatesv1.PodCertificateRequestConditionTypeDenied},
		{"failed", []metav1.Condition{cond(certificatesv1.PodCertificateRequestConditionTypeFailed)}, certificatesv1.PodCertificateRequestConditionTypeFailed},
		{"non-terminal only", []metav1.Condition{cond("SomethingElse")}, ""},
		{"terminal after non-terminal", []metav1.Condition{cond("SomethingElse"), cond(certificatesv1.PodCertificateRequestConditionTypeDenied)}, certificatesv1.PodCertificateRequestConditionTypeDenied},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcr := &certificatesv1.PodCertificateRequest{Status: certificatesv1.PodCertificateRequestStatus{Conditions: tc.conditions}}
			if got := terminalConditionType(&pcr.Status); got != tc.want {
				t.Errorf("terminalConditionType() = %q, want %q", got, tc.want)
			}
			if got, want := isTerminal(pcr), tc.want != ""; got != want {
				t.Errorf("isTerminal() = %t, want %t", got, want)
			}
		})
	}
}
