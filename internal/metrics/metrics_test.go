package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestOutcomesTotalIncrements(t *testing.T) {
	OutcomesTotal.Reset()
	OutcomesTotal.WithLabelValues("CertificateIssued").Inc()
	OutcomesTotal.WithLabelValues("CertificateIssued").Inc()
	if got := testutil.ToFloat64(OutcomesTotal.WithLabelValues("CertificateIssued")); got != 2 {
		t.Fatalf("OutcomesTotal = %v, want 2", got)
	}
}

func TestCAExpirySecondsSettable(t *testing.T) {
	CAExpirySeconds.Set(123)
	if got := testutil.ToFloat64(CAExpirySeconds); got != 123 {
		t.Fatalf("CAExpirySeconds = %v, want 123", got)
	}
}
