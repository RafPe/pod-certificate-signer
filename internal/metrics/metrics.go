// Package metrics defines the custom Prometheus collectors for the
// pod-certificate-signer controller. They are registered with the
// controller-runtime metrics registry, which already serves /metrics.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// OutcomesTotal counts terminal reconcile outcomes by reason.
	OutcomesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pcs_outcomes_total",
		Help: "Total PodCertificateRequest reconcile outcomes, labeled by reason.",
	}, []string{"reason"})

	// CAExpirySeconds is the number of seconds until the active CA expires.
	CAExpirySeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "pcs_ca_expiry_seconds",
		Help: "Seconds until the active signing CA certificate expires.",
	})
)

func init() {
	ctrlmetrics.Registry.MustRegister(OutcomesTotal, CAExpirySeconds)
}
