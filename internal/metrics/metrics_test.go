package metrics

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// wantSeries is the entire custom metric surface: every series this signer may
// expose, pinned by metric name and label pair.
//
// It is a literal, not something derived from the declarations, which is the
// whole point. ADR-0005 (docs/adr/0005-bounded-metrics-surface.md) decides the
// surface; a metric or a label value added without amending that record fails
// TestRegisteredSurfaceMatchesADR0005 rather than shipping.
var wantSeries = []string{
	`podcertificatesigner_podcertificaterequests_total{outcome="issued",reason="CertificateIssued"}`,
	`podcertificatesigner_podcertificaterequests_total{outcome="denied",reason="UnsupportedKeyType"}`,
	`podcertificatesigner_podcertificaterequests_total{outcome="denied",reason="InvalidUnverifiedUserAnnotations"}`,
	`podcertificatesigner_podcertificaterequests_total{outcome="failed",reason="SigningFailed"}`,
	`podcertificatesigner_podcertificaterequest_requeues_total{reason="CASignerUnusable"}`,
	`podcertificatesigner_podcertificaterequest_requeues_total{reason="Transient"}`,
	`podcertificatesigner_podcertificaterequest_drops_total{reason="AssociatedPodGone"}`,
	`podcertificatesigner_clustertrustbundle_publish_attempts_total{result="created"}`,
	`podcertificatesigner_clustertrustbundle_publish_attempts_total{result="failed"}`,
	`podcertificatesigner_clustertrustbundle_publish_attempts_total{result="unchanged"}`,
	`podcertificatesigner_clustertrustbundle_publish_attempts_total{result="updated"}`,
}

func TestRegisteredSurfaceMatchesADR0005(t *testing.T) {
	got := gatherSeries(t, register(t))

	if diff := diffSeries(wantSeries, got); diff != "" {
		t.Errorf("registered metric surface does not match the one ADR-0005 decides on:\n%s\n"+
			"Adding to or removing from the surface is an amendment to docs/adr/0005-bounded-metrics-surface.md, "+
			"not an edit to this list.", diff)
	}
}

// TestPreInitialisedSeriesStartAtZero pins the "avoid missing metrics" rule: a
// series an alert may reference must exist before the thing it counts has ever
// happened, or rate() over it is unreliable for the first window.
func TestPreInitialisedSeriesStartAtZero(t *testing.T) {
	reg := register(t)

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			if got := m.GetCounter().GetValue(); got != 0 {
				t.Errorf("%s starts at %v, want 0", seriesID(mf.GetName(), m.GetLabel()), got)
			}
		}
	}
}

// TestSurfaceIsLintClean runs the Prometheus naming linter over the surface,
// which catches a missing _total, a non-base unit and an _info misuse. A metric
// name is effectively permanent once published, so the check belongs at build
// time rather than at review time.
func TestSurfaceIsLintClean(t *testing.T) {
	for _, c := range collectors() {
		problems, err := testutil.CollectAndLint(c)
		if err != nil {
			t.Fatalf("lint: %v", err)
		}
		for _, p := range problems {
			t.Errorf("%s: %s", p.Metric, p.Text)
		}
	}
}

// TestRegisterRejectsDuplicates proves Register surfaces a duplicate rather
// than panicking, so the caller decides how to fail.
func TestRegisterRejectsDuplicates(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	if err := Register(reg); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := Register(reg); err == nil {
		t.Error("second Register into the same registry returned nil, want a duplicate-registration error")
	}
}

// register registers the surface into a throwaway pedantic registry, which -
// unlike the default one - rejects inconsistent help strings and label sets.
func register(t *testing.T) *prometheus.Registry {
	t.Helper()

	reg := prometheus.NewPedanticRegistry()
	if err := Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	return reg
}

// gatherSeries returns every series in reg, rendered as name{label="value",...}
// and sorted, so a surface can be compared as a set of strings.
func gatherSeries(t *testing.T, reg prometheus.Gatherer) []string {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	var series []string
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			series = append(series, seriesID(mf.GetName(), m.GetLabel()))
		}
	}
	sort.Strings(series)

	return series
}

// seriesID renders one series as name{label="value",...} with labels sorted, so
// the identity does not depend on the order the collector emitted them in.
func seriesID[L interface {
	GetName() string
	GetValue() string
}](name string, labels []L) string {
	if len(labels) == 0 {
		return name
	}

	pairs := make([]string, 0, len(labels))
	for _, l := range labels {
		pairs = append(pairs, fmt.Sprintf("%s=%q", l.GetName(), l.GetValue()))
	}
	sort.Strings(pairs)

	return name + "{" + strings.Join(pairs, ",") + "}"
}

// diffSeries reports the series present in one set and not the other, or "" if
// they match.
func diffSeries(want, got []string) string {
	inGot := make(map[string]bool, len(got))
	for _, s := range got {
		inGot[s] = true
	}
	inWant := make(map[string]bool, len(want))
	for _, s := range want {
		inWant[s] = true
	}

	var b strings.Builder
	for _, s := range want {
		if !inGot[s] {
			fmt.Fprintf(&b, "  missing: %s\n", s)
		}
	}
	for _, s := range got {
		if !inWant[s] {
			fmt.Fprintf(&b, "  unexpected: %s\n", s)
		}
	}

	return b.String()
}
