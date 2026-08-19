package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeCA is a settable CAState, so a test can change the CA underneath a
// registered collector without any reload machinery.
type fakeCA struct {
	failures    int
	lastSuccess time.Time
	notAfter    time.Time
	bundleSize  int
}

func (f *fakeCA) ReloadHealth() (int, time.Time) { return f.failures, f.lastSuccess }
func (f *fakeCA) CertificateNotAfter() time.Time { return f.notAfter }
func (f *fakeCA) TrustBundleSize() int           { return f.bundleSize }

func TestCACollectorReportsCurrentState(t *testing.T) {
	ca := &fakeCA{
		failures:    2,
		lastSuccess: time.Unix(1700000000, 0),
		notAfter:    time.Unix(1800000000, 0),
		bundleSize:  3,
	}
	collector := NewCACollector(ca)

	// One golden comparison pins the exposition shape - name, type and help -
	// for the whole collector; the rest assert the values.
	want := `
# HELP podcertificatesigner_ca_reload_consecutive_failures Consecutive failed CA reload attempts. Readiness fails once this reaches 3 and has been there for ten minutes, so alerting at 3 gives roughly five minutes before the replica leaves the Service.
# TYPE podcertificatesigner_ca_reload_consecutive_failures gauge
podcertificatesigner_ca_reload_consecutive_failures 2
`
	if err := testutil.CollectAndCompare(collector, strings.NewReader(want),
		"podcertificatesigner_ca_reload_consecutive_failures"); err != nil {
		t.Error(err)
	}

	assertGauges(t, collector, map[string]float64{
		"podcertificatesigner_ca_reload_last_success_timestamp_seconds": 1700000000,
		"podcertificatesigner_ca_expiration_timestamp_seconds":          1800000000,
		"podcertificatesigner_trust_bundle_certificates":                3,
	})
}

// The collector must read live state on every scrape, not a value cached when a
// reload happened. This is the whole reason it is a Collector: a gauge written
// by the reload loop goes stale exactly when the loop stops, which is the
// failure the last-success timestamp exists to catch.
func TestCACollectorReadsLiveStateOnEveryScrape(t *testing.T) {
	ca := &fakeCA{notAfter: time.Unix(1700000000, 0), bundleSize: 1}
	collector := NewCACollector(ca)

	assertGauges(t, collector, map[string]float64{
		"podcertificatesigner_ca_expiration_timestamp_seconds": 1700000000,
		"podcertificatesigner_trust_bundle_certificates":       1,
	})

	ca.notAfter = time.Unix(1900000000, 0)
	ca.bundleSize = 3
	ca.failures = 5

	assertGauges(t, collector, map[string]float64{
		"podcertificatesigner_ca_expiration_timestamp_seconds": 1900000000,
		"podcertificatesigner_trust_bundle_certificates":       3,
		"podcertificatesigner_ca_reload_consecutive_failures":  5,
	})
}

// A CA that has never been read successfully must report the epoch rather than
// a zero time.Time's negative Unix second, so "never" reads as stale rather
// than as a parsing accident.
func TestCACollectorReportsNeverAsEpoch(t *testing.T) {
	collector := NewCACollector(&fakeCA{notAfter: time.Unix(1700000000, 0), bundleSize: 1})

	assertGauges(t, collector, map[string]float64{
		"podcertificatesigner_ca_reload_last_success_timestamp_seconds": 0,
	})
}

// assertGauges scrapes collector once and checks the named gauges.
func assertGauges(t *testing.T, collector prometheus.Collector, want map[string]float64) {
	t.Helper()

	reg := prometheus.NewPedanticRegistry()
	if err := reg.Register(collector); err != nil {
		t.Fatalf("register: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	got := make(map[string]float64, len(families))
	for _, mf := range families {
		for _, m := range mf.GetMetric() {
			got[mf.GetName()] = m.GetGauge().GetValue()
		}
	}
	for name, wantValue := range want {
		gotValue, ok := got[name]
		if !ok {
			t.Errorf("%s was not collected", name)
			continue
		}
		if gotValue != wantValue {
			t.Errorf("%s = %v, want %v", name, gotValue, wantValue)
		}
	}
}
