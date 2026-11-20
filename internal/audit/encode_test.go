package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
)

// encodeLine encodes rec with b, checks that the result is one line, and
// returns the line and its decoded object.
func encodeLine(t *testing.T, b *Builder, rec Record) ([]byte, map[string]any) {
	t.Helper()
	line, err := b.Encode(rec)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if bytes.Count(line, []byte("\n")) != 1 || !bytes.HasSuffix(line, []byte("\n")) {
		t.Fatalf("Encode() = %q, want one line that ends in a newline", line)
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("unmarshal line %q: %v", line, err)
	}
	return line, m
}

func TestEncodeIsOneLine(t *testing.T) {
	const injected = "line one\nline \"two\"\u0000\n" + `{"kind":"CertificateAuditRecord"}` + "\n"
	opts := DefaultOptions()
	opts.PodLabels = []string{"evil"}
	opts.PodAnnotations = []string{"example.com/evil"}
	opts.MaxValueLength = 4096
	b := newTestBuilder(t, opts)
	pod := testPod()
	pod.Labels["evil"] = injected
	pod.Annotations["example.com/evil"] = injected

	_, got := encodeLine(t, b, b.Terminal(EventDenied, string(outcome.InvalidUserConfig), injected, testPCR(), pod, nil))

	if got["kind"] != Kind {
		t.Errorf("kind = %v, want %q", got["kind"], Kind)
	}
	wantKeys := []string{"event", "kind", "message", "reason", "request", "schemaVersion", "signerName", "ts", "workload"}
	if keys := slices.Sorted(maps.Keys(got)); !slices.Equal(keys, wantKeys) {
		t.Errorf("top-level keys = %v, want %v", keys, wantKeys)
	}
	if got["message"] != injected {
		t.Errorf("message = %q, want %q", got["message"], injected)
	}
	workload := group(t, got, "workload")
	if v := group(t, workload, "labels")["evil"]; v != injected {
		t.Errorf("workload.labels.evil = %q, want %q", v, injected)
	}
	if v := group(t, workload, "annotations")["example.com/evil"]; v != injected {
		t.Errorf("workload.annotations[example.com/evil] = %q, want %q", v, injected)
	}
}

func TestEncodeTruncatesValuesAtRuneBoundary(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "cut inside a rune", value: "ééé", want: "éé...[truncated]"},
		{name: "cut at a rune boundary", value: "abcdef", want: "abcde...[truncated]"},
		{name: "at the limit", value: "abcde", want: "abcde"},
		{name: "invalid UTF-8", value: "\xff\xff\xff\xff\xff\xff", want: strings.Repeat("�", 5) + "...[truncated]"},
	}
	opts := DefaultOptions()
	opts.PodLabels = []string{"value"}
	opts.PodAnnotations = []string{"example.com/value"}
	opts.MaxValueLength = 5
	opts.RecordSuppliedValues = true
	b := newTestBuilder(t, opts)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod()
			pod.Labels["value"] = tt.value
			pod.Annotations["example.com/value"] = tt.value
			supplied := map[string]string{"example.com/pod-signer-san": tt.value}
			rec := b.Terminal(EventDenied, string(outcome.InvalidUserConfig), tt.value, testPCR(), pod, supplied)

			_, got := encodeLine(t, b, rec)

			workload := group(t, got, "workload")
			request := group(t, got, "request")
			values := map[string]any{
				"message":                got["message"],
				"workload.labels":        group(t, workload, "labels")["value"],
				"workload.annotations":   group(t, workload, "annotations")["example.com/value"],
				"request.suppliedValues": group(t, request, "suppliedValues")["example.com/pod-signer-san"],
			}
			for field, v := range values {
				if v != tt.want {
					t.Errorf("%s = %q, want %q", field, v, tt.want)
				}
			}
			if rec.Message != tt.value || rec.Workload.Labels["value"] != tt.value ||
				rec.Workload.Annotations["example.com/value"] != tt.value ||
				rec.Request.SuppliedValues["example.com/pod-signer-san"] != tt.value {
				t.Errorf("Encode changed the record it was given: %+v", rec)
			}
		})
	}
}

// budgetOptions copies every label and every example.com/ annotation, records
// supplied values, and uses the smallest record budget.
func budgetOptions() Options {
	opts := DefaultOptions()
	opts.PodLabels = []string{"*"}
	opts.PodAnnotations = []string{"example.com/*"}
	opts.MaxValueLength = 1024
	opts.MaxRecordBytes = 4096
	opts.RecordSuppliedValues = true
	return opts
}

// kilobyteValues returns n keys named prefix0, prefix1, ... with 1024-byte
// values.
func kilobyteValues(prefix string, n int) map[string]string {
	m := make(map[string]string, n)
	for i := range n {
		m[fmt.Sprintf("%s%d", prefix, i)] = strings.Repeat("x", 1024)
	}
	return m
}

func TestEncodeByteBudgetOrder(t *testing.T) {
	tests := []struct {
		name                                    string
		annotations, labels, supplied           int
		wantAnnotations, wantLabels, wantValues bool
	}{
		{name: "under the budget", annotations: 1, wantAnnotations: true, wantLabels: true, wantValues: true},
		{name: "annotations removed", annotations: 3, labels: 1, supplied: 1, wantLabels: true, wantValues: true},
		{name: "annotations and labels removed", annotations: 1, labels: 2, supplied: 1, wantValues: true},
		{name: "all three removed", annotations: 1, labels: 1, supplied: 3},
	}
	cert := newTestCertificate(t, testSerial)
	b := newTestBuilder(t, budgetOptions())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := testPod()
			pod.Labels = kilobyteValues("label", tt.labels)
			pod.Annotations = kilobyteValues("example.com/annotation", tt.annotations)
			supplied := kilobyteValues("example.com/pod-signer-", tt.supplied)
			rec := b.Signed(testPCR(), pod, cert, supplied)

			line, got := encodeLine(t, b, rec)

			if len(line) > 4096 {
				t.Errorf("line is %d bytes, want at most 4096", len(line))
			}
			workload := group(t, got, "workload")
			request := group(t, got, "request")
			present := func(m map[string]any, key string, want bool) {
				t.Helper()
				if _, ok := m[key]; ok != want {
					t.Errorf("%s present = %t, want %t", key, ok, want)
				}
			}
			present(workload, "annotations", tt.wantAnnotations)
			present(workload, "labels", tt.wantLabels)
			present(request, "suppliedValues", tt.wantValues)
			wantOmitted := map[string]any{"labels": 0.0, "annotations": 0.0}
			if !tt.wantAnnotations {
				wantOmitted["annotations"] = float64(tt.annotations)
			}
			if !tt.wantLabels {
				wantOmitted["labels"] = float64(tt.labels)
			}
			if !tt.wantValues {
				wantOmitted["suppliedValues"] = float64(tt.supplied)
			}
			if omitted := group(t, workload, "omitted"); !reflect.DeepEqual(omitted, wantOmitted) {
				t.Errorf("workload.omitted = %v, want %v", omitted, wantOmitted)
			}
			if keys := request["suppliedKeys"].([]any); len(keys) != tt.supplied {
				t.Errorf("request.suppliedKeys has %d keys, want %d", len(keys), tt.supplied)
			}
			assertIdentity(t, got, rec)
			if len(rec.Workload.Annotations) != tt.annotations || rec.Workload.Omitted != (Omitted{}) {
				t.Errorf("Encode changed the workload of the record it was given: %+v", rec.Workload)
			}
		})
	}
}

func TestEncodeByteBudgetAddsToOmittedCounts(t *testing.T) {
	opts := budgetOptions()
	opts.MaxCopiedKeys = 2
	b := newTestBuilder(t, opts)
	pod := testPod()
	pod.Labels = kilobyteValues("label", 3)
	pod.Annotations = kilobyteValues("example.com/annotation", 3)
	rec := b.Signed(testPCR(), pod, newTestCertificate(t, testSerial), kilobyteValues("example.com/pod-signer-", 1))
	if rec.Workload.Omitted != (Omitted{Labels: 1, Annotations: 1}) {
		t.Fatalf("workload.omitted before Encode = %+v, want 1 label and 1 annotation from MaxCopiedKeys", rec.Workload.Omitted)
	}

	line, got := encodeLine(t, b, rec)

	if len(line) > 4096 {
		t.Errorf("line is %d bytes, want at most 4096", len(line))
	}
	workload := group(t, got, "workload")
	wantOmitted := map[string]any{"labels": 3.0, "annotations": 3.0}
	if omitted := group(t, workload, "omitted"); !reflect.DeepEqual(omitted, wantOmitted) {
		t.Errorf("workload.omitted = %v, want %v", omitted, wantOmitted)
	}
	if _, ok := group(t, got, "request")["suppliedValues"]; !ok {
		t.Error("request.suppliedValues is absent, want it kept")
	}
}

// assertIdentity checks that the reserved identity fields of rec are in the
// decoded line got.
func assertIdentity(t *testing.T, got map[string]any, rec Record) {
	t.Helper()
	checks := []struct {
		field string
		got   any
		want  string
	}{
		{"request.uid", group(t, got, "request")["uid"], rec.Request.UID},
		{"workload.pod.uid", group(t, group(t, got, "workload"), "pod")["uid"], rec.Workload.Pod.UID},
		{"certificate.fingerprint", group(t, got, "certificate")["fingerprint"], rec.Certificate.Fingerprint},
		{"issuer.fingerprint", group(t, got, "issuer")["fingerprint"], rec.Issuer.Fingerprint},
	}
	for _, c := range checks {
		if c.got != c.want || c.want == "" {
			t.Errorf("%s = %v, want %q", c.field, c.got, c.want)
		}
	}
}

func TestEncodeOverBudgetKeepsIdentity(t *testing.T) {
	cert := newTestCertificate(t, testSerial)
	b := newTestBuilder(t, budgetOptions())
	pod := testPod()
	pod.Labels = kilobyteValues("label", 1)
	pod.Annotations = kilobyteValues("example.com/annotation", 1)
	rec := b.Signed(testPCR(), pod, cert, kilobyteValues("example.com/pod-signer-", 1))
	dnsNames := make([]string, 200)
	for i := range dnsNames {
		dnsNames[i] = fmt.Sprintf("service-%03d.payments.svc.cluster.local", i)
	}
	rec.Certificate.DNSNames = dnsNames

	line, got := encodeLine(t, b, rec)

	if len(line) <= 4096 {
		t.Fatalf("line is %d bytes, want more than 4096 for this test", len(line))
	}
	if names := group(t, got, "certificate")["dnsNames"].([]any); len(names) != len(dnsNames) {
		t.Errorf("certificate.dnsNames has %d names, want %d", len(names), len(dnsNames))
	}
	workload := group(t, got, "workload")
	wantOmitted := map[string]any{"labels": 1.0, "annotations": 1.0, "suppliedValues": 1.0, "overBudget": true}
	if omitted := group(t, workload, "omitted"); !reflect.DeepEqual(omitted, wantOmitted) {
		t.Errorf("workload.omitted = %v, want %v", omitted, wantOmitted)
	}
	assertIdentity(t, got, rec)
}

func TestEncodeFollowUpRecord(t *testing.T) {
	b := newTestBuilder(t, budgetOptions())
	signed := b.Signed(testPCR(), testPod(), newTestCertificate(t, testSerial), nil)
	rec := b.FollowUp(EventPublished, ReasonStatusWritten, signed)

	_, got := encodeLine(t, b, rec)

	if _, ok := got["workload"]; ok {
		t.Errorf("workload = %v, want absent", got["workload"])
	}
	if fp := group(t, got, "certificate")["fingerprint"]; fp != signed.Certificate.Fingerprint {
		t.Errorf("certificate.fingerprint = %v, want %q", fp, signed.Certificate.Fingerprint)
	}
}
