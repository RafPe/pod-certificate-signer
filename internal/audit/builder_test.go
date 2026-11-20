package audit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"testing"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

const testSignerName = "example.com/pod-signer"

// testSerial is a fixed leaf serial, so the golden record can spell out both
// serial forms.
var testSerial, _ = new(big.Int).SetString("3fa91c0e77b2d4a8056e1f9c2b7d6a40", 16)

var tsPattern = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$`)

func testPCR() *certificatesv1.PodCertificateRequest {
	return &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: "payments", Name: "pcr-7xk2q", UID: "pcr-uid"},
		Spec: certificatesv1.PodCertificateRequestSpec{
			SignerName:         testSignerName,
			PodName:            "api-6c9f7d5b8-x2lqp",
			PodUID:             "pod-uid",
			ServiceAccountName: "api",
			ServiceAccountUID:  "sa-uid",
			NodeName:           "ip-10-0-3-17",
			NodeUID:            "node-uid",
		},
	}
}

func testPod(ownerRefs ...metav1.OwnerReference) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "payments",
			Name:      "api-6c9f7d5b8-x2lqp",
			UID:       "pod-uid",
			Labels: map[string]string{
				"app.kubernetes.io/name":    "api",
				"app.kubernetes.io/version": "1.2.3",
				"pod-template-hash":         "6c9f7d5b8",
			},
			Annotations: map[string]string{
				"example.com/owner": "team-payments",
				"example.com/other": "not copied",
			},
			OwnerReferences: ownerRefs,
		},
	}
}

func replicaSetOwner() metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion: "apps/v1",
		Kind:       "ReplicaSet",
		Name:       "api-6c9f7d5b8",
		UID:        "rs-uid",
		Controller: new(true),
	}
}

func testOptions() Options {
	o := DefaultOptions()
	o.PodLabels = []string{"app.kubernetes.io/*"}
	o.PodAnnotations = []string{"example.com/owner"}
	return o
}

func newTestBuilder(t *testing.T, opts Options) *Builder {
	t.Helper()
	b, err := NewBuilder(testSignerName, opts)
	if err != nil {
		t.Fatalf("NewBuilder: %v", err)
	}
	return b
}

// newTestCertificate signs a leaf with serial under a fresh test CA, the way
// the authority does, and returns it as an issued certificate.
func newTestCertificate(t *testing.T, serial *big.Int) *podcertificate.Certificate {
	t.Helper()
	ca, err := testutil.NewCA("pod-signer-ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	notBefore := time.Date(2026, 11, 20, 9, 14, 2, 0, time.UTC)
	notAfter := notBefore.Add(24 * time.Hour)
	uri, err := url.Parse("spiffe://cluster.local/ns/payments/sa/api")
	if err != nil {
		t.Fatalf("parse URI: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "api.payments.svc"},
		DNSNames:     []string{"api.payments.svc", "api"},
		IPAddresses:  []net.IP{net.ParseIP("10.0.3.17")},
		URIs:         []*url.URL{uri},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return &podcertificate.Certificate{
		Leaf:   leaf,
		Issuer: ca.Cert,
		Config: &podcertificate.Config{
			Sources: podcertificate.FieldSources{
				CommonName:    podcertificate.SourceDefault,
				DNSNames:      podcertificate.SourcePCR,
				IPAddresses:   podcertificate.SourceCSR,
				URIs:          podcertificate.SourceCSR,
				ExtKeyUsage:   podcertificate.SourcePod,
				Duration:      podcertificate.SourceDefault,
				RefreshBefore: podcertificate.SourceDefault,
			},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}
}

// recordMap returns rec as it decodes from its JSON encoding, after it checks
// that ts is an RFC 3339 UTC time with milliseconds and removes it.
func recordMap(t *testing.T, rec Record) map[string]any {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	ts, ok := m["ts"].(string)
	if !ok || !tsPattern.MatchString(ts) {
		t.Fatalf("ts = %v, want RFC 3339 UTC with milliseconds", m["ts"])
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Fatalf("ts %q does not parse as RFC 3339: %v", ts, err)
	}
	delete(m, "ts")
	return m
}

func decodeGolden(t *testing.T, golden string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(golden), &m); err != nil {
		t.Fatalf("unmarshal golden record: %v", err)
	}
	return m
}

func assertJSONEqual(t *testing.T, got, want map[string]any) {
	t.Helper()
	if reflect.DeepEqual(got, want) {
		return
	}
	gotJSON, _ := json.MarshalIndent(got, "", "  ")
	wantJSON, _ := json.MarshalIndent(want, "", "  ")
	t.Errorf("record mismatch\ngot:\n%s\nwant:\n%s", gotJSON, wantJSON)
}

func group(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	g, ok := m[key].(map[string]any)
	if !ok {
		t.Fatalf("record has no %q object: %v", key, m)
	}
	return g
}

func TestSignedRecordShape(t *testing.T) {
	cert := newTestCertificate(t, testSerial)
	b := newTestBuilder(t, testOptions())
	supplied := map[string]string{
		"example.com/pod-signer-san": "api.payments.svc",
		"example.com/pod-signer-eku": "server",
	}

	rec := b.Signed(testPCR(), testPod(replicaSetOwner()), cert, supplied)
	got := recordMap(t, rec)

	want := decodeGolden(t, fmt.Sprintf(`{
		"kind": "CertificateAuditRecord",
		"schemaVersion": "v1",
		"event": "signed",
		"reason": "CertificateIssued",
		"signerName": "example.com/pod-signer",
		"request": {
			"namespace": "payments", "name": "pcr-7xk2q", "uid": "pcr-uid",
			"suppliedKeys": ["example.com/pod-signer-eku", "example.com/pod-signer-san"]
		},
		"workload": {
			"pod": {"name": "api-6c9f7d5b8-x2lqp", "uid": "pod-uid"},
			"serviceAccount": {"name": "api", "uid": "sa-uid"},
			"node": {"name": "ip-10-0-3-17", "uid": "node-uid"},
			"owner": {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-6c9f7d5b8", "uid": "rs-uid"},
			"labels": {"app.kubernetes.io/name": "api", "app.kubernetes.io/version": "1.2.3"},
			"annotations": {"example.com/owner": "team-payments"},
			"omitted": {"labels": 0, "annotations": 0}
		},
		"certificate": {
			"serialHex": "3fa91c0e77b2d4a8056e1f9c2b7d6a40",
			"serialDecimal": "84619430957250172514404220402520648256",
			"fingerprint": %q,
			"commonName": "api.payments.svc",
			"dnsNames": ["api.payments.svc", "api"],
			"ipAddresses": ["10.0.3.17"],
			"uris": ["spiffe://cluster.local/ns/payments/sa/api"],
			"extKeyUsage": ["serverAuth", "clientAuth"],
			"keyAlgorithm": "ECDSA",
			"notBefore": "2026-11-20T09:14:02Z",
			"notAfter": "2026-11-21T09:14:02Z",
			"sources": {
				"commonName": "default", "dnsNames": "pcr", "ipAddresses": "csr", "uris": "csr",
				"extKeyUsage": "pod", "duration": "default", "refreshBefore": "default"
			}
		},
		"issuer": {"subject": "CN=pod-signer-ca", "serialHex": %q, "fingerprint": %q}
	}`, Fingerprint(cert.Leaf), cert.Issuer.SerialNumber.Text(16), Fingerprint(cert.Issuer)))
	assertJSONEqual(t, got, want)

	certificate := group(t, got, "certificate")
	if certificate["serialDecimal"] != cert.Leaf.SerialNumber.String() {
		t.Errorf("serialDecimal = %v, want %s", certificate["serialDecimal"], cert.Leaf.SerialNumber)
	}
	if !regexp.MustCompile(`^[1-9a-f][0-9a-f]*$`).MatchString(rec.Certificate.SerialHex) {
		t.Errorf("serialHex = %q, want lowercase hex with no leading zeros", rec.Certificate.SerialHex)
	}
	if rec.Certificate.Fingerprint != Fingerprint(cert.Leaf) {
		t.Errorf("fingerprint = %q, want %q", rec.Certificate.Fingerprint, Fingerprint(cert.Leaf))
	}
	if rec.Issuer.Fingerprint != Fingerprint(cert.Issuer) {
		t.Errorf("issuer fingerprint = %q, want %q", rec.Issuer.Fingerprint, Fingerprint(cert.Issuer))
	}
	src := cert.Config.Sources
	wantSources := Sources{
		CommonName: src.CommonName, DNSNames: src.DNSNames, IPAddresses: src.IPAddresses, URIs: src.URIs,
		ExtKeyUsage: src.ExtKeyUsage, Duration: src.Duration, RefreshBefore: src.RefreshBefore,
	}
	if rec.Certificate.Sources != wantSources {
		t.Errorf("sources = %+v, want %+v", rec.Certificate.Sources, wantSources)
	}
}

func TestSignedRecordEmptyFieldsArePresent(t *testing.T) {
	cert := newTestCertificate(t, testSerial)
	cert.Leaf.Subject.CommonName = ""
	cert.Leaf.IPAddresses = nil
	cert.Leaf.URIs = nil
	b := newTestBuilder(t, DefaultOptions())

	got := recordMap(t, b.Signed(testPCR(), testPod(), cert, nil))

	certificate := group(t, got, "certificate")
	if v, ok := certificate["commonName"]; !ok || v != "" {
		t.Errorf("certificate.commonName = %#v (present %t), want \"\"", v, ok)
	}
	for _, key := range []string{"ipAddresses", "uris"} {
		if v, ok := certificate[key].([]any); !ok || len(v) != 0 {
			t.Errorf("certificate.%s = %#v, want []", key, certificate[key])
		}
	}
	workload := group(t, got, "workload")
	for _, key := range []string{"labels", "annotations"} {
		if v, ok := workload[key].(map[string]any); !ok || len(v) != 0 {
			t.Errorf("workload.%s = %#v, want {}", key, workload[key])
		}
	}
	if v, ok := group(t, got, "request")["suppliedKeys"].([]any); !ok || len(v) != 0 {
		t.Errorf("request.suppliedKeys = %#v, want []", group(t, got, "request")["suppliedKeys"])
	}
}

func TestSignedRecordSerialWithHighZeroByte(t *testing.T) {
	cert := newTestCertificate(t, big.NewInt(0x00ab))
	b := newTestBuilder(t, DefaultOptions())

	rec := b.Signed(testPCR(), testPod(), cert, nil)

	if rec.Certificate.SerialHex != "ab" {
		t.Errorf("serialHex = %q, want %q", rec.Certificate.SerialHex, "ab")
	}
	if rec.Certificate.SerialDecimal != "171" {
		t.Errorf("serialDecimal = %q, want %q", rec.Certificate.SerialDecimal, "171")
	}
}

func TestFingerprint(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("abc")}
	const want = "X509SHA256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := Fingerprint(cert); got != want {
		t.Errorf("Fingerprint() = %q, want %q", got, want)
	}
}

func TestOwner(t *testing.T) {
	notController := func(name string) metav1.OwnerReference {
		ref := replicaSetOwner()
		ref.Name = name
		ref.Controller = nil
		return ref
	}
	tests := []struct {
		name      string
		ownerRefs []metav1.OwnerReference
		want      map[string]any
	}{
		{
			name:      "one controller ownerReference",
			ownerRefs: []metav1.OwnerReference{replicaSetOwner()},
			want: map[string]any{
				"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-6c9f7d5b8", "uid": "rs-uid",
			},
		},
		{name: "no ownerReferences"},
		{
			name:      "two ownerReferences without a controller",
			ownerRefs: []metav1.OwnerReference{notController("a"), notController("b")},
		},
	}
	cert := newTestCertificate(t, testSerial)
	b := newTestBuilder(t, DefaultOptions())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workload := group(t, recordMap(t, b.Signed(testPCR(), testPod(tt.ownerRefs...), cert, nil)), "workload")
			owner, ok := workload["owner"]
			if tt.want == nil {
				if ok {
					t.Fatalf("workload.owner = %v, want no owner key", owner)
				}
				return
			}
			if !reflect.DeepEqual(owner, tt.want) {
				t.Errorf("workload.owner = %v, want %v", owner, tt.want)
			}
		})
	}
}

func TestSuppliedKeysOnlyByDefault(t *testing.T) {
	cert := newTestCertificate(t, testSerial)
	supplied := map[string]string{"example.com/pod-signer-san": "a", "example.com/pod-signer-cn": "b"}
	wantKeys := []any{"example.com/pod-signer-cn", "example.com/pod-signer-san"}

	request := group(t, recordMap(t, newTestBuilder(t, DefaultOptions()).Signed(testPCR(), testPod(), cert, supplied)), "request")
	if !reflect.DeepEqual(request["suppliedKeys"], wantKeys) {
		t.Errorf("suppliedKeys = %v, want %v", request["suppliedKeys"], wantKeys)
	}
	if v, ok := request["suppliedValues"]; ok {
		t.Errorf("suppliedValues = %v, want absent", v)
	}

	opts := DefaultOptions()
	opts.RecordSuppliedValues = true
	b := newTestBuilder(t, opts)
	rec := b.Signed(testPCR(), testPod(), cert, supplied)
	supplied["example.com/pod-signer-san"] = "changed after the build"
	request = group(t, recordMap(t, rec), "request")
	if !reflect.DeepEqual(request["suppliedKeys"], wantKeys) {
		t.Errorf("suppliedKeys = %v, want %v", request["suppliedKeys"], wantKeys)
	}
	wantValues := map[string]any{"example.com/pod-signer-san": "a", "example.com/pod-signer-cn": "b"}
	if !reflect.DeepEqual(request["suppliedValues"], wantValues) {
		t.Errorf("suppliedValues = %v, want %v", request["suppliedValues"], wantValues)
	}
}

func TestFollowUpRecord(t *testing.T) {
	cert := newTestCertificate(t, testSerial)
	b := newTestBuilder(t, testOptions())
	signed := b.Signed(testPCR(), testPod(replicaSetOwner()), cert, map[string]string{"example.com/pod-signer-san": "a"})

	got := recordMap(t, b.FollowUp(EventSuperseded, ReasonOtherWriterWon, signed))

	want := decodeGolden(t, fmt.Sprintf(`{
		"kind": "CertificateAuditRecord",
		"schemaVersion": "v1",
		"event": "superseded",
		"reason": "OtherWriterWon",
		"signerName": "example.com/pod-signer",
		"request": {"namespace": "payments", "name": "pcr-7xk2q", "uid": "pcr-uid"},
		"certificate": {
			"serialHex": "3fa91c0e77b2d4a8056e1f9c2b7d6a40",
			"serialDecimal": "84619430957250172514404220402520648256",
			"fingerprint": %q
		}
	}`, Fingerprint(cert.Leaf)))
	assertJSONEqual(t, got, want)
}

func TestTerminalRecord(t *testing.T) {
	tests := []struct {
		name         string
		pod          *corev1.Pod
		wantWorkload string
	}{
		{
			name: "with the live pod",
			pod:  testPod(replicaSetOwner()),
			wantWorkload: `{
				"pod": {"name": "api-6c9f7d5b8-x2lqp", "uid": "pod-uid"},
				"serviceAccount": {"name": "api", "uid": "sa-uid"},
				"node": {"name": "ip-10-0-3-17", "uid": "node-uid"},
				"owner": {"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-6c9f7d5b8", "uid": "rs-uid"},
				"labels": {"app.kubernetes.io/name": "api", "app.kubernetes.io/version": "1.2.3"},
				"annotations": {"example.com/owner": "team-payments"},
				"omitted": {"labels": 0, "annotations": 0}
			}`,
		},
		{
			name: "without a pod",
			wantWorkload: `{
				"pod": {"name": "api-6c9f7d5b8-x2lqp", "uid": "pod-uid"},
				"serviceAccount": {"name": "api", "uid": "sa-uid"},
				"node": {"name": "ip-10-0-3-17", "uid": "node-uid"},
				"labels": {},
				"annotations": {},
				"omitted": {"labels": 0, "annotations": 0}
			}`,
		},
	}
	b := newTestBuilder(t, testOptions())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := b.Terminal(EventDenied, string(outcome.InvalidUserConfig), "the eku annotation is invalid",
				testPCR(), tt.pod, map[string]string{"example.com/pod-signer-eku": "bogus"})

			got := recordMap(t, rec)
			want := decodeGolden(t, `{
				"kind": "CertificateAuditRecord",
				"schemaVersion": "v1",
				"event": "denied",
				"reason": "InvalidUnverifiedUserAnnotations",
				"message": "the eku annotation is invalid",
				"signerName": "example.com/pod-signer",
				"request": {
					"namespace": "payments", "name": "pcr-7xk2q", "uid": "pcr-uid",
					"suppliedKeys": ["example.com/pod-signer-eku"]
				}
			}`)
			want["workload"] = decodeGolden(t, tt.wantWorkload)
			assertJSONEqual(t, got, want)
		})
	}
}
