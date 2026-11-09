/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
)

// These tests drive the probe against synthesized material that mirrors what
// kubelet projects: a PKCS#8 private key followed by the leaf and its issuer,
// and a trust bundle holding the issuing CA.
//
// They exist so the probe's logic - particularly the TLS role boundaries and
// the classification of *why* a handshake failed - is debugged here, in
// milliseconds, rather than through three-minute pod timeouts in the e2e suite.
// When the in-cluster probe later goes red with these green, the fault is in
// the cluster or the signer, not in the probe.

const (
	testAllowedDNS    = "workload.default.pod.cluster.local"
	testUnrelatedDNS  = "unrelated.example.org"
	testCALifetime    = time.Hour
	testLeafLifetime  = 30 * time.Minute
	testChainCertsLen = 2
)

// issueLeaf signs an Ed25519 leaf with the given CA, mirroring what the signer
// issues by default.
func issueLeaf(t *testing.T, ca *testutil.KeyPair, ekus []x509.ExtKeyUsage, dnsNames []string) (ed25519.PrivateKey, *x509.Certificate) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(testLeafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, pub, ca.Key)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return priv, leaf
}

// writeBundle writes a credential bundle in kubelet's layout: the PKCS#8
// private key first, then the certificate chain.
func writeBundle(t *testing.T, dir string, key ed25519.PrivateKey, chain ...*x509.Certificate) string {
	t.Helper()

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	var buf bytes.Buffer
	buf.Write(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	for _, cert := range chain {
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}

	path := filepath.Join(dir, "credentialbundle.pem")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

// readBundle reads a bundle a test is about to corrupt.
func readBundle(t *testing.T, path string) []byte {
	t.Helper()

	//nolint:gosec // G304/G703: the path came from writeBundle a few lines above.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	return data
}

// writeRawBundle writes bundle bytes verbatim into a fresh directory, for the
// tests that hand the probe something malformed on purpose.
func writeRawBundle(t *testing.T, data []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "credentialbundle.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

// writeTrust writes a projected ClusterTrustBundle holding the given anchors.
func writeTrust(t *testing.T, dir string, anchors ...*x509.Certificate) string {
	t.Helper()

	var buf bytes.Buffer
	for _, anchor := range anchors {
		buf.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: anchor.Raw}))
	}

	path := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write trust bundle: %v", err)
	}
	return path
}

// fixture is a complete projected volume plus the probe config that reads it.
type fixture struct {
	ca   *testutil.KeyPair
	leaf *x509.Certificate
	cfg  config
}

// newFixture builds a projected volume for the given role.
func newFixture(t *testing.T, role string) fixture {
	t.Helper()

	ca, err := testutil.NewCA("credprobe-test-ca", testCALifetime)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}

	// The peer role authenticates to a real peer, so its credential is a client
	// credential like RoleClient's; only what it does with it differs.
	eku := x509.ExtKeyUsageServerAuth
	if role == report.RoleClient || role == report.RolePeer {
		eku = x509.ExtKeyUsageClientAuth
	}
	key, leaf := issueLeaf(t, ca, []x509.ExtKeyUsage{eku}, []string{testAllowedDNS})

	dir := t.TempDir()
	return fixture{
		ca:   ca,
		leaf: leaf,
		cfg: config{
			bundlePath:     writeBundle(t, dir, key, leaf, ca.Cert),
			trustPath:      writeTrust(t, dir, ca.Cert),
			role:           role,
			expectChainLen: testChainCertsLen,
			allowedDNS:     testAllowedDNS,
			unrelatedDNS:   testUnrelatedDNS,
		},
	}
}

// requireAllPassed fails the test unless the report contains exactly the checks
// expected for its role and all of them passed.
func requireAllPassed(t *testing.T, got report.Report) {
	t.Helper()

	want := report.ExpectedChecks(got.Role)
	if names := got.CheckNames(); !slices.Equal(names, want) {
		t.Fatalf("checks = %v, want %v\n%s", names, want, got)
	}
	if failed := got.Failures(); len(failed) > 0 {
		t.Fatalf("%d checks failed\n%s", len(failed), got)
	}
}

// requireFailed fails the test unless the named check is present and failed.
func requireFailed(t *testing.T, got report.Report, name string) {
	t.Helper()

	for _, check := range got.Checks {
		if check.Name != name {
			continue
		}
		if check.OK {
			t.Fatalf("check %s passed, want failure\n%s", name, got)
		}
		return
	}
	t.Fatalf("check %s was not recorded\n%s", name, got)
}

func TestProbeServerRolePasses(t *testing.T) {
	f := newFixture(t, report.RoleServer)

	got := probe(f.cfg)
	requireAllPassed(t, got)

	if want := []string{testAllowedDNS}; !slices.Equal(got.Facts.LeafDNSNames, want) {
		t.Errorf("leaf DNS names = %v, want %v", got.Facts.LeafDNSNames, want)
	}
	if want := []string{"serverAuth"}; !slices.Equal(got.Facts.LeafExtKeyUsage, want) {
		t.Errorf("leaf EKU = %v, want %v", got.Facts.LeafExtKeyUsage, want)
	}
	if len(got.Facts.ChainSHA256) != testChainCertsLen {
		t.Errorf("chain fingerprints = %v, want %d entries", got.Facts.ChainSHA256, testChainCertsLen)
	}
	if got.Facts.ChainSHA256[0] != fingerprint(f.leaf) {
		t.Errorf("leaf fingerprint = %s, want %s", got.Facts.ChainSHA256[0], fingerprint(f.leaf))
	}
	if want := []string{fingerprint(f.ca.Cert)}; !slices.Equal(got.Facts.TrustSHA256, want) {
		t.Errorf("trust fingerprints = %v, want %v", got.Facts.TrustSHA256, want)
	}
	if want := []string{"PRIVATE KEY", "CERTIFICATE", "CERTIFICATE"}; !slices.Equal(got.Facts.Bundle.BlockTypes, want) {
		t.Errorf("bundle block types = %v, want %v", got.Facts.Bundle.BlockTypes, want)
	}
}

func TestProbeClientRolePasses(t *testing.T) {
	f := newFixture(t, report.RoleClient)

	got := probe(f.cfg)
	requireAllPassed(t, got)

	if want := []string{"clientAuth"}; !slices.Equal(got.Facts.LeafExtKeyUsage, want) {
		t.Errorf("leaf EKU = %v, want %v", got.Facts.LeafExtKeyUsage, want)
	}
}

// A serverAuth-only certificate must be refused for client authentication, and
// a clientAuth-only one for server authentication. Both are asserted by the
// role fixtures above; this test pins the classification itself, so a future
// Go release that stops reporting IncompatibleUsage cannot turn the negative
// checks into ones that pass for the wrong reason.
func TestRoleRejectionsAreClassified(t *testing.T) {
	server := probe(newFixture(t, report.RoleServer).cfg)
	clientAuthRejected := detail(t, server, report.CheckTLSClientAuthRejected)
	if !strings.Contains(clientAuthRejected, "incompatible key usage") {
		t.Errorf("client-auth rejection detail = %q, want an incompatible key usage error", clientAuthRejected)
	}

	client := probe(newFixture(t, report.RoleClient).cfg)
	serverRoleRejected := detail(t, client, report.CheckTLSServerRoleRejected)
	if !strings.Contains(serverRoleRejected, "incompatible key usage") {
		t.Errorf("server-role rejection detail = %q, want an incompatible key usage error", serverRoleRejected)
	}

	unrelated := detail(t, server, report.CheckTLSServerUnrelatedDNS)
	if !strings.Contains(unrelated, testUnrelatedDNS) {
		t.Errorf("unrelated-name detail = %q, want it to name %q", unrelated, testUnrelatedDNS)
	}
}

func TestProbeDetectsKeyNotMatchingLeaf(t *testing.T) {
	f := newFixture(t, report.RoleServer)

	// Replace the bundle's key with one belonging to nobody in the chain.
	otherKey, _ := issueLeaf(t, f.ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testAllowedDNS})
	dir := t.TempDir()
	f.cfg.bundlePath = writeBundle(t, dir, otherKey, f.leaf, f.ca.Cert)

	requireFailed(t, probe(f.cfg), report.CheckBundleKeyMatchesLeaf)
}

func TestProbeDetectsUnexpectedBundleBlock(t *testing.T) {
	f := newFixture(t, report.RoleServer)

	extra := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("extra")})
	f.cfg.bundlePath = writeRawBundle(t, append(readBundle(t, f.cfg.bundlePath), extra...))

	requireFailed(t, probe(f.cfg), report.CheckBundleBlocks)
}

func TestProbeDetectsTrailingGarbageInBundle(t *testing.T) {
	f := newFixture(t, report.RoleServer)

	// A truncated PEM block is what a non-atomic projection update would leave
	// behind, and it must not read as a valid bundle.
	truncated := []byte("-----BEGIN CERTIFICATE-----\nAAAA\n")
	f.cfg.bundlePath = writeRawBundle(t, append(readBundle(t, f.cfg.bundlePath), truncated...))

	requireFailed(t, probe(f.cfg), report.CheckBundleBlocks)
}

func TestProbeDetectsNonCATrustAnchor(t *testing.T) {
	f := newFixture(t, report.RoleServer)

	nonCA, err := testutil.NewNonCA("credprobe-not-a-ca", testCALifetime)
	if err != nil {
		t.Fatalf("generate non-CA: %v", err)
	}
	f.cfg.trustPath = writeTrust(t, t.TempDir(), f.ca.Cert, nonCA.Cert)

	requireFailed(t, probe(f.cfg), report.CheckTrustOnlyCAs)
}

func TestProbeDetectsUntrustedIssuer(t *testing.T) {
	f := newFixture(t, report.RoleServer)

	otherCA, err := testutil.NewCA("credprobe-other-ca", testCALifetime)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	f.cfg.trustPath = writeTrust(t, t.TempDir(), otherCA.Cert)

	requireFailed(t, probe(f.cfg), report.CheckTrustVerifiesLeaf)
}

func TestProbeDetectsMissingBundle(t *testing.T) {
	f := newFixture(t, report.RoleServer)
	f.cfg.bundlePath = filepath.Join(t.TempDir(), "absent.pem")

	requireFailed(t, probe(f.cfg), report.CheckBundleFile)
}

// The probe holds the workload's private key and must never publish it. This
// pins that: the encoded report may not contain a PEM key block, nor the key's
// own bytes. The block *type* "PRIVATE KEY" does appear, in the list of block
// types the bundle carried - that is a description of the file's structure and
// is exactly what the suite asserts on.
func TestReportCarriesNoPrivateKeyMaterial(t *testing.T) {
	ca, err := testutil.NewCA("credprobe-test-ca", testCALifetime)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	key, leaf := issueLeaf(t, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{testAllowedDNS})

	dir := t.TempDir()
	cfg := config{
		bundlePath:     writeBundle(t, dir, key, leaf, ca.Cert),
		trustPath:      writeTrust(t, dir, ca.Cert),
		role:           report.RoleServer,
		expectChainLen: testChainCertsLen,
		allowedDNS:     testAllowedDNS,
		unrelatedDNS:   testUnrelatedDNS,
	}

	encoded, err := json.Marshal(probe(cfg))
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(encoded), "-----BEGIN") {
		t.Errorf("the report carries a PEM block: %s", encoded)
	}
	if bytes.Contains(encoded, key.Seed()) {
		t.Error("the report contains the private key seed")
	}
	if bytes.Contains(encoded, []byte(key)) {
		t.Error("the report contains the private key bytes")
	}
}

// The report travels as one line of a pod log, so parsing must survive
// whatever else the runtime wrote around it.
func TestParseReportFromLog(t *testing.T) {
	f := newFixture(t, report.RoleServer)
	encoded, err := json.Marshal(probe(f.cfg))
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}

	log := strings.Join([]string{
		"some unrelated runtime line",
		report.Prefix + string(encoded),
		"a trailing line",
		"",
	}, "\n")

	parsed, err := report.Parse(log)
	if err != nil {
		t.Fatalf("parse report: %v", err)
	}
	requireAllPassed(t, parsed)

	if _, err := report.Parse("no report here\n"); err == nil {
		t.Error("parsing a log without a report must fail")
	}
}

// detail returns the detail of the named check, failing when it is absent.
func detail(t *testing.T, got report.Report, name string) string {
	t.Helper()

	for _, check := range got.Checks {
		if check.Name == name {
			if !check.OK {
				t.Fatalf("check %s failed\n%s", name, got)
			}
			return check.Detail
		}
	}
	t.Fatalf("check %s was not recorded\n%s", name, got)
	return ""
}
