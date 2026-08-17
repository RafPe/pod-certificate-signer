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

// Package report defines the wire format the in-cluster credential probe
// (test/credprobe) writes and the e2e suite reads.
//
// It exists so the two halves cannot drift: the probe runs as its own binary in
// its own image, the suite decodes what the pod logged, and a renamed check or
// a retyped fact is a compile error rather than a silently unmatched string.
//
// Nothing here may carry private key material. The probe is the only component
// in the suite that holds the workload's private key, and everything it reports
// about that key is derived and public: fingerprints of certificates, PEM block
// *types*, sizes, and booleans. See the e2e suite's diagnostics_test.go for the
// same rule applied to the failure dump.
package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Prefix marks the single line of JSON the probe writes to stdout. The suite
// takes the last line of the pod log carrying this prefix, so a runtime message
// on stdout or stderr can never be mistaken for the report.
const Prefix = "CREDPROBE-REPORT "

// Roles the probe can be run in. The role is the EKU the projected certificate
// was issued with, and it selects which TLS checks are meaningful: a
// serverAuth-only certificate cannot be asserted to succeed as a client, and a
// clientAuth-only one cannot be asserted to succeed as a server.
const (
	RoleServer = "server"
	RoleClient = "client"
)

// Check names. The suite asserts on the exact set for a role, so a check that
// fails to run is as visible as one that fails.
const (
	// CheckBundleFile covers the credential bundle as a file: present,
	// non-empty and readable by the (non-root) user the container runs as.
	CheckBundleFile = "bundle.file"

	// CheckBundleBlocks covers the bundle's PEM structure: exactly one private
	// key block, first, followed by the expected number of certificates and
	// nothing else.
	CheckBundleBlocks = "bundle.blocks"

	// CheckBundleKeyMatchesLeaf proves the projected private key belongs to the
	// projected leaf certificate.
	CheckBundleKeyMatchesLeaf = "bundle.keyMatchesLeaf"

	// CheckTrustFile covers the projected ClusterTrustBundle as a file.
	CheckTrustFile = "trust.file"

	// CheckTrustOnlyCAs proves the trust anchors are certificates, and are all
	// CA certificates - an end-entity certificate in a trust store is a trust
	// bug, not a formatting one.
	CheckTrustOnlyCAs = "trust.onlyCAs"

	// CheckTrustVerifiesLeaf proves the projected leaf chains to the projected
	// trust anchors.
	CheckTrustVerifiesLeaf = "trust.verifiesLeaf"

	// CheckTLSServerAllowedDNS proves a real TLS handshake succeeds when the
	// peer verifies the projected certificate against the projected trust
	// anchors for a DNS name the certificate carries.
	CheckTLSServerAllowedDNS = "tls.server.allowedDNS"

	// CheckTLSServerUnrelatedDNS proves the same handshake fails, with a
	// hostname error specifically, for a name the certificate does not carry.
	CheckTLSServerUnrelatedDNS = "tls.server.unrelatedDNS"

	// CheckTLSClientAuthRejected proves a serverAuth-only certificate is
	// refused when presented for client authentication, with an incompatible
	// key usage error specifically.
	CheckTLSClientAuthRejected = "tls.clientAuth.rejectsServerOnlyCert"

	// CheckTLSClientAuthAccepted proves a clientAuth certificate is accepted by
	// a server that requires and verifies client certificates.
	CheckTLSClientAuthAccepted = "tls.clientAuth.acceptsClientCert"

	// CheckTLSServerRoleRejected proves a clientAuth-only certificate is
	// refused when presented as a server certificate.
	CheckTLSServerRoleRejected = "tls.server.rejectsClientOnlyCert"
)

// ExpectedChecks returns the checks a report for the given role must contain,
// in the order the probe runs them.
func ExpectedChecks(role string) []string {
	common := []string{
		CheckBundleFile,
		CheckBundleBlocks,
		CheckBundleKeyMatchesLeaf,
		CheckTrustFile,
		CheckTrustOnlyCAs,
		CheckTrustVerifiesLeaf,
	}
	if role == RoleClient {
		return append(common, CheckTLSClientAuthAccepted, CheckTLSServerRoleRejected)
	}
	return append(common,
		CheckTLSServerAllowedDNS,
		CheckTLSServerUnrelatedDNS,
		CheckTLSClientAuthRejected)
}

// Check is one assertion the probe made about the projected credential.
type Check struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	// Detail states what was observed, whether the check passed or failed, so a
	// red run needs no second run to explain itself.
	Detail string `json:"detail"`
}

// FileFacts is what the probe observed about a projected file. The mode and
// ownership are reported rather than asserted: whether kubelet chowns a
// projected credential to the container's user is kubelet's contract, not this
// signer's, and recording it makes a change visible without pinning it.
type FileFacts struct {
	Path       string   `json:"path"`
	Mode       string   `json:"mode"`
	UID        uint32   `json:"uid"`
	GID        uint32   `json:"gid"`
	Size       int64    `json:"size"`
	BlockTypes []string `json:"blockTypes"`
}

// Facts are the observations the probe made. They are what lets the suite judge
// properties the probe cannot know on its own - that the projected leaf is the
// one the PodCertificateRequest status published, that the projected trust
// anchors are the ones the ClusterTrustBundle carries - and what makes a failed
// check readable.
type Facts struct {
	// ProcessUID is the uid the probe ran as, so "readable" is qualified by who
	// read it.
	ProcessUID int `json:"processUid"`

	Bundle FileFacts `json:"bundle"`
	Trust  FileFacts `json:"trust"`

	// ChainSHA256 are the SHA-256 fingerprints of the bundle's certificates in
	// order, leaf first.
	ChainSHA256 []string `json:"chainSha256"`
	// TrustSHA256 are the SHA-256 fingerprints of the trust anchors in order.
	TrustSHA256 []string `json:"trustSha256"`

	LeafSubject     string   `json:"leafSubject"`
	LeafDNSNames    []string `json:"leafDnsNames"`
	LeafIPAddresses []string `json:"leafIpAddresses"`
	LeafURIs        []string `json:"leafUris"`
	LeafExtKeyUsage []string `json:"leafExtKeyUsage"`
	LeafNotBefore   string   `json:"leafNotBefore"`
	LeafNotAfter    string   `json:"leafNotAfter"`
	// LeafKeyAlgorithm is the public key algorithm of the projected leaf, e.g.
	// Ed25519.
	LeafKeyAlgorithm string `json:"leafKeyAlgorithm"`
}

// Report is the probe's whole output.
type Report struct {
	Role   string  `json:"role"`
	Checks []Check `json:"checks"`
	Facts  Facts   `json:"facts"`
}

// Failures returns the checks that did not pass.
func (r Report) Failures() []Check {
	var failed []Check
	for _, check := range r.Checks {
		if !check.OK {
			failed = append(failed, check)
		}
	}
	return failed
}

// CheckNames returns the names of every check in the report, in order.
func (r Report) CheckNames() []string {
	names := make([]string, 0, len(r.Checks))
	for _, check := range r.Checks {
		names = append(names, check.Name)
	}
	return names
}

// String renders the report for a test failure message: every check with its
// detail, then the facts as JSON.
func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "credprobe report (role %s):\n", r.Role)
	for _, check := range r.Checks {
		status := "PASS"
		if !check.OK {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "  [%s] %s: %s\n", status, check.Name, check.Detail)
	}
	facts, err := json.MarshalIndent(r.Facts, "  ", "  ")
	if err != nil {
		fmt.Fprintf(&b, "  facts: unavailable (%v)\n", err)
		return b.String()
	}
	fmt.Fprintf(&b, "  facts: %s\n", facts)
	return b.String()
}

// Parse extracts the report from a pod log.
//
// It takes the last prefixed line rather than the first so a probe that somehow
// reported twice is read at its latest state, and returns an error naming what
// it saw when there is no report at all - a probe that crashed before reporting
// must not look like a probe that reported nothing.
func Parse(log string) (Report, error) {
	var line string
	for _, candidate := range strings.Split(log, "\n") {
		if idx := strings.Index(candidate, Prefix); idx >= 0 {
			line = candidate[idx+len(Prefix):]
		}
	}
	if line == "" {
		return Report{}, fmt.Errorf("no %q line in the probe log", strings.TrimSpace(Prefix))
	}

	var parsed Report
	if err := json.Unmarshal([]byte(line), &parsed); err != nil {
		return Report{}, fmt.Errorf("decoding the probe report: %w", err)
	}
	return parsed, nil
}
