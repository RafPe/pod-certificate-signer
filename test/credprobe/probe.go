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
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
)

// config is what the e2e suite tells the probe about the credential it is
// about to inspect. Everything the probe can observe for itself - fingerprints,
// subject, SANs, lifetimes - is reported rather than passed in, so the suite
// judges those against the PodCertificateRequest status and the
// ClusterTrustBundle instead of the probe grading its own homework.
type config struct {
	bundlePath string
	trustPath  string

	// role is the EKU the projected certificate was issued with; see
	// report.RoleServer / report.RoleClient.
	role string

	// expectChainLen is how many certificates the bundle must carry after the
	// private key.
	expectChainLen int

	// allowedDNS is a DNS name the certificate carries, and unrelatedDNS one it
	// must not: the pair is what separates "the handshake worked" from "the
	// handshake verified the name".
	allowedDNS   string
	unrelatedDNS string

	hold time.Duration
}

// probe runs every check for the configured role and returns the report.
//
// Checks that later ones depend on stop the run: with no parseable bundle there
// is nothing to say about the key, and reporting a cascade of failures whose
// only cause is the first one buries the actual fault. The suite asserts on the
// full expected set of check names, so a short report fails just as loudly as a
// failing check - and says why in the last check it did record.
func probe(cfg config) report.Report {
	r := &reporter{}
	r.report.Role = cfg.role
	r.report.Facts.ProcessUID = os.Getuid()

	bundlePEM, ok := r.readProjectedFile(report.CheckBundleFile, cfg.bundlePath, &r.report.Facts.Bundle)
	if !ok {
		return r.report
	}

	key, chain, ok := r.checkBundleBlocks(cfg, bundlePEM)
	if !ok {
		return r.report
	}
	r.recordLeafFacts(chain)

	if !r.checkKeyMatchesLeaf(key, chain[0]) {
		return r.report
	}

	trustPEM, ok := r.readProjectedFile(report.CheckTrustFile, cfg.trustPath, &r.report.Facts.Trust)
	if !ok {
		return r.report
	}

	anchors, ok := r.checkTrustAnchors(trustPEM)
	if !ok {
		return r.report
	}

	pool := x509.NewCertPool()
	for _, anchor := range anchors {
		pool.AddCert(anchor)
	}
	if !r.checkTrustVerifiesLeaf(chain, pool) {
		return r.report
	}

	r.checkTLS(cfg, tls.Certificate{
		Certificate: rawChain(chain),
		PrivateKey:  key,
		Leaf:        chain[0],
	}, pool)

	return r.report
}

// reporter accumulates checks and facts.
type reporter struct {
	report report.Report
}

// pass records a satisfied check. The detail states what was observed anyway:
// a green run is the baseline a later red one is read against.
func (r *reporter) pass(name, format string, args ...any) bool {
	r.report.Checks = append(r.report.Checks, report.Check{
		Name: name, OK: true, Detail: fmt.Sprintf(format, args...),
	})
	return true
}

// fail records an unsatisfied check and returns false, so callers can write
// `if !r.check(...) { return }`.
func (r *reporter) fail(name, format string, args ...any) bool {
	r.report.Checks = append(r.report.Checks, report.Check{
		Name: name, OK: false, Detail: fmt.Sprintf(format, args...),
	})
	return false
}

// readProjectedFile stats and reads one projected file, recording what it found
// either way.
//
// The stat facts are collected before the read so a permission failure is
// reported alongside the mode and ownership that caused it. That combination is
// the whole point of running this in-cluster: the suite cannot see from outside
// whether kubelet made the credential readable by the user the container
// actually runs as.
func (r *reporter) readProjectedFile(checkName, path string, facts *report.FileFacts) ([]byte, bool) {
	facts.Path = path

	info, err := os.Stat(path)
	if err != nil {
		return nil, r.fail(checkName, "stat %s: %v", path, err)
	}
	facts.Mode = info.Mode().Perm().String()
	facts.Size = info.Size()
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		facts.UID = stat.Uid
		facts.GID = stat.Gid
	}

	//nolint:gosec // G304: the path is a probe flag set by the e2e suite.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, r.fail(checkName, "read %s as uid %d (mode %s, owner %d:%d): %v",
			path, r.report.Facts.ProcessUID, facts.Mode, facts.UID, facts.GID, err)
	}
	if len(data) == 0 {
		return nil, r.fail(checkName, "%s is empty", path)
	}

	r.pass(checkName, "read %d bytes from %s as uid %d (mode %s, owner %d:%d)",
		len(data), path, r.report.Facts.ProcessUID, facts.Mode, facts.UID, facts.GID)
	return data, true
}

// checkBundleBlocks decodes the credential bundle and asserts its shape:
// exactly one private key block, first, then exactly the expected number of
// certificates, and nothing else.
//
// The order and the count both matter. A bundle whose trailing bytes are not
// PEM, or which carries a second key, or which is missing the issuer, is a
// bundle a workload cannot use to serve TLS - and none of that is visible in
// the PodCertificateRequest status, which is why it is checked here.
func (r *reporter) checkBundleBlocks(cfg config, bundlePEM []byte) (crypto.Signer, []*x509.Certificate, bool) {
	blocks, rest := decodePEM(bundlePEM)
	for _, block := range blocks {
		r.report.Facts.Bundle.BlockTypes = append(r.report.Facts.Bundle.BlockTypes, block.Type)
	}

	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, r.fail(report.CheckBundleBlocks,
			"%d trailing bytes after the last PEM block; blocks were %v",
			len(rest), r.report.Facts.Bundle.BlockTypes)
	}
	if want := cfg.expectChainLen + 1; len(blocks) != want {
		return nil, nil, r.fail(report.CheckBundleBlocks,
			"want %d PEM blocks (1 private key + %d certificates), got %d: %v",
			want, cfg.expectChainLen, len(blocks), r.report.Facts.Bundle.BlockTypes)
	}
	if !isPrivateKeyBlock(blocks[0].Type) {
		return nil, nil, r.fail(report.CheckBundleBlocks,
			"the first PEM block must be a private key, got %q; blocks were %v",
			blocks[0].Type, r.report.Facts.Bundle.BlockTypes)
	}

	key, err := parsePrivateKey(blocks[0])
	if err != nil {
		return nil, nil, r.fail(report.CheckBundleBlocks, "parsing the private key: %v", err)
	}

	var chain []*x509.Certificate
	for i, block := range blocks[1:] {
		if block.Type != "CERTIFICATE" {
			return nil, nil, r.fail(report.CheckBundleBlocks,
				"PEM block %d must be a CERTIFICATE, got %q; blocks were %v",
				i+1, block.Type, r.report.Facts.Bundle.BlockTypes)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, r.fail(report.CheckBundleBlocks, "parsing certificate %d: %v", i, err)
		}
		chain = append(chain, cert)
		r.report.Facts.ChainSHA256 = append(r.report.Facts.ChainSHA256, fingerprint(cert))
	}

	r.pass(report.CheckBundleBlocks, "bundle carries %v and no other blocks",
		r.report.Facts.Bundle.BlockTypes)
	return key, chain, true
}

// checkKeyMatchesLeaf proves the projected private key is the one the leaf
// certifies. A bundle pairing a valid key with someone else's certificate
// parses perfectly and fails at the first handshake.
func (r *reporter) checkKeyMatchesLeaf(key crypto.Signer, leaf *x509.Certificate) bool {
	pub, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return r.fail(report.CheckBundleKeyMatchesLeaf,
			"private key of type %T cannot be compared to the leaf public key", key.Public())
	}
	if !pub.Equal(leaf.PublicKey) {
		return r.fail(report.CheckBundleKeyMatchesLeaf,
			"the projected private key does not match the public key of leaf %s", fingerprint(leaf))
	}
	return r.pass(report.CheckBundleKeyMatchesLeaf,
		"the projected %s private key matches leaf %s", leaf.PublicKeyAlgorithm, fingerprint(leaf))
}

// checkTrustAnchors decodes the projected ClusterTrustBundle and asserts every
// entry is a CA certificate. An end-entity certificate in a trust store is a
// trust bug: anything it signs would be accepted.
func (r *reporter) checkTrustAnchors(trustPEM []byte) ([]*x509.Certificate, bool) {
	blocks, rest := decodePEM(trustPEM)
	for _, block := range blocks {
		r.report.Facts.Trust.BlockTypes = append(r.report.Facts.Trust.BlockTypes, block.Type)
	}

	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, r.fail(report.CheckTrustOnlyCAs,
			"%d trailing bytes after the last PEM block; blocks were %v",
			len(rest), r.report.Facts.Trust.BlockTypes)
	}
	if len(blocks) == 0 {
		return nil, r.fail(report.CheckTrustOnlyCAs, "the projected trust bundle carries no PEM blocks")
	}

	var anchors []*x509.Certificate
	for i, block := range blocks {
		if block.Type != "CERTIFICATE" {
			return nil, r.fail(report.CheckTrustOnlyCAs,
				"trust anchor %d must be a CERTIFICATE, got %q", i, block.Type)
		}
		anchor, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, r.fail(report.CheckTrustOnlyCAs, "parsing trust anchor %d: %v", i, err)
		}
		if !anchor.IsCA {
			return nil, r.fail(report.CheckTrustOnlyCAs,
				"trust anchor %d (%s, subject %q) is not a CA certificate",
				i, fingerprint(anchor), anchor.Subject)
		}
		anchors = append(anchors, anchor)
		r.report.Facts.TrustSHA256 = append(r.report.Facts.TrustSHA256, fingerprint(anchor))
	}

	r.pass(report.CheckTrustOnlyCAs, "%d trust anchors, all CA certificates: %v",
		len(anchors), r.report.Facts.TrustSHA256)
	return anchors, true
}

// checkTrustVerifiesLeaf builds a chain from the projected leaf to the
// projected trust anchors.
func (r *reporter) checkTrustVerifiesLeaf(chain []*x509.Certificate, pool *x509.CertPool) bool {
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}

	// KeyUsageAny keeps this check about the chain: whether the leaf is usable
	// for a given role is what the TLS checks below prove.
	_, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return r.fail(report.CheckTrustVerifiesLeaf,
			"leaf %s does not chain to the projected trust anchors %v: %v",
			fingerprint(chain[0]), r.report.Facts.TrustSHA256, err)
	}
	return r.pass(report.CheckTrustVerifiesLeaf,
		"leaf %s chains to the projected trust anchors", fingerprint(chain[0]))
}

// recordLeafFacts copies the public fields of the leaf into the report so the
// suite can compare them against the request status.
func (r *reporter) recordLeafFacts(chain []*x509.Certificate) {
	leaf := chain[0]
	facts := &r.report.Facts

	facts.LeafSubject = leaf.Subject.String()
	facts.LeafDNSNames = leaf.DNSNames
	facts.LeafNotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	facts.LeafNotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	facts.LeafKeyAlgorithm = leaf.PublicKeyAlgorithm.String()

	for _, ip := range leaf.IPAddresses {
		facts.LeafIPAddresses = append(facts.LeafIPAddresses, ip.String())
	}
	for _, uri := range leaf.URIs {
		facts.LeafURIs = append(facts.LeafURIs, uri.String())
	}
	for _, eku := range leaf.ExtKeyUsage {
		facts.LeafExtKeyUsage = append(facts.LeafExtKeyUsage, extKeyUsageName(eku))
	}
}

// decodePEM decodes every PEM block in data and returns them with whatever the
// decoder could not consume.
func decodePEM(data []byte) ([]*pem.Block, []byte) {
	var blocks []*pem.Block
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return blocks, rest
		}
		blocks = append(blocks, block)
	}
}

// isPrivateKeyBlock reports whether a PEM block type names a private key, in
// any of the encodings x509 can produce.
func isPrivateKeyBlock(blockType string) bool {
	return strings.HasSuffix(blockType, "PRIVATE KEY")
}

// parsePrivateKey decodes a private key PEM block, accepting the PKCS#8 form
// kubelet writes today as well as the algorithm-specific forms, and requires
// the result to be usable for signing.
func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	var (
		key any
		err error
	)
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key of type %T cannot sign", key)
	}
	return signer, nil
}

// rawChain returns the DER of every certificate in the chain, the form
// tls.Certificate wants.
func rawChain(chain []*x509.Certificate) [][]byte {
	raw := make([][]byte, 0, len(chain))
	for _, cert := range chain {
		raw = append(raw, cert.Raw)
	}
	return raw
}

// fingerprint returns the SHA-256 fingerprint of a certificate, the identifier
// the suite compares against the request status and the trust bundle.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// extKeyUsageName renders an extended key usage for the report.
func extKeyUsageName(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "any"
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	default:
		return fmt.Sprintf("eku(%d)", eku)
	}
}

// isHostnameError reports whether err is, or wraps, a name mismatch.
func isHostnameError(err error) bool {
	var hostname x509.HostnameError
	return errors.As(err, &hostname)
}

// isIncompatibleUsage reports whether err is, or wraps, a rejection for the
// certificate's extended key usage - the specific reason a serverAuth-only
// certificate must be refused in the client role and vice versa.
//
// Classifying rather than checking for any error is what keeps these negative
// cases honest: a handshake that fails because the probe misconfigured the
// listener would otherwise read as proof of an EKU boundary that was never
// tested.
func isIncompatibleUsage(err error) bool {
	var invalid x509.CertificateInvalidError
	return errors.As(err, &invalid) && invalid.Reason == x509.IncompatibleUsage
}
