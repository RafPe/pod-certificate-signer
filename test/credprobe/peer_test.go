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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
)

// These tests stand a local HTTPS server up with the same TLS settings the
// in-cluster peer uses - TLS 1.3 and tls.VerifyClientCertIfGiven over a trust
// bundle of CA certificates - and drive the peer role against it.
//
// They exist because the three peer modes fail in three different places, and
// two of those are easy to get silently wrong:
//
//   - Presenting a foreign certificate at all requires overriding Go's default
//     client-certificate selection, which filters candidates against the
//     acceptable-CA list the server advertises. Without the override the
//     handshake succeeds carrying no certificate and the untrusted-client case
//     quietly becomes the no-certificate case - passing, while testing nothing.
//   - A refusal must be distinguishable from a failure to reach the peer at all.
//
// Proving both here means the e2e spec that asserts them is debugging the
// cluster, not the probe.

// verifyClientCertIfGivenServer starts a TLS server mirroring the in-cluster
// peer: it serves leaf, trusts clientCAs for client certificates, and requires
// none.
func verifyClientCertIfGivenServer(t *testing.T, leaf tls.Certificate, clientCAs *x509.CertPool) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mirrors the peer's own rule: identity comes from the verified chain,
		// never from the presented certificates.
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"authenticated":false,"reason":"no client certificate presented"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"authenticated":true}`))
	}))
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{leaf},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientCAs,
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	return server
}

// issueLoopbackServerLeaf signs a serverAuth certificate valid for 127.0.0.1,
// which is the address httptest listens on.
func issueLoopbackServerLeaf(t *testing.T, f fixture) tls.Certificate {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "credprobe-peer-under-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(testLeafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.ca.Cert, pub, f.ca.Key)
	if err != nil {
		t.Fatalf("sign server leaf: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

// newPeerFixture builds a peer-role fixture pointed at a live local peer.
func newPeerFixture(t *testing.T, mode string) (fixture, *httptest.Server) {
	t.Helper()

	f := newFixture(t, report.RolePeer)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(f.ca.Cert)
	server := verifyClientCertIfGivenServer(t, issueLoopbackServerLeaf(t, f), clientCAs)

	f.cfg.peerURL = server.URL + "/whoami.json"
	f.cfg.peerMode = mode
	return f, server
}

// requirePeerFacts fails unless the report ran every peer check, passed them,
// and recorded peer facts.
func requirePeerFacts(t *testing.T, got report.Report) report.PeerFacts {
	t.Helper()

	requireAllPassed(t, got)
	if got.Facts.Peer == nil {
		t.Fatalf("the peer role must record peer facts\n%s", got)
	}
	return *got.Facts.Peer
}

func TestPeerProjectedCredentialIsAccepted(t *testing.T) {
	f, _ := newPeerFixture(t, report.PeerModeProjected)

	facts := requirePeerFacts(t, probe(f.cfg))

	if !facts.Connected {
		t.Errorf("connected = false, want true")
	}
	if facts.HTTPStatus != http.StatusOK {
		t.Errorf("httpStatus = %d, want %d; error was %q", facts.HTTPStatus, http.StatusOK, facts.Error)
	}
	if facts.Body != `{"authenticated":true}` {
		t.Errorf("body = %q, want the authenticated document", facts.Body)
	}
	if facts.TLSAlert {
		t.Errorf("tlsAlert = true for a credential the peer trusts")
	}
}

func TestPeerWithoutCertificateIsRefusedAsHTTP(t *testing.T) {
	f, _ := newPeerFixture(t, report.PeerModeNone)

	facts := requirePeerFacts(t, probe(f.cfg))

	// The handshake completes: VerifyClientCertIfGiven permits a client that
	// offers nothing, so the refusal is the peer's application-level answer and
	// not a TLS failure. This is what makes it a different assertion from the
	// foreign-certificate case below, rather than a differently worded one.
	if facts.HTTPStatus != http.StatusForbidden {
		t.Errorf("httpStatus = %d, want %d; error was %q", facts.HTTPStatus, http.StatusForbidden, facts.Error)
	}
	if facts.TLSAlert {
		t.Errorf("tlsAlert = true; presenting no certificate must not fail the handshake")
	}
}

func TestPeerWithForeignCertificateIsRefusedInHandshake(t *testing.T) {
	f, _ := newPeerFixture(t, report.PeerModeForeign)

	facts := requirePeerFacts(t, probe(f.cfg))

	if !facts.Connected {
		t.Errorf("connected = false; the refusal must come from the peer, not from the network")
	}
	if facts.HTTPStatus != 0 {
		t.Errorf("httpStatus = %d, want no response at all: the peer must reject the certificate "+
			"during the handshake, before any handler runs", facts.HTTPStatus)
	}
	if !facts.TLSAlert {
		t.Fatalf("tlsAlert = false, want a TLS alert; error was %q.\n"+
			"A foreign certificate that produces no alert most likely was never sent - see the "+
			"GetClientCertificate note in checkPeer", facts.Error)
	}
	// A Go peer sends unknown_certificate_authority for a chain it cannot build;
	// bad_certificate is the other refusal a peer may reasonably choose. Both
	// name the certificate itself, which is the claim. Admitting either keeps
	// the assertion about the rejection rather than about the peer's choice of
	// alert, which is not ours to fix.
	if !strings.Contains(facts.TLSAlertText, "unknown certificate authority") &&
		!strings.Contains(facts.TLSAlertText, "bad certificate") {
		t.Errorf("tlsAlertText = %q, want an alert naming the certificate; error was %q",
			facts.TLSAlertText, facts.Error)
	}
}

func TestPeerUnreachableIsNotARefusal(t *testing.T) {
	f, server := newPeerFixture(t, report.PeerModeProjected)
	// Closing the peer makes the request fail without the peer ever judging the
	// credential. The check must go red: a suite that accepted this as a
	// refusal would report a passing negative for a peer that was never there.
	server.Close()

	got := probe(f.cfg)

	failures := got.Failures()
	if len(failures) != 1 || failures[0].Name != report.CheckPeerRequest {
		t.Fatalf("want exactly the %s check to fail\n%s", report.CheckPeerRequest, got)
	}
	if got.Facts.Peer == nil || got.Facts.Peer.TLSAlert {
		t.Errorf("an unreachable peer must not be classified as a TLS refusal\n%s", got)
	}
}

func TestPeerRoleRequiresURL(t *testing.T) {
	f := newFixture(t, report.RolePeer)
	f.cfg.peerMode = report.PeerModeProjected

	got := probe(f.cfg)

	if len(got.Failures()) != 1 {
		t.Fatalf("a peer run with no -peer-url must fail exactly one check\n%s", got)
	}
}
