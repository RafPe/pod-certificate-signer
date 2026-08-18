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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
)

// The peer role is the only check in this suite whose other end is software
// this repository did not write. Everything the server and client roles do is a
// handshake the probe configured on both sides, which proves the projected
// credential is well-formed and internally consistent but cannot prove that an
// independent peer *accepts* the identity the signer issued.
//
// It is driven one request at a time, by `kubectl exec` rather than at pod
// start, because the interesting questions are about a pod that is already
// running: whether the same client still authenticates after the issuing CA has
// rotated underneath the peer, without either pod restarting. A check that only
// ran at startup could not ask that.

const (
	// peerRequestTimeout bounds the whole request, so an exec that cannot
	// complete fails with a report rather than hanging until the suite's own
	// timeout fires.
	peerRequestTimeout = 20 * time.Second

	// peerBodyLimit caps how much of the response is read into the report. The
	// peer's JSON documents are well under this; the limit is here so a
	// misdirected request cannot paste an arbitrary page into the log.
	peerBodyLimit = 64 << 10
)

// checkPeer performs one request against the configured peer and records what
// happened.
//
// It never asserts on the outcome. The suite decides whether a 200, a 403 or a
// TLS alert was the right answer for the mode it asked for; this records which
// one occurred, in enough detail that a wrong answer explains itself.
func (r *reporter) checkPeer(cfg config, projected tls.Certificate, pool *x509.CertPool) bool {
	facts := &report.PeerFacts{URL: cfg.peerURL, Mode: cfg.peerMode}
	r.report.Facts.Peer = facts

	if cfg.peerURL == "" {
		return r.fail(report.CheckPeerRequest, "the peer role requires -peer-url")
	}

	clientCert, err := peerClientCertificate(cfg.peerMode, projected)
	if err != nil {
		return r.fail(report.CheckPeerRequest,
			"preparing the client credential for mode %q: %v", cfg.peerMode, err)
	}

	tlsConfig := &tls.Config{
		// Pinned at both ends throughout this probe, so the observations are
		// stable across Go releases that move the default.
		MinVersion: tls.VersionTLS13,
		// The projected trust anchors and nothing else: the peer's certificate
		// has to verify against what the signer published, not against whatever
		// the image's root store happens to carry.
		RootCAs: pool,
	}
	if clientCert != nil {
		// GetClientCertificate rather than Certificates, and this is the
		// difference between testing the untrusted-client case and silently not
		// testing it. Go's default certificate selection filters candidates
		// against the acceptable-CA list the server advertises, so a foreign
		// certificate would never be put on the wire at all - the handshake
		// would succeed with no client certificate and the run would look like
		// the no-certificate case while claiming to be the untrusted one.
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return clientCert, nil
		}
	}

	// The dialer records that the TCP connection was established. Without it a
	// DNS failure, a missing Service and a peer that refused the credential are
	// one indistinguishable error, and the negative cases would pass for the
	// wrong reason.
	dialer := &net.Dialer{Timeout: peerRequestTimeout}
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, address)
			if err == nil {
				facts.Connected = true
			}
			return conn, err
		},
		// One connection per run, never reused: a pooled connection would carry
		// the trust decision made at its handshake, so a post-rotation request
		// could be answered over a session established before the rotation and
		// prove nothing about the reloaded bundle.
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Transport: transport, Timeout: peerRequestTimeout}

	request, err := http.NewRequest(http.MethodGet, cfg.peerURL, nil)
	if err != nil {
		return r.fail(report.CheckPeerRequest, "building the request for %s: %v", cfg.peerURL, err)
	}
	// The peer serves a human page by default and JSON only to a client that
	// asks for it explicitly by media type - a */* wildcard does not count.
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		classifyPeerError(err, facts)
		if !facts.TLSAlert {
			return r.fail(report.CheckPeerRequest,
				"the request to %s reached no definite outcome (connected=%t): %v; "+
					"a transport failure is not evidence that the peer refused the credential",
				cfg.peerURL, facts.Connected, err)
		}
		return r.pass(report.CheckPeerRequest,
			"the peer refused the %s credential during the handshake with TLS alert %q",
			cfg.peerMode, facts.TLSAlertText)
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, peerBodyLimit))
	if err != nil {
		facts.HTTPStatus = response.StatusCode
		return r.fail(report.CheckPeerRequest,
			"reading the response body from %s after HTTP %d: %v", cfg.peerURL, response.StatusCode, err)
	}

	facts.HTTPStatus = response.StatusCode
	facts.Body = string(body)

	return r.pass(report.CheckPeerRequest,
		"the peer answered HTTP %d to a request presenting the %s credential",
		response.StatusCode, cfg.peerMode)
}

// peerClientCertificate returns the credential the configured mode presents, or
// nil to present none.
func peerClientCertificate(mode string, projected tls.Certificate) (*tls.Certificate, error) {
	switch mode {
	case report.PeerModeProjected:
		return &projected, nil
	case report.PeerModeNone:
		return nil, nil
	case report.PeerModeForeign:
		return foreignClientCertificate()
	default:
		return nil, fmt.Errorf("unknown peer mode %q", mode)
	}
}

// foreignClientCertificate mints a self-signed client certificate that no CA in
// the cluster ever signed.
//
// It is generated here, in the pod, rather than handed in by the suite: a
// certificate that arrives over the wire or through a flag would have to be
// carried by something, and the point of this negative is a credential with no
// relationship to the signer at all. Self-signed is the strongest form of that -
// it chains to nothing the peer could possibly trust.
//
// It deliberately carries clientAuth, so the peer's refusal is about *trust* and
// not about key usage. A certificate that failed the extended-key-usage check
// would be refused too, and the spec would pass without ever testing what it
// claims to.
func foreignClientCertificate() (*tls.Certificate, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating the foreign key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating the foreign serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "credprobe-foreign-client.invalid"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, fmt.Errorf("creating the foreign certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing the foreign certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  private,
		Leaf:        leaf,
	}, nil
}

// remoteErrorOp is the net.OpError operation crypto/tls uses for an alert
// *received* from the peer, as opposed to one this side raised. It is the
// discriminator that makes "the peer rejected the credential" a structural
// observation rather than a guess at error text.
const remoteErrorOp = "remote error"

// classifyPeerError records what kind of failure err was.
//
// The classification that matters is whether the peer raised a TLS alert. An
// alert is proof that the other end examined the credential and rejected it;
// every other failure - a refused connection, an unresolved name, a deadline -
// is something that happened on this side or in between, and says nothing about
// what the peer would have decided.
//
// It matches on a net.OpError whose Op is "remote error" and not on
// tls.AlertError, which looks like the obvious choice and never matches. A
// received alert is delivered as net.OpError wrapping crypto/tls's *unexported*
// alert type; tls.AlertError is a distinct exported type used for alerts raised
// locally, so errors.As against it silently returns false for exactly the case
// this function exists to detect. The observed chain is
// *url.Error -> *tls.permanentError -> *net.OpError{Op: "remote error"}.
func classifyPeerError(err error, facts *report.PeerFacts) {
	facts.Error = err.Error()

	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == remoteErrorOp && opErr.Err != nil {
		facts.TLSAlert = true
		facts.TLSAlertText = opErr.Err.Error()
	}
}
