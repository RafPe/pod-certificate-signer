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
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
)

// The TLS checks are the point of running in-cluster at all. A credential that
// parses is not a credential that works: the questions that matter are whether
// a peer verifying the projected trust anchors accepts the projected
// certificate for a name it is supposed to have, refuses it for a name it is
// not, and refuses it outright in a role its extended key usage does not
// permit. Each of those is answered by a real TLS 1.3 handshake over a loopback
// socket, not by inspecting fields.
//
// TLS 1.3 is pinned at both ends so the observations are stable. It also moves
// client-certificate verification entirely to the server side of the
// handshake - the client's Handshake returns before the server has judged its
// certificate - which is why every client-authentication assertion below reads
// the *server's* error and not the client's.

const (
	// handshakeTimeout bounds every socket operation, so a check that cannot
	// complete fails the run instead of hanging the pod.
	handshakeTimeout = 10 * time.Second

	// handshakePayload is written by the server after a successful handshake
	// and read back by the client, so a passing check proves a usable session
	// rather than a completed handshake.
	handshakePayload = "credprobe-ok"
)

// handshakeResult is what one handshake attempt observed from both ends.
type handshakeResult struct {
	serverErr error
	clientErr error

	// clientPeers are the certificates the server received from the client.
	clientPeers []*x509.Certificate

	// payload is what the client managed to read over the established session.
	payload string
}

// String renders the result for a check detail.
func (h handshakeResult) String() string {
	return fmt.Sprintf("server error: %v; client error: %v", h.serverErr, h.clientErr)
}

// handshake runs one TLS handshake between the two configurations over a
// loopback TCP connection and reports what each end saw.
func handshake(serverCfg, clientCfg *tls.Config) handshakeResult {
	var result handshakeResult

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		result.serverErr = fmt.Errorf("listen: %w", err)
		return result
	}
	defer func() { _ = listener.Close() }()
	if tcp, ok := listener.(*net.TCPListener); ok {
		// Bounds Accept, so a client that never connects cannot wedge the
		// goroutine below.
		_ = tcp.SetDeadline(time.Now().Add(handshakeTimeout))
	}

	type serverOutcome struct {
		err   error
		peers []*x509.Certificate
	}
	done := make(chan serverOutcome, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- serverOutcome{err: fmt.Errorf("accept: %w", err)}
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

		server := tls.Server(conn, serverCfg)
		if err := server.Handshake(); err != nil {
			done <- serverOutcome{err: err}
			return
		}
		peers := server.ConnectionState().PeerCertificates
		_, err = server.Write([]byte(handshakePayload))
		done <- serverOutcome{err: err, peers: peers}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		result.clientErr = fmt.Errorf("dial: %w", err)
	} else {
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))

		client := tls.Client(conn, clientCfg)
		if err := client.Handshake(); err != nil {
			result.clientErr = err
		} else {
			buf := make([]byte, len(handshakePayload))
			if _, err := io.ReadFull(client, buf); err != nil {
				// Under TLS 1.3 a server that rejected the client certificate
				// surfaces here rather than during the handshake.
				result.clientErr = err
			} else {
				result.payload = string(buf)
			}
		}
	}

	outcome := <-done
	result.serverErr = outcome.err
	result.clientPeers = outcome.peers
	return result
}

// serverConfig serves the given certificate.
func serverConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}

// verifyingClientConfig verifies the peer against the projected trust anchors
// for the given name, which is what a workload's own client would do.
func verifyingClientConfig(pool *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
}

// checkTLS runs the handshakes that are meaningful for the certificate's role.
func (r *reporter) checkTLS(cfg config, cert tls.Certificate, pool *x509.CertPool) {
	if cfg.role == report.RoleClient {
		r.checkClientAuthAccepted(cert, pool)
		r.checkServerRoleRejected(cfg, cert, pool)
		return
	}

	r.checkServerAllowedDNS(cfg, cert, pool)
	r.checkServerUnrelatedDNS(cfg, cert, pool)
	r.checkClientAuthRejected(cfg, cert, pool)
}

// checkServerAllowedDNS proves the projected credential serves TLS for a name
// it carries, to a client that trusts only the projected anchors.
func (r *reporter) checkServerAllowedDNS(cfg config, cert tls.Certificate, pool *x509.CertPool) {
	result := handshake(serverConfig(cert), verifyingClientConfig(pool, cfg.allowedDNS))
	if result.serverErr != nil || result.clientErr != nil {
		r.fail(report.CheckTLSServerAllowedDNS,
			"a handshake for %q must succeed; %s", cfg.allowedDNS, result)
		return
	}
	if result.payload != handshakePayload {
		r.fail(report.CheckTLSServerAllowedDNS,
			"the session for %q carried %q, want %q", cfg.allowedDNS, result.payload, handshakePayload)
		return
	}
	r.pass(report.CheckTLSServerAllowedDNS,
		"a client trusting only the projected anchors completed a TLS 1.3 session for %q", cfg.allowedDNS)
}

// checkServerUnrelatedDNS proves the same credential is refused for a name it
// does not carry, and refused for that reason.
func (r *reporter) checkServerUnrelatedDNS(cfg config, cert tls.Certificate, pool *x509.CertPool) {
	result := handshake(serverConfig(cert), verifyingClientConfig(pool, cfg.unrelatedDNS))
	if !isHostnameError(result.clientErr) {
		r.fail(report.CheckTLSServerUnrelatedDNS,
			"a handshake for the unrelated name %q must fail with a hostname error; %s",
			cfg.unrelatedDNS, result)
		return
	}
	r.pass(report.CheckTLSServerUnrelatedDNS,
		"the client refused the certificate for the unrelated name %q: %v",
		cfg.unrelatedDNS, result.clientErr)
}

// checkClientAuthRejected proves a serverAuth-only credential cannot be used to
// authenticate as a client.
//
// The server here both serves the projected certificate and requires one from
// the client, so the only thing that changes between this check and the
// allowed-name check above is the role the certificate is asked to play.
func (r *reporter) checkClientAuthRejected(cfg config, cert tls.Certificate, pool *x509.CertPool) {
	serverCfg := serverConfig(cert)
	serverCfg.ClientAuth = tls.RequireAndVerifyClientCert
	serverCfg.ClientCAs = pool

	clientCfg := verifyingClientConfig(pool, cfg.allowedDNS)
	clientCfg.Certificates = []tls.Certificate{cert}

	result := handshake(serverCfg, clientCfg)
	if !isIncompatibleUsage(result.serverErr) {
		r.fail(report.CheckTLSClientAuthRejected,
			"a server-only certificate presented for client authentication must be refused "+
				"for an incompatible key usage; %s", result)
		return
	}
	r.pass(report.CheckTLSClientAuthRejected,
		"the server refused the server-only certificate for client authentication: %v", result.serverErr)
}

// checkClientAuthAccepted proves a clientAuth credential authenticates against
// a server that requires and verifies client certificates.
//
// The counterparty is a throwaway self-signed server certificate generated
// here: the projected credential is a client certificate and has no server
// identity to offer, and what is under test is the server's verification of the
// *client* certificate against the projected trust anchors. The client still
// verifies its peer properly - against a pool holding exactly that throwaway
// certificate - so this check turns nothing off.
func (r *reporter) checkClientAuthAccepted(cert tls.Certificate, pool *x509.CertPool) {
	peerCert, err := ephemeralServerCertificate()
	if err != nil {
		r.fail(report.CheckTLSClientAuthAccepted, "generating the peer server certificate: %v", err)
		return
	}
	peerPool := x509.NewCertPool()
	peerPool.AddCert(peerCert.Leaf)

	serverCfg := serverConfig(peerCert)
	serverCfg.ClientAuth = tls.RequireAndVerifyClientCert
	serverCfg.ClientCAs = pool

	clientCfg := verifyingClientConfig(peerPool, ephemeralPeerName)
	clientCfg.Certificates = []tls.Certificate{cert}

	result := handshake(serverCfg, clientCfg)
	if result.serverErr != nil || result.clientErr != nil {
		r.fail(report.CheckTLSClientAuthAccepted,
			"a client-auth certificate must be accepted for client authentication; %s", result)
		return
	}
	if len(result.clientPeers) == 0 {
		r.fail(report.CheckTLSClientAuthAccepted, "the server received no client certificate")
		return
	}
	if got := fingerprint(result.clientPeers[0]); got != fingerprint(cert.Leaf) {
		r.fail(report.CheckTLSClientAuthAccepted,
			"the server authenticated a different certificate: got %s, want %s", got, fingerprint(cert.Leaf))
		return
	}
	r.pass(report.CheckTLSClientAuthAccepted,
		"a server requiring client certificates verified the projected leaf %s against the projected anchors",
		fingerprint(cert.Leaf))
}

// checkServerRoleRejected proves a clientAuth-only credential is refused when
// offered as a server certificate.
func (r *reporter) checkServerRoleRejected(cfg config, cert tls.Certificate, pool *x509.CertPool) {
	result := handshake(serverConfig(cert), verifyingClientConfig(pool, cfg.allowedDNS))
	if !isIncompatibleUsage(result.clientErr) {
		r.fail(report.CheckTLSServerRoleRejected,
			"a client-only certificate served for %q must be refused for an incompatible key usage; %s",
			cfg.allowedDNS, result)
		return
	}
	r.pass(report.CheckTLSServerRoleRejected,
		"the client refused the client-only certificate served for %q: %v", cfg.allowedDNS, result.clientErr)
}

// ephemeralPeerName is the identity of the throwaway counterparty.
const ephemeralPeerName = "credprobe-ephemeral-peer"

// ephemeralServerCertificate returns a throwaway self-signed server
// certificate, used as the counterparty in the client-authentication check.
//
// It is marked as a CA so the client can trust it directly by putting it in a
// root pool - a self-signed certificate present in Roots verifies as its own
// chain - which keeps certificate verification switched on at both ends of that
// handshake.
func ephemeralServerCertificate() (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: ephemeralPeerName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
		DNSNames:              []string{ephemeralPeerName},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse certificate: %w", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}
