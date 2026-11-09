//go:build e2e
// +build e2e

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

package e2e

import (
	"crypto/x509"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
)

// Interoperability with a real TLS workload.
//
// Every other spec in this suite judges the signer against itself. The request
// status is read from outside the cluster, and the credential-conformance specs
// close half the remaining gap by having the workload use its own credential -
// but the probe is both ends of that handshake, so what it proves is that the
// material is well-formed and internally consistent. Nothing so far shows that
// an independent peer *accepts* an identity this signer issued.
//
// These specs close that. The server is goweb-https, software from another
// repository that knows nothing about this one: it serves HTTPS from the
// projected credential bundle, verifies client certificates against the
// projected ClusterTrustBundle, and publishes what it loaded and when. The
// clients are credprobe pods in the peer role. Every verdict below is goweb's,
// read out of its own diagnostic endpoints and judged here against the
// PodCertificateRequest status - so, as everywhere else in this suite, neither
// half grades its own homework.
//
// The spec that justifies the whole file is the rotation one. ca_lifecycle_test.go
// already proves transitional trust *structurally*, by comparing fingerprint
// sets across a rotation. This proves it *functionally*: a client holding a
// certificate issued under the new CA authenticates to a server that was
// started before the rotation, a client holding one from the previous CA still
// authenticates, and neither pod restarts.
//
// Placement. This container is declared last, after every other container in
// the Manager Describe, and that is not a matter of taste. It rotates the CA,
// and the previous-CA retention spec in ca_lifecycle_test.go asserts an exact
// rotation history - after A -> B -> C -> D with a bound of two, the published
// bundle must be [D, B, C]. A rotation inserted anywhere before it changes that
// arithmetic and fails a spec that has nothing to do with this file. Declared
// last, nothing follows that a rotation here can disturb.
//
// Cost. Every spec carries Label(nightlyLabel): the container pays a Helm
// rollout, several issuances and - in the rotation spec - one full
// mountedTrustUpdateTimeout window, which is minutes of wall time that the
// per-PR tier has no room for.

// gowebImage is the TLS workload these specs run.
//
// Pinned by digest, not by tag. A tag makes the suite non-reproducible and hands
// an unrelated repository's release the ability to turn this one red: the image
// behind :latest can change between the run that passed and the run that did
// not, with nothing in this repository's history to explain the difference.
//
// This is the multi-architecture index digest, so it resolves to the right
// manifest on an arm64 laptop and an amd64 CI runner alike; pinning a
// per-platform manifest digest would break one of the two.
//
// To refresh it:
//
//	docker buildx imagetools inspect ghcr.io/rafpe/goweb-https/server:latest
//
// and take the top-level "Digest:" line. Re-read the environment variables and
// the /status.json and /whoami.json field names below when you do - they are
// that image's contract, and this file is a consumer of it.
const gowebImage = "ghcr.io/rafpe/goweb-https/server@sha256:9173587079415499d100659a18b4fcfc58014a38a55ce74432a34cf6db6b2e60"

// The goweb server's identity. The Service is named after the pod deliberately:
// the signer's default SANs are <pod>.<namespace>.pod.cluster.local and
// <pod>.<namespace>.svc.cluster.local, and only the second is resolvable - and
// only if a Service of that name selects the pod. Naming them alike is what lets
// a client dial a name the certificate actually carries, rather than dialling a
// pod IP and turning off the hostname check that is half the point of TLS.
const (
	gowebServerPodName = "pcs-goweb-server"
	gowebClientPodName = "pcs-goweb-client"
	gowebRotatedClient = "pcs-goweb-client-rotated"

	// gowebPort is the port goweb listens on; it is goweb's own default, set
	// explicitly so the fixture and the URL cannot drift apart.
	gowebPort = 8443

	// gowebSelectorLabel carries the pod name, so the Service selects exactly
	// this pod and not every workload the suite has created.
	gowebSelectorLabel = "e2e.pod-certificate-signer/goweb"

	// gowebClientServiceAccount is the identity the client pods run as.
	//
	// It exists so the client's SPIFFE ID differs from the server's. Both would
	// otherwise run as "default" and resolve to the same URI, and a spec
	// asserting that goweb reported the client's identity would be satisfied by
	// a server echoing its own.
	gowebClientServiceAccount = "pcs-goweb-client"
)

// goweb's reload knobs, set far below their defaults.
//
// This is what makes the reload-latency spec able to say anything. goweb's
// observed convergence after a rotation is two independent terms added
// together - kubelet propagating the new ClusterTrustBundle into the projected
// volume, then goweb noticing the file changed and re-reading it - and with the
// stock 30-second reconcile interval the second term is large enough to be
// mistaken for the first. Turned down to seconds, goweb's own contribution is
// bounded by configuration, and what remains is kubelet's.
const (
	gowebReloadDebounce = "200ms"
	gowebReloadInterval = "2s"
)

// gowebOwnReloadBudget bounds the term this file attributes to goweb: the time
// from the projected file changing to goweb serving the new anchors.
//
// The configured worst case is the debounce plus one reconcile interval, 2.2
// seconds. The rest of this budget is measurement overhead and nothing to do
// with goweb: the file change is observed by polling `cat` through `kubectl
// exec`, and the reload by polling /status.json through another, so each
// endpoint of the interval is quantised by a poll period and a round trip.
//
// It is emphatically *not* a bound on kubelet, which is measured separately and
// is minutes rather than seconds. See the rotation spec.
const gowebOwnReloadBudget = 20 * time.Second

// gowebObserverHold is how long the sidecar and the client probes stay up.
//
// It has to outlive the whole container, not just one spec: the client created
// in BeforeAll is re-exec'd by the last spec, after a rotation and a full
// mountedTrustUpdateTimeout window. A container that exits early is worse than
// a timeout - the pod stops being Ready, drops out of the Service's endpoints,
// and the failure surfaces as unresolvable DNS with nothing to say why.
const gowebObserverHold = 3600

// gowebServeTimeout bounds the wait for goweb to answer its first request. It
// covers pulling the image, which - unlike every other image in this suite - is
// pulled from a registry by the node rather than loaded into Kind.
const gowebServeTimeout = 5 * time.Minute

// gowebSpiffeURI is the SPIFFE ID template both pods request. Under the
// verified-interpolation profile the resolved value still has to clear the
// verified-identity allowlist, so an issued certificate carrying it is itself an
// assertion (see ADR-0001).
const gowebSpiffeURI = "spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}"

// defineGowebInteropTests is called last from the Manager Describe. See the
// placement note above before moving it.
func defineGowebInteropTests() {
	Context("Interoperability with a real TLS workload", Label(nightlyLabel), func() {
		var (
			// serverLeaf is the certificate goweb serves, as the request status
			// published it. Every assertion about what goweb reports is made
			// against this rather than against goweb's own account of itself.
			serverLeaf *x509.Certificate

			// baselineCA is the CA current while the server and the first client
			// were issued. The rotation spec needs it to state which clients
			// hold pre-rotation certificates.
			baselineCA *x509.Certificate

			server, client podRef
		)

		BeforeAll(func() {
			By("installing the profile these specs describe")
			// Interpolation on with the identity constraints still enforced.
			// This is the only profile in which every spec below is expressible
			// at once: the default DNS SANs a server needs, the eku=client
			// opt-in a client needs, and a SPIFFE URI that has to clear the
			// verified-identity allowlist on its own merits. Using one profile
			// costs one rollout instead of three.
			installProfile(verifiedInterpolationInstallArgs)

			By("waiting for the signer to publish its ClusterTrustBundle")
			var anchors []*x509.Certificate
			Eventually(func(g Gomega) {
				anchors = getTrustBundleCertificates(g)
				g.Expect(anchors).NotTo(BeEmpty(), "the trust bundle must carry the current CA")
			}).Should(Succeed())
			baselineCA = anchors[0]

			By("verifying every published anchor is one goweb can load as a client CA")
			// A precondition, not a claim about the signer, and it is here to
			// convert one specific mystery into a diagnosis. goweb validates
			// every anchor in its client CA file at startup and refuses to start
			// if any one of them fails - so a single unusable certificate left in
			// the bundle by a preceding container reaches this file as a pod
			// stuck in CrashLoopBackOff, minutes into a nightly run, looking for
			// all the world like an image-pull problem.
			expectAnchorsUsableAsClientCAs(anchors)

			By("creating the service account the client pods run as")
			createGowebClientServiceAccount()

			By("starting the goweb server with the projected credential and trust bundle")
			server = createGowebServer()

			By("waiting for the server's PodCertificateRequest to be issued")
			serverChain := expectIssued(server)
			Expect(serverChain).To(HaveLen(defaultChainLength))
			serverLeaf = serverChain[0]
			Expect(serverChain[1].Equal(baselineCA)).To(BeTrue(),
				"the server's certificate must be issued under the CA the bundle currently leads with")

			By("publishing a Service so the server is reachable at a name its certificate carries")
			createGowebService()

			By("starting a client whose certificate carries a SPIFFE identity")
			client = createGowebClient(gowebClientPodName)
			expectIssued(client)

			By("waiting for both pods to run with their projected credentials")
			expectPodRunning(server)
			expectPodRunning(client)

			By("waiting for the server to answer over TLS")
			// Deliberately the first real request rather than a readiness probe
			// on the pod. goweb has no probe configured, so it is Ready as soon
			// as its container starts and its Service endpoint appears
			// immediately; an HTTPS probe would add a failure surface that
			// manifests as unresolvable DNS. Waiting on an actual answer here
			// proves DNS, routing, the listener and the trust chain in one, and
			// does it once instead of in every spec.
			Eventually(func(g Gomega) {
				gowebStatus(g, client)
			}, gowebServeTimeout).Should(Succeed())
		})

		It("serves real TLS to another pod, with the certificate the signer issued", func() {
			By("reading the server's own account of the certificate it is serving")
			var status gowebStatusDocument
			Eventually(func(g Gomega) {
				status = gowebStatus(g, client)
			}).Should(Succeed())

			Expect(status.Certificate).NotTo(BeNil(),
				"the server must report the certificate it is serving")

			By("verifying it is byte-for-byte the leaf the request status published")
			// The fingerprint is the whole claim. A subject or a SAN could match
			// while the served certificate was some other one carrying the same
			// fields; the fingerprint cannot.
			Expect(status.Certificate.FingerprintSHA256).To(Equal(fingerprint(serverLeaf)),
				"goweb must be serving exactly the certificate the PodCertificateRequest published")

			By("verifying the names it serves are the ones the signer put in the certificate")
			Expect(status.Certificate.DNSNames).To(ConsistOf(serverLeaf.DNSNames))
			Expect(status.Certificate.DNSNames).To(ContainElement(gowebServerDNSName()),
				"the client reached the server at this name, so the certificate must carry it")
			Expect(status.Certificate.URIs).To(ConsistOf(certificateURIs(serverLeaf)))
			Expect(status.Certificate.Validity).To(Equal("valid"),
				"the served certificate must be within its validity window")

			// The client verified that certificate against the projected anchors
			// and nothing else: the peer probe sets RootCAs to the projected
			// ca.crt alone, so a decoded status document at all means the chain
			// built and the hostname matched. gowebStatus already requires the
			// 200 that proves it, which is why there is no further assertion
			// here - one restating it would read as a check and test nothing.
		})

		It("authenticates a client by the SPIFFE identity the signer issued it", func() {
			By("verifying the client holds the SPIFFE identity this spec is about")
			clientLeaf := expectIssued(client)[0]
			Expect(clientLeaf.URIs).To(HaveLen(1))
			wantURI := fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s",
				workloadNamespace, gowebClientServiceAccount)
			Expect(clientLeaf.URIs[0].String()).To(Equal(wantURI))

			By("asking the server who the client is")
			var whoami gowebWhoamiDocument
			Eventually(func(g Gomega) {
				whoami = gowebWhoami(g, client, report.PeerModeProjected, http200)
			}).Should(Succeed())

			By("verifying the server accepted the identity rather than merely receiving it")
			// This is the assertion nothing else in the suite makes. Every other
			// spec proves an identity was *issued*; this proves a peer that has
			// never heard of this signer verified it, chained it to the published
			// trust anchors and reported it back.
			Expect(whoami.Authenticated).To(BeTrue(),
				"the server must authenticate a client whose certificate chains to the published anchors")
			Expect(whoami.Client).NotTo(BeNil())
			Expect(whoami.Client.URIs).To(ConsistOf(wantURI),
				"the server must report the SPIFFE ID the signer issued, not one of its own")
			Expect(whoami.Client.FingerprintSHA256).To(Equal(fingerprint(clientLeaf)),
				"the authenticated certificate must be the one the request status published")
			Expect(whoami.Client.Chain).NotTo(BeEmpty(),
				"an authenticated client must have a verified chain")
		})

		It("refuses an unauthenticated client and an untrusted one, differently", func() {
			// The two negatives fail in different places and must be asserted
			// differently. goweb verifies client certificates with
			// tls.VerifyClientCertIfGiven: a client offering nothing completes
			// the handshake and is refused by the application, while a client
			// offering a certificate that does not chain is refused during the
			// handshake and never reaches a handler at all. Asserting both as
			// "the request did not succeed" would pass for a server that was
			// simply unreachable, which is the false pass this spec exists to
			// rule out.

			By("presenting no client certificate at all")
			var whoami gowebWhoamiDocument
			Eventually(func(g Gomega) {
				whoami = gowebWhoami(g, client, report.PeerModeNone, http403)
			}).Should(Succeed())

			Expect(whoami.Authenticated).To(BeFalse())
			Expect(whoami.Reason).To(Equal("no client certificate presented"),
				"the refusal must name why, so it cannot be confused with any other 403")

			By("presenting a certificate no CA in this cluster ever signed")
			var facts report.PeerFacts
			Eventually(func(g Gomega) {
				facts = gowebPeerRequest(g, client, report.PeerModeForeign, gowebWhoamiURL())
			}).Should(Succeed())

			By("verifying the server rejected it in the handshake, and did not merely fail to answer")
			Expect(facts.Connected).To(BeTrue(),
				"the connection must have been established, or this proves nothing about the server's decision")
			Expect(facts.HTTPStatus).To(BeZero(),
				"an untrusted certificate must be refused before any handler runs, so there is no response")
			Expect(facts.TLSAlert).To(BeTrue(),
				"the refusal must be a TLS alert from the server: %s", facts.Error)
			// A Go peer sends unknown_certificate_authority for a chain it cannot
			// build. bad_certificate is the other refusal a server may
			// reasonably choose, so both are admitted - the claim is that the
			// certificate was rejected, not which alert says so.
			Expect(facts.TLSAlertText).To(SatisfyAny(
				ContainSubstring("unknown certificate authority"),
				ContainSubstring("bad certificate"),
			), "the alert must name the certificate as the reason: %s", facts.Error)
		})

		It("keeps authenticating across a CA rotation, hot-reloading trust without a restart", func() {
			// The spec this file exists for. ca_lifecycle_test.go proves the
			// published bundle carries both CAs across a rotation; this proves
			// what that is *for* - that a running server picks the new anchors up
			// from a file changing underneath it, starts accepting clients issued
			// under the new CA, and keeps accepting the ones issued under the
			// old, all without either process being restarted.

			By("recording what the server looked like before the rotation")
			var before gowebStatusDocument
			Eventually(func(g Gomega) {
				before = gowebStatus(g, client)
			}).Should(Succeed())
			Expect(before.TrustBundle).NotTo(BeNil(),
				"the server must report the trust bundle it enforces")
			Expect(before.TrustBundle.Anchors).NotTo(BeEmpty())
			Expect(anchorFingerprints(before)).To(ContainElement(fingerprint(baselineCA)),
				"the server must start out trusting the CA its client was issued under")

			By("verifying the pre-rotation client authenticates today")
			// The baseline for the "still authenticates" claim below. Without it
			// a client that never worked would look like one that survived.
			Eventually(func(g Gomega) {
				g.Expect(gowebWhoami(g, client, report.PeerModeProjected, http200).Authenticated).To(BeTrue())
			}).Should(Succeed())

			By("rotating the issuing CA")
			rotationStarted := time.Now()
			rotated := newLifecycleCA("goweb-interop-rotated")
			rotateCA(rotated)
			Expect(rotated.Cert.Equal(baselineCA)).To(BeFalse(),
				"the rotation must change the CA, or nothing below proves anything")

			By("waiting for kubelet to write the new anchors into the server's projected volume")
			// Term one of the latency, and the large one. This is kubelet
			// propagating a changed ClusterTrustBundle into a mounted projected
			// volume, which goes through a normalization cache with a hard-coded
			// five-minute TTL plus a pod sync - see mountedTrustUpdateTimeout.
			// None of it is goweb's, and none of it is this signer's.
			//
			// It is read out of the sidecar because the goweb image is distroless
			// and has no cat. The sidecar mounts the same volume, so this is the
			// same projection the server is reading.
			var fileChanged time.Time
			Eventually(func(g Gomega) {
				mounted := certificateFingerprints(observerTrustAnchors(g, server))
				g.Expect(mounted).To(ContainElement(fingerprint(rotated.Cert)),
					"the projected trust anchors must catch up with the published bundle")
				fileChanged = time.Now()
			}, mountedTrustUpdateTimeout, 5*time.Second).Should(Succeed())

			By("waiting for the server to reload the trust bundle it enforces")
			// Term two, and the only one that is goweb's. Measured from the file
			// changing rather than from the rotation, which is the whole point:
			// attributing the wait above to goweb would report a reload latency
			// of minutes for software that reconciles every two seconds.
			var after gowebStatusDocument
			var reloaded time.Time
			Eventually(func(g Gomega) {
				after = gowebStatus(g, client)
				g.Expect(after.TrustBundle).NotTo(BeNil())
				g.Expect(anchorFingerprints(after)).To(ContainElement(fingerprint(rotated.Cert)),
					"the server must enforce the rotated CA once its file carries it")
				// Set equality, not just containment. A server that only ever
				// added anchors would satisfy the check above forever and would
				// never apply a removal - and removing a CA from the published
				// bundle is how this signer expresses revocation. Converging on
				// exactly the published set is the property that makes the
				// overlap window bounded rather than permanent.
				g.Expect(anchorFingerprints(after)).To(
					ConsistOf(certificateFingerprints(getTrustBundleCertificates(g))),
					"the server must enforce exactly the anchors the signer publishes")
				reloaded = time.Now()
			}, gowebOwnReloadBudget+time.Minute, time.Second).Should(Succeed())

			gowebTerm := reloaded.Sub(fileChanged)
			kubeletTerm := fileChanged.Sub(rotationStarted)
			AddReportEntry("trust propagation split", fmt.Sprintf(
				"kubelet %s, goweb %s (goweb configured for debounce %s + interval %s)",
				kubeletTerm.Round(time.Second), gowebTerm.Round(time.Second),
				gowebReloadDebounce, gowebReloadInterval))

			By("verifying the server's own reload was quick, whatever kubelet took")
			// A non-positive value is normal and not an error: both endpoints are
			// polled, so goweb can be observed serving the new anchors before the
			// poll that notices the file changed. The assertion is an upper bound
			// on goweb's term only.
			Expect(gowebTerm).To(BeNumerically("<=", gowebOwnReloadBudget),
				"the server's own reload must be bounded by its configured debounce and interval; "+
					"kubelet's propagation took %s and is not part of this", kubeletTerm)

			By("verifying the reload is visible as a fresh load, not a stale cache")
			Expect(after.TrustBundle.LoadedAt).To(BeTemporally(">", before.TrustBundle.LoadedAt),
				"a rotation must advance the time the enforced bundle was loaded")
			Expect(after.TrustBundle.LastError).To(BeEmpty(),
				"the reload must have succeeded, not been retained after a failure")
			Expect(after.TrustBundle.StaleSeconds).To(BeNumerically("<=", int64(gowebOwnReloadBudget.Seconds())),
				"the server must be reading its trust bundle continuously, or LoadedAt says little")

			By("verifying neither process restarted")
			// The claim is about hot reload, so a restart anywhere invalidates
			// it. started_at is the load-bearing half: a container can be
			// restarted and still report restartCount 0 in a race, but a new
			// process cannot report the old start time.
			Expect(after.Server.StartedAt).To(BeTemporally("==", before.Server.StartedAt),
				"the server process must be the one that was running before the rotation")
			expectNoRestarts(server)
			expectNoRestarts(client)

			By("verifying a client issued under the new CA authenticates")
			rotatedClient := createGowebClient(gowebRotatedClient)
			rotatedLeaf := expectIssued(rotatedClient)[0]
			Expect(rotatedLeaf.CheckSignatureFrom(rotated.Cert)).To(Succeed(),
				"the new client's certificate must actually be signed by the rotated CA")
			expectPodRunning(rotatedClient)

			Eventually(func(g Gomega) {
				identified := gowebWhoami(g, rotatedClient, report.PeerModeProjected, http200)
				g.Expect(identified.Authenticated).To(BeTrue(),
					"a client issued under the rotated CA must authenticate to a server that never restarted")
				g.Expect(identified.Client.FingerprintSHA256).To(Equal(fingerprint(rotatedLeaf)))
			}, gowebServeTimeout).Should(Succeed())

			By("verifying the client issued under the previous CA still authenticates")
			// The other half of transitional trust, and the half that makes
			// rotation survivable: the previous CA stays in the overlap bundle,
			// so certificates issued under it keep working until they expire.
			Eventually(func(g Gomega) {
				surviving := gowebWhoami(g, client, report.PeerModeProjected, http200)
				g.Expect(surviving.Authenticated).To(BeTrue(),
					"a certificate issued before the rotation must keep authenticating "+
						"while its CA remains in the published bundle")
			}).Should(Succeed())

			By("verifying the server trusts both CAs at once, which is why both clients work")
			Expect(anchorFingerprints(after)).To(ContainElement(fingerprint(rotated.Cert)))
			Expect(anchorFingerprints(after)).To(ContainElement(fingerprint(baselineCA)))

			By("verifying neither process restarted while all of that happened")
			expectNoRestarts(server)
			expectNoRestarts(client)
		})
	})
}
