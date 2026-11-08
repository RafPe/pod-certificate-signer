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
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// CA lifecycle.
//
// Everything else in this suite runs against one CA that never changes. These
// specs are about the CA itself moving: rotated, replaced with material the
// controller cannot use, reloaded across a restart, and published into a
// ClusterTrustBundle that something else has since damaged. The property under
// test throughout is that a workload holding a certificate issued a minute ago
// keeps verifying, and that nothing bad ever reaches the trust anchors every
// workload in the cluster mounts.
//
// They are declared last, after the ClusterTrustBundle context, for two
// reasons. They deliberately break the CA, so no spec that assumes a working
// signer may follow them inside the same install; and the container's BeforeAll
// rotates to a CA it generated, which re-creates the ClusterTrustBundle the
// preceding context's AfterAll deletes and gives every spec below a known
// starting point rather than whatever the run happened to leave behind.
//
// Cost and the CI partition. A CA change is not cheap: the secret write has to
// reach the controller through kubelet's mounted-secret refresh (a minute by
// default) before the reload can even start, so each rotation is on the order
// of a minute of wall time regardless of how fast the controller is. Only the
// rotation pair below is affordable on every pull request; the rest carry
// Label(nightlyLabel) and are excluded by `make test-e2e`'s default
// E2E_LABEL_FILTER. `make test-e2e-nightly` runs everything. That split is the
// one the coverage review specifies - PR keeps "one CA rotation plus
// post-rotation issuance", nightly takes invalid-CA recovery, repeated
// rotations and retention, restart bootstrap and CTB drift.

// nightlyLabel marks specs excluded from the per-PR e2e gate. See the Makefile's
// E2E_LABEL_FILTER and the note above.
const nightlyLabel = "nightly"

// caPropagationTimeout bounds the wait for a write to the CA secret to become
// observable in the controller.
//
// It is generous on purpose and is not a measure of how fast the controller is.
// A mounted secret is refreshed by kubelet on its sync period, a minute by
// default, and only then does the controller's file watcher see anything; the
// watcher additionally coalesces the write burst before reloading.
const caPropagationTimeout = 5 * time.Minute

// mountedTrustUpdateTimeout bounds the wait for a workload's projected
// ClusterTrustBundle to catch up with a rotation.
//
// This is NOT the mounted-secret refresh above - projected clusterTrustBundle
// sources go through a different kubelet cache with a different TTL, and
// conflating the two is what made this timeout too tight to begin with. The
// budget has two terms:
//
//   - kubelet's ClusterTrustBundle manager serves the projection from a
//     normalization cache with a hard-coded 5-minute TTL. For the `name` form
//     of the projection - which this suite uses, and which is the form that
//     pins trust to one named object - a bundle carrying a spec.signerName is
//     not invalidated by the informer's update callback, so the entry only
//     goes away when the TTL expires. There is no flag that shortens it.
//   - the refreshed content is written on the next pod sync
//     (--sync-frequency, 1 minute by default).
//
// Worst case is therefore ~6 minutes, and the phase of the cache entry when a
// rotation lands is arbitrary, so a 5-minute bound failed a large fraction of
// runs rather than all of them. 8 minutes is 6 plus headroom.
//
// Do not "fix" a failure here by switching the fixture to the signerName form.
// That converges in about one sync period because the informer does invalidate
// those entries, but it also changes what the projection trusts - one named
// object becomes a cluster-wide union of every bundle for that signer. A test
// change must not be the vehicle for a trust-model change.
const mountedTrustUpdateTimeout = 8 * time.Minute

// caLifecycleObserverHold is how long the rotation observer pod stays up. It has
// to outlive the pod's own issuance, a full rotation and the projected volume
// refresh that follows it, with room to spare - the spec reads the pod after all
// three.
const caLifecycleObserverHold = 1200

// caLifecycleValidity is how long the CAs these specs rotate to are valid for.
//
// It has to exceed the default certificate lifetime by a clear margin, and the
// margin is not cosmetic. The signer backdates notBefore by a minute and then
// adds the requested duration, so a certificate issued from a CA at time T for
// the default 24 hours ends at T + 24h - 1m; a CA generated moments earlier and
// valid for exactly 24 hours expires before that and cannot sign it at all. The
// request does not fail - authority returns ErrCASignerUnusable, which the
// reconciler treats as transient - it simply never issues, and the workload
// hangs in ContainerCreating. Nothing is written to the request itself either;
// the only trace on the object is the rate-limited CASignerUnusable warning
// event the reconciler emits on that branch.
//
// Three days leaves no doubt. The spec that wants an unsuitable CA asks for one
// explicitly; see shortCAValidity.
const caLifecycleValidity = 72 * time.Hour

// maxPreviousCACerts mirrors the chart's signer.max_previous_ca_certs default.
// The retention spec asserts against it rather than against a literal, so the
// spec says which setting it is describing.
const maxPreviousCACerts = 2

// shortCAValidity is the remaining lifetime of the CA used to make the signer
// unusable without making it unloadable.
//
// The distinction is the whole point of that spec and it is narrow. An
// already-expired CA is rejected by authority.load, so it would never become the
// current CA at all and the spec would silently be testing last-good retention
// instead. Half an hour loads comfortably, survives the propagation delay, and
// is still far shorter than the 24-hour lifetime a default request asks for, so
// signing fails with ErrCASignerUnusable.
const shortCAValidity = 30 * time.Minute

// Controller log lines the CA-lifecycle specs still count.
//
// Counting a log line is not the assertion; it is what makes the assertion
// about the right moment. A spec that only waited for "the bundle did not
// change" would pass against a controller that had not yet noticed the write at
// all, which is the false pass these lines rule out.
//
// Two of these greps are gone, replaced by metric samples (see
// metrics_scrape_test.go): a metric says what the controller *did*, where a log
// line says what it *said*, and the difference turned this suite red once
// already when a log level moved. The two below are deliberately not migrated,
// and neither is the immutability grep in outcomes_test.go:
//
//   - caReloadFailedLine is asserted together with classification and detail
//     needles that are standard-library error strings. They are unbounded and
//     unstable, which is exactly what a metric label may never carry, so a
//     metric could replace the count but never the claim that the controller
//     said *why* it refused the material. Half a migration invites the belief
//     that the migration is done.
//   - caBootstrapLine is emitted before the manager starts, so the metrics
//     endpoint is not listening when it happens. A gauge can show the history
//     is non-empty, but the spec's claim is provenance - that it came from the
//     published ClusterTrustBundle - and only the log line carries that.
const (
	// caReloadFailedLine is logged by authority.reportReload once a reload has
	// failed - after the retry budget on the event path, or on a single
	// periodic attempt. The error it carries names why, which is what
	// distinguishes the invalid-material cases from each other.
	caReloadFailedLine = "failed to reload CA certificate; retaining the last-good CA"

	// caBootstrapLine is logged by trustbundle.LoadPreviousCAHistory when a
	// starting process seeds its previous-CA history from the published
	// ClusterTrustBundle.
	caBootstrapLine = "bootstrapped previous CA certificates from ClusterTrustBundle"

	// terminalRequestLine is logged by the reconciler for every reconcile of a
	// request that already carries a terminal condition. Counting it is how a
	// spec proves the controller looked at the request and left it alone.
	terminalRequestLine = "request is already terminal"

	// publishedBundleLine is logged by trustbundle.Publisher after each
	// successful ClusterTrustBundle write.
	publishedBundleLine = "published ClusterTrustBundle"
)

// defineCALifecycleTests is called from the top-level Manager container, after
// the ClusterTrustBundle context. See the note at the top of this file.
func defineCALifecycleTests() {
	Context("CA lifecycle", func() {
		// caA is the CA the container starts from, caB the one it rotates to.
		// Both are read by specs after the one that created them - the retention
		// spec asserts on where each ends up in the window - which is why they
		// are container-scoped rather than local.
		//
		// Which CA is *current* at any point is not tracked here: rotateCA
		// records it, and currentCA reports it. One writer, so a spec cannot
		// rotate and forget to update the bookkeeping.
		var caA, caB *testutil.KeyPair

		BeforeAll(func() {
			By("authorizing the metrics scrapes these specs assert on")
			authorizeMetricsScrapes()

			By("rotating to a CA this container generated, so every spec below starts from a known one")
			caA = newLifecycleCA("ca-lifecycle-a")
			rotateCA(caA)
		})

		AfterAll(func() {
			By("removing the ClusterTrustBundle this container re-created")
			cmd := exec.Command("kubectl", "delete", "clustertrustbundle", trustBundleName, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})

		// The rotation pair is the per-PR half of this file: one rotation, and
		// proof that what the rotation produced is usable by a workload.
		It("rotates the issuing CA without breaking transitional trust", func() {
			By("issuing a certificate under the current CA")
			before := createCertTestPod(certTestPod{name: "pcs-ca-rotation-before"})
			chainBefore := expectIssued(before)
			Expect(chainBefore).To(HaveLen(defaultChainLength))
			leafBefore, issuerBefore := chainBefore[0], chainBefore[1]
			Expect(issuerBefore.Equal(caA.Cert)).To(BeTrue(),
				"the pre-rotation certificate must be signed by the pre-rotation CA")

			By("starting an observer pod that mounts the published trust anchors before the rotation")
			// Created now, read after the rotation. A pod created afterwards
			// would only prove that a fresh mount picks up the new bundle; the
			// claim that matters to a running workload is that the file it
			// already has open is updated underneath it.
			observer := createCertTestPod(certTestPod{
				name:                   "pcs-ca-rotation-observer",
				clusterTrustBundleName: trustBundleName,
				holdSeconds:            caLifecycleObserverHold,
			})
			expectPodRunning(observer)

			By("waiting for the observer's mounted anchors to agree with the published bundle")
			// The baseline is observed, not assumed. Asserting "CA A is mounted"
			// here looked equivalent and was not: the preceding context's
			// AfterAll deletes the ClusterTrustBundle and this container's
			// BeforeAll re-creates it by rotating, and a pod that mounts moments
			// after an object is deleted and re-created under the same name can
			// be given content from before the gap. That is a fact about the
			// projection's timing, not about rotation, and pinning CA A here made
			// the spec fail for it.
			//
			// What this spec actually needs is a "before" set it has seen with
			// its own eyes and that matches what the signer publishes. Waiting
			// for the mount and the bundle to agree gives exactly that, and the
			// claim below - the file changes in place when the CA rotates - is
			// unchanged and now rests on a baseline that was true.
			var anchorsBefore []string
			Eventually(func(g Gomega) {
				published := certificateFingerprints(getTrustBundleCertificates(g))
				g.Expect(published).NotTo(BeEmpty(), "the signer must publish a bundle to mount")
				mounted := certificateFingerprints(mountedTrustAnchors(g, observer))
				g.Expect(mounted).To(ConsistOf(published),
					"the observer's projected ca.crt must converge on the published bundle before the rotation")
				anchorsBefore = mounted
			}, mountedTrustUpdateTimeout).Should(Succeed())

			// Stated separately from the convergence above so a failure here says
			// "the bundle lost the current CA", not "the mount is behind".
			Expect(anchorsBefore).To(ContainElement(fingerprint(caA.Cert)),
				"the converged anchors must include the CA that is currently signing")

			By("rotating the CA")
			caB = newLifecycleCA("ca-lifecycle-b")
			rotateCA(caB)

			By("verifying the published bundle carries the new CA first and keeps the previous one")
			var overlap []*x509.Certificate
			Eventually(func(g Gomega) {
				overlap = getTrustBundleCertificates(g)
				g.Expect(overlap).NotTo(BeEmpty())
				g.Expect(overlap[0].Equal(caB.Cert)).To(BeTrue(),
					"the rotated CA must be published first")
				g.Expect(containsCertificate(overlap, caA.Cert)).To(BeTrue(),
					"the previous CA must stay published, or every certificate issued before the rotation stops verifying")
			}).Should(Succeed())

			By("issuing a certificate after the rotation")
			after := createCertTestPod(certTestPod{name: "pcs-ca-rotation-after"})
			chainAfter := expectIssued(after)
			Expect(chainAfter).To(HaveLen(defaultChainLength))
			leafAfter, issuerAfter := chainAfter[0], chainAfter[1]

			By("verifying the new certificate was signed by the new CA and not by the old one")
			Expect(issuerAfter.Equal(caB.Cert)).To(BeTrue(),
				"a certificate issued after the rotation must be served with the rotated CA")
			Expect(issuerAfter.Equal(caA.Cert)).To(BeFalse(),
				"the pre-rotation CA must no longer be the issuer")
			// The chain says which CA the controller *shipped*; the signature
			// says which one it *used*. Asserting only the former would pass for
			// a controller that signed with the old key and attached the new
			// certificate.
			Expect(leafAfter.CheckSignatureFrom(caB.Cert)).To(Succeed(),
				"the post-rotation leaf must actually be signed by the rotated CA's key")
			Expect(leafAfter.CheckSignatureFrom(caA.Cert)).NotTo(Succeed(),
				"the post-rotation leaf must not be signed by the pre-rotation CA's key")

			By("verifying certificates from both CAs verify against the overlap bundle")
			expectVerifiesAgainst(leafBefore, overlap,
				"a certificate issued before the rotation must still verify against the published anchors")
			expectVerifiesAgainst(leafAfter, overlap,
				"a certificate issued after the rotation must verify against the published anchors")

			By("verifying the observer's mounted ca.crt was updated in place")
			wantAnchors := certificateFingerprints(overlap)
			Expect(anchorsBefore).NotTo(ConsistOf(wantAnchors),
				"the rotation must change the published anchors, otherwise the next assertion proves nothing")
			Eventually(func(g Gomega) {
				g.Expect(certificateFingerprints(mountedTrustAnchors(g, observer))).To(ConsistOf(wantAnchors),
					"the running workload's projected ca.crt must catch up with the published bundle")
			}, mountedTrustUpdateTimeout).Should(Succeed())
		})

		It("hands a workload a usable credential under the rotated CA", func() {
			const podName = "pcs-ca-rotation-probe"
			Expect(caB).NotTo(BeNil(), "this spec continues from the rotation spec above; run the container whole")

			By("running the credential probe as a workload issued after the rotation")
			pod := createCertTestPod(certTestPod{
				name:                   podName,
				image:                  workloadProbeImage,
				args:                   probeArgs(podName, report.RoleServer),
				clusterTrustBundleName: trustBundleName,
			})
			chain := expectIssued(pod)
			Expect(chain).To(HaveLen(defaultChainLength))
			Expect(chain[1].Equal(caB.Cert)).To(BeTrue(),
				"the probe's credential must be issued under the rotated CA")

			By("waiting for the pod to run with the projected credential")
			expectPodRunning(pod)

			By("verifying the workload can use the post-rotation credential for real TLS")
			observed := expectProbeReport(pod, report.RoleServer)
			Expect(observed.Facts.ChainSHA256).To(Equal(certificateFingerprints(chain)),
				"the projected bundle must carry exactly the chain the request published")

			By("verifying the workload still trusts certificates issued before the rotation")
			Expect(observed.Facts.TrustSHA256).To(ContainElement(fingerprint(caB.Cert)),
				"the workload must trust the CA that signed its own certificate")
			Expect(observed.Facts.TrustSHA256).To(ContainElement(fingerprint(caA.Cert)),
				"the workload must still trust the previous CA, or its peers' pre-rotation certificates fail")
		})

		Context("Controller restart", Label(nightlyLabel), func() {
			It("bootstraps the previous-CA history from the published bundle and keeps the current CA", func() {
				current := currentCA()

				By("capturing the published bundle before the restart")
				var publishedBefore []string
				Eventually(func(g Gomega) {
					publishedBefore = certificateFingerprints(getTrustBundleCertificates(g))
					g.Expect(publishedBefore).NotTo(BeEmpty())
				}).Should(Succeed())

				restartController()

				By("verifying the new process seeded its CA history from the ClusterTrustBundle")
				// Nothing else carries the history across a restart: the previous
				// CAs live only in the process's memory and in this bundle.
				Eventually(func(g Gomega) {
					g.Expect(controllerLogLineCount(caBootstrapLine)).To(BeNumerically(">", 0),
						"the restarted controller must read its previous-CA history from the published bundle")
				}).Should(Succeed())

				By("verifying the republished bundle is the one that was there before")
				Eventually(func(g Gomega) {
					certs := getTrustBundleCertificates(g)
					g.Expect(certs).NotTo(BeEmpty())
					g.Expect(certs[0].Equal(current.Cert)).To(BeTrue(),
						"the restarted controller must keep the current CA current")
					g.Expect(certificateFingerprints(certs)).To(ConsistOf(publishedBefore),
						"a restart must neither drop nor invent trust anchors")
				}).Should(Succeed())

				By("verifying the restarted controller signs with the current CA")
				pod := createCertTestPod(certTestPod{name: "pcs-ca-restart-issue"})
				chain := expectIssued(pod)
				Expect(chain).To(HaveLen(defaultChainLength))
				Expect(chain[1].Equal(current.Cert)).To(BeTrue(),
					"a restart must not change which CA signs")
				Expect(chain[0].CheckSignatureFrom(current.Cert)).To(Succeed())

				expectControllerReady()
			})
		})

		Context("Previous-CA retention", Label(nightlyLabel), func() {
			It("bounds the history, evicts the oldest CA and survives a restart", func() {
				Expect(caA).NotTo(BeNil())
				Expect(caB).NotTo(BeNil(),
					"the window this spec asserts on is built by the rotations above; run the container whole")

				By("rotating past the retention bound")
				caC := newLifecycleCA("ca-lifecycle-c")
				rotateCA(caC)
				caD := newLifecycleCA("ca-lifecycle-d")
				rotateCA(caD)

				// Ordering is not arbitrary and is worth pinning. authority.load
				// appends the outgoing CA to the history and then keeps the
				// *last* maxPreviousCerts entries, so the published bundle is the
				// current CA followed by the retained ones oldest-first. After
				// rotating A -> B -> C -> D with a bound of two, that is
				// [D, B, C]: A has been pushed out of the window.
				expectRetainedHistory := func(g Gomega) {
					certs := getTrustBundleCertificates(g)
					g.Expect(certs).To(HaveLen(maxPreviousCACerts+1),
						"the bundle must be the current CA plus at most %d previous ones", maxPreviousCACerts)
					g.Expect(certs[0].Equal(caD.Cert)).To(BeTrue(),
						"the current CA must be published first")
					g.Expect(certs[1].Equal(caB.Cert)).To(BeTrue(),
						"the retained CAs must follow the current one oldest-first")
					g.Expect(certs[2].Equal(caC.Cert)).To(BeTrue(),
						"the most recently retired CA must be last")
					g.Expect(containsCertificate(certs, caA.Cert)).To(BeFalse(),
						"the oldest CA must be evicted once the window is full")

					fingerprints := certificateFingerprints(certs)
					g.Expect(fingerprints).To(HaveLen(len(uniqueStrings(fingerprints))),
						"the bundle must never publish the same CA twice: %v", fingerprints)
				}
				Eventually(expectRetainedHistory).Should(Succeed())

				By("restarting the controller and verifying the bound and the ordering survive")
				// Re-asserting the same set after a restart is not redundant with
				// the check above, and the length assertion least of all. A
				// starting process seeds its history from whatever the published
				// bundle says, and that path applies no bound of its own -
				// maxPreviousCerts is enforced in authority.load's rotate branch
				// and nowhere else. The bound surviving a restart is therefore a
				// property of the bundle having been correct, not of the bootstrap
				// enforcing anything. Do not delete this as a duplicate.
				restartController()
				Eventually(expectRetainedHistory).Should(Succeed())

				By("verifying the restarted controller signs with the current CA")
				pod := createCertTestPod(certTestPod{name: "pcs-ca-retention-issue"})
				chain := expectIssued(pod)
				Expect(chain).To(HaveLen(defaultChainLength))
				Expect(chain[1].Equal(caD.Cert)).To(BeTrue())
			})
		})

		defineCAFailureModeTests()
	})
}
