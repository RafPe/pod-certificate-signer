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
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
// hangs in ContainerCreating with nothing on the request to say why.
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
	// caReloadFailedLine is logged by authority.watchLoop once a reload has
	// exhausted its retry budget. The error it carries names why, which is what
	// distinguishes the invalid-material cases from each other.
	caReloadFailedLine = "failed to reload CA certificate after retries"

	// caBootstrapLine is logged by fetchPreviousCAs when a starting process
	// seeds its previous-CA history from the published ClusterTrustBundle.
	caBootstrapLine = "bootstrapped previous CA certificates from ClusterTrustBundle"
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

		Context("Unusable replacement material", Label(nightlyLabel), func() {
			// The guarantee under test is that a bad write is inert. The
			// controller keeps the last CA that loaded, keeps signing with it,
			// keeps publishing exactly the bundle it had, and recovers on its own
			// as soon as loadable material returns - all without a restart and
			// without a single certificate signed from the material that failed.
			//
			// Each case restores the last-good material before the next one runs.
			// That is not tidiness: authority.recordReloadResult starts the
			// failure clock at the first failure of a streak and only a
			// successful load clears it, so four cases chained back to back would
			// share one streak and eventually cross the readiness grace period -
			// making a legitimate readiness failure look like a flake. Restoring
			// per case is also what makes "recovery is automatic" a per-case
			// assertion rather than one at the end.
			DescribeTable("keeps the last-good CA and never publishes what it could not load",
				func(podName string, material func() (certPEM, keyPEM []byte), wantClassification, wantDetail string) {
					good := currentCA()

					By("capturing the published bundle before the bad write")
					publishedBefore := trustBundleRaw(Default)
					Expect(publishedBefore).NotTo(BeEmpty(), "there must be a published bundle to protect")
					failuresBefore := controllerLogLineCount(caReloadFailedLine, wantClassification, wantDetail)

					By("writing unusable material into the CA secret")
					certPEM, keyPEM := material()
					applyCAMaterial(certPEM, keyPEM)

					By("waiting for the controller to reject the replacement, naming why")
					// Both the classification and the detail are required. The
					// first three cases all fail inside tls.LoadX509KeyPair and
					// share the "failed to load key pair" wrapper, so a spec that
					// matched only the wrapper would pass for the wrong reason -
					// an invalid key would satisfy the mismatched-pair case.
					Eventually(func(g Gomega) {
						g.Expect(controllerLogLineCount(caReloadFailedLine, wantClassification, wantDetail)).
							To(BeNumerically(">", failuresBefore),
								"the controller must report the reload failure and say it was %q (%s)",
								wantDetail, wantClassification)
					}, caPropagationTimeout).Should(Succeed())

					By("verifying the ClusterTrustBundle is byte-for-byte what it was")
					// Compared as raw text rather than as parsed certificates:
					// unusable material has no parseable form to go looking for,
					// so the only way to state "nothing leaked into the bundle"
					// is that the bundle did not change at all. This also catches
					// a truncated or partially rewritten bundle, which a
					// certificate-set comparison would not.
					Consistently(func(g Gomega) {
						g.Expect(trustBundleRaw(g)).To(Equal(publishedBefore),
							"material the controller refused to load must never reach the published trust anchors")
					}, 15*time.Second, 3*time.Second).Should(Succeed())

					By("verifying the last-good CA is still signing")
					pod := createCertTestPod(certTestPod{name: podName})
					chain := expectIssued(pod)
					Expect(chain).To(HaveLen(defaultChainLength))
					Expect(chain[1].Equal(good.Cert)).To(BeTrue(),
						"a failed reload must leave the previous CA in place, not half-apply the new one")
					Expect(chain[0].CheckSignatureFrom(good.Cert)).To(Succeed(),
						"the certificate must be signed by the last-good CA's key")

					By("verifying readiness matches the documented contract")
					// authority.Healthy fails readiness only once reloads have
					// failed at least reloadFailureThreshold times *and* have been
					// failing for reloadFailureGracePeriod (ten minutes). A single
					// bad write crosses the first and not the second, so the
					// replica deliberately stays Ready: the last-good CA is intact
					// and pulling the only replica out of service would turn a
					// recoverable write into an outage.
					expectControllerStaysReady()

					By("restoring loadable material and verifying recovery needs no restart")
					// Asserted on the metrics endpoint rather than on a log
					// line. The claim is behavioural - "a good write after a bad
					// one reloads on its own" - but the old assertion was
					// written against a log level and an emission condition, so
					// changing when the controller logs turned this spec red for
					// no behavioural reason. That is the wrong coupling.
					//
					// The observable is the last-success timestamp, not the
					// changed counter: restoring the material the signer already
					// had is a successful reload that changes nothing, which is
					// precisely the recovery case. The streak returning to zero
					// is the same fact from the readiness side.
					var successBefore float64
					Eventually(func(g Gomega) {
						successBefore = scrapeMetricValue(g, caReloadLastSuccessGauge)
					}, caPropagationTimeout, metricsScrapePollInterval).Should(Succeed())

					applyCAMaterial(good.CertPEM, good.KeyPEM)
					Eventually(func(g Gomega) {
						body := scrapeControllerMetrics(g)
						g.Expect(metricValue(g, body, caReloadLastSuccessGauge)).To(BeNumerically(">", successBefore),
							"a good write after a bad one must reload on its own")
						g.Expect(metricValue(g, body, caReloadFailuresGauge)).To(BeZero(),
							"a successful reload must clear the failure streak, so readiness recovers without a restart")
					}, caPropagationTimeout, metricsScrapePollInterval).Should(Succeed())

					By("verifying the published bundle came back unchanged")
					// Restoring the same CA is not a rotation, so the history must
					// not move either - hence the raw comparison rather than just
					// a leading-certificate check.
					expectTrustBundleLeader(good.Cert)
					Expect(trustBundleRaw(Default)).To(Equal(publishedBefore),
						"recovering must republish exactly the bundle that was current before the bad write")
				},
				Entry("a certificate and a key that do not belong together",
					"pcs-ca-bad-mismatch",
					func() ([]byte, []byte) {
						// Two individually valid CAs, crossed. Nothing about
						// either file is malformed, which is what makes this the
						// case a PEM-shape check would miss.
						return currentCA().CertPEM, newLifecycleCA("ca-lifecycle-mismatch").KeyPEM
					},
					"failed to load key pair", "private key does not match public key"),
				Entry("a certificate that is not PEM at all",
					"pcs-ca-bad-cert-pem",
					func() ([]byte, []byte) {
						return []byte("this is not a certificate\n"), currentCA().KeyPEM
					},
					"failed to load key pair", "failed to find any PEM data in certificate input"),
				Entry("a key that is not PEM at all",
					"pcs-ca-bad-key-pem",
					func() ([]byte, []byte) {
						return currentCA().CertPEM, []byte("this is not a private key\n")
					},
					"failed to load key pair", "failed to find any PEM data in key input"),
				Entry("a well-formed certificate that is not a CA",
					"pcs-ca-bad-non-ca",
					func() ([]byte, []byte) {
						leaf := newLifecycleNonCA("ca-lifecycle-not-a-ca")
						return leaf.CertPEM, leaf.KeyPEM
					},
					"certificate is not a valid CA certificate", "certificate is not a valid CA certificate"),
			)

			It("leaves a request pending rather than failed while the CA cannot cover the lifetime", func() {
				By("rotating to a CA that loads but expires before a default certificate would")
				short, err := testutil.NewCA("ca-lifecycle-short", shortCAValidity)
				Expect(err).NotTo(HaveOccurred(), "Failed to generate the short-lived CA")
				// The metric collapses both ErrCASignerUnusable producers - an
				// expired signer and a lifetime the CA cannot cover - into one
				// series, because errors.Is is the only discrimination the
				// reconciler makes. The old grep proved the second branch
				// specifically. This setup guarantees which one is hit (a CA
				// that loads but expires before a default certificate would),
				// so the weaker assertion still tests the intended thing, but
				// it is weaker and that is worth knowing.
				var requeuesBefore float64
				Eventually(func(g Gomega) {
					requeuesBefore = scrapeMetricValue(g, caUnusableRequeueSeries)
				}, caPropagationTimeout, metricsScrapePollInterval).Should(Succeed())
				rotateCA(short)

				By("creating a workload whose default 24-hour lifetime cannot fit inside that CA")
				pod := createCertTestPod(certTestPod{name: "pcs-ca-unusable-signer"})

				By("verifying the controller treats the unusable CA as transient and requeues")
				Eventually(func(g Gomega) {
					g.Expect(scrapeMetricValue(g, caUnusableRequeueSeries)).
						To(BeNumerically(">", requeuesBefore),
							"an unusable CA must be counted as a requeue, not as a terminal outcome")
				}, caPropagationTimeout, metricsScrapePollInterval).Should(Succeed())

				By("verifying the request records no terminal outcome")
				// This is the contract the reconciler states at the
				// ErrCASignerUnusable branch: a CA that cannot cover the request
				// today can cover it after a rotation, so recording Failed would
				// write an outcome the request could never recover from. The
				// request must simply stay pending.
				Consistently(func(g Gomega) {
					pcr := findPodCertificateRequest(g, pod)
					g.Expect(terminalConditionsOf(pcr)).To(BeEmpty(),
						"an unusable CA must not produce a terminal condition; request %s carries %v",
						pcr.Name, pcr.Status.Conditions)
					expectStatusFieldsCleared(g, pcr)
				}, 30*time.Second, 5*time.Second).Should(Succeed())

				By("restoring a CA that can cover the lifetime")
				// A CA that has not been current before, rather than an earlier
				// one: rotating back into a certificate already in the history
				// takes a different path through authority.load's append-trim-
				// then-drop-current sequence, and this spec is not about that.
				recovered := newLifecycleCA("ca-lifecycle-recovered")
				rotateCA(recovered)

				// Nothing re-enqueues a pending request when the CA reloads: the
				// reload notification goes to the ClusterTrustBundle publisher and
				// nowhere else, so the request comes back only on the workqueue's
				// exponential backoff, whose attempts fall at roughly 82s, 164s,
				// 328s and 655s. A restore that lands late would push the next
				// attempt past any timeout this spec could reasonably set, and the
				// spec would go red for arithmetic rather than for behavior. The
				// nudge takes the backoff out of the measurement; it does not
				// stand in for the recovery claim, which is still that *this*
				// request - not a replacement - issues under the restored CA.
				nudgeRequest(pod)

				By("verifying the request that was pending now issues, without being recreated")
				chain := expectIssued(pod)
				Expect(chain).To(HaveLen(defaultChainLength))
				Expect(chain[1].Equal(recovered.Cert)).To(BeTrue(),
					"the previously unsatisfiable request must issue under the restored CA")
			})
		})

		Context("ClusterTrustBundle drift", Label(nightlyLabel), func() {
			// The publisher does not watch the ClusterTrustBundle. It publishes
			// when it starts, on every CA reload event, and on a ten-minute
			// drift-repair tick (ctbDriftRepairInterval). Ten minutes is far
			// longer than any spec here can wait, so both specs cause a CA reload
			// and assert the repair that follows it. What they can assert
			// unconditionally, and do, is that damaged trust anchors never stop
			// the signer issuing: signing reads the in-memory CA and never the
			// published bundle.
			It("re-creates the bundle after it is deleted, without interrupting issuance", func() {
				current := currentCA()
				publishedBefore := trustBundleRaw(Default)
				Expect(publishedBefore).NotTo(BeEmpty())

				By("deleting the ClusterTrustBundle out from under the controller")
				cmd := exec.Command("kubectl", "delete", "clustertrustbundle", trustBundleName)
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "Failed to delete the ClusterTrustBundle: %s", output)

				By("verifying issuance is unaffected while the bundle is missing")
				// Deliberately a workload that does not project the bundle:
				// kubelet blocks pod start on a missing ClusterTrustBundle
				// projection, so a pod that mounted it would fail to start for a
				// reason that has nothing to do with the signer.
				pod := createCertTestPod(certTestPod{name: "pcs-ctb-deleted-issue"})
				chain := expectIssued(pod)
				Expect(chain).To(HaveLen(defaultChainLength))
				Expect(chain[1].Equal(current.Cert)).To(BeTrue(),
					"a missing trust bundle must not change what the signer issues")

				By("rotating the CA to drive the publisher")
				replacement := newLifecycleCA("ca-lifecycle-after-delete")
				rotateCA(replacement)

				By("verifying the bundle came back with the history intact")
				Eventually(func(g Gomega) {
					certs := getTrustBundleCertificates(g)
					g.Expect(certs).NotTo(BeEmpty())
					g.Expect(certs[0].Equal(replacement.Cert)).To(BeTrue(),
						"the re-created bundle must lead with the current CA")
					g.Expect(containsCertificate(certs, current.Cert)).To(BeTrue(),
						"deleting the bundle must not lose the previous CA the controller still holds")
				}).Should(Succeed())
			})

			It("overwrites a bundle something else has rewritten", func() {
				current := currentCA()

				By("injecting a foreign CA into the published bundle")
				foreign := newLifecycleCA("ca-lifecycle-foreign")
				patchTrustBundle(string(foreign.CertPEM))
				Eventually(func(g Gomega) {
					certs := getTrustBundleCertificates(g)
					g.Expect(containsCertificate(certs, foreign.Cert)).To(BeTrue(),
						"the drift must actually be in place, otherwise the repair below proves nothing")
				}).Should(Succeed())

				By("verifying issuance is unaffected by the drift")
				pod := createCertTestPod(certTestPod{name: "pcs-ctb-mutated-issue"})
				chain := expectIssued(pod)
				Expect(chain).To(HaveLen(defaultChainLength))
				Expect(chain[1].Equal(current.Cert)).To(BeTrue(),
					"a rewritten trust bundle must not change what the signer issues")

				By("rotating the CA to drive the publisher")
				replacement := newLifecycleCA("ca-lifecycle-after-mutation")
				rotateCA(replacement)

				By("verifying the publisher overwrote the drift rather than merging it")
				Eventually(func(g Gomega) {
					certs := getTrustBundleCertificates(g)
					g.Expect(certs).NotTo(BeEmpty())
					g.Expect(certs[0].Equal(replacement.Cert)).To(BeTrue(),
						"the corrected bundle must lead with the current CA")
					g.Expect(containsCertificate(certs, foreign.Cert)).To(BeFalse(),
						"an injected CA must not survive the next publish")
					g.Expect(containsCertificate(certs, current.Cert)).To(BeTrue(),
						"correcting the drift must restore the history the controller holds")
				}).Should(Succeed())
			})
		})
	})
}

// lifecycleCurrentCA is the CA the controller has most recently loaded, written
// by rotateCA and read by currentCA. It is the single record of "which CA is
// signing right now", so a spec that rotates cannot forget to update it.
//
// It is package-level rather than container-scoped because of how Ginkgo builds
// a DescribeTable: entry arguments are evaluated when the spec tree is
// constructed, long before any BeforeAll runs, so an entry cannot close over a
// container variable and see anything but its zero value. An entry therefore
// names a function, and that function calls currentCA at spec time.
var lifecycleCurrentCA *testutil.KeyPair

// currentCA returns the CA the controller has most recently loaded.
func currentCA() *testutil.KeyPair {
	GinkgoHelper()

	Expect(lifecycleCurrentCA).NotTo(BeNil(),
		"no CA has been written yet; the CA-lifecycle BeforeAll establishes one")
	return lifecycleCurrentCA
}

// newLifecycleCA generates a CA for the lifecycle specs. It does not make it
// current: only rotateCA does that, and only once the controller has published
// the result.
func newLifecycleCA(commonName string) *testutil.KeyPair {
	GinkgoHelper()

	kp, err := testutil.NewCA(commonName, caLifecycleValidity)
	Expect(err).NotTo(HaveOccurred(), "Failed to generate CA %q", commonName)
	return kp
}

// newLifecycleNonCA generates a self-signed certificate without CA capabilities.
func newLifecycleNonCA(commonName string) *testutil.KeyPair {
	GinkgoHelper()

	kp, err := testutil.NewNonCA(commonName, caLifecycleValidity)
	Expect(err).NotTo(HaveOccurred(), "Failed to generate non-CA certificate %q", commonName)
	return kp
}

// rotateCA writes the key pair into the controller's CA secret and waits until
// the controller has reloaded it and published it.
//
// Waiting on the published bundle rather than on a log line is deliberate: the
// bundle is the observable every other spec reads, so returning from here means
// the cluster - not just the controller's memory - has caught up. A spec that
// created a workload before that point would race the reload and could see a
// certificate from either CA.
func rotateCA(kp *testutil.KeyPair) {
	GinkgoHelper()

	By("writing CA " + kp.Cert.Subject.CommonName + " into the controller's CA secret")
	applyCAMaterial(kp.CertPEM, kp.KeyPEM)

	By("waiting for the controller to reload and publish it")
	expectTrustBundleLeader(kp.Cert)
	lifecycleCurrentCA = kp
}

// applyCAMaterial replaces the contents of the controller's CA secret.
//
// It builds the Secret itself rather than shelling out to `kubectl create secret
// tls`, which validates client-side that the certificate and key are a usable
// pair and would refuse every case the invalid-material specs need to write.
// kube-apiserver only requires that a kubernetes.io/tls Secret carries both
// keys, so arbitrary bytes reach the controller exactly as an operator's mistake
// would.
//
// The manifest goes in over stdin. utils.Run echoes a command's arguments to the
// Ginkgo report, so key material must never be one.
func applyCAMaterial(certPEM, keyPEM []byte) {
	GinkgoHelper()

	secret := &corev1.Secret{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{Name: caSecretName, Namespace: namespace},
		Type:       corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}
	manifest, err := json.Marshal(secret)
	Expect(err).NotTo(HaveOccurred(), "Failed to marshal the CA secret")

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	output, err := utils.Run(cmd)
	// Redacted for the same reason the failure dump is: an apiserver rejection
	// can quote the object it rejected.
	Expect(err).NotTo(HaveOccurred(), "Failed to apply the CA secret: %s", redactSensitive(output))
}

// expectTrustBundleLeader waits until the published bundle leads with the given
// certificate.
func expectTrustBundleLeader(want *x509.Certificate) {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		certs := getTrustBundleCertificates(g)
		g.Expect(certs).NotTo(BeEmpty(), "the published bundle must carry the current CA")
		g.Expect(certs[0].Equal(want)).To(BeTrue(),
			"the published bundle must lead with %q, leads with %q",
			want.Subject.CommonName, certs[0].Subject.CommonName)
	}, caPropagationTimeout).Should(Succeed())
}

// trustBundleRaw returns the published bundle exactly as it is stored, for the
// assertions that are about the bytes rather than about the certificates.
func trustBundleRaw(g Gomega) string {
	cmd := exec.Command("kubectl", "get", "clustertrustbundle", trustBundleName,
		"-o", "jsonpath={.spec.trustBundle}")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to read the ClusterTrustBundle")
	return output
}

// patchTrustBundle rewrites the published bundle, standing in for whatever else
// in the cluster might.
//
// The patch is written to a file rather than passed as an argument: utils.Run
// echoes arguments, and a multi-line PEM in the report makes the surrounding
// output unreadable.
func patchTrustBundle(bundlePEM string) {
	GinkgoHelper()

	patch, err := json.Marshal(map[string]any{
		"spec": map[string]any{"trustBundle": bundlePEM},
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to build the ClusterTrustBundle patch")

	dir, err := os.MkdirTemp("", "pcs-e2e-ctb")
	Expect(err).NotTo(HaveOccurred(), "Failed to create a temp dir for the patch")
	DeferCleanup(func() { _ = os.RemoveAll(dir) })

	patchFile := filepath.Join(dir, "patch.json")
	Expect(os.WriteFile(patchFile, patch, os.FileMode(0o600))).To(Succeed())

	cmd := exec.Command("kubectl", "patch", "clustertrustbundle", trustBundleName,
		"--type=merge", "--patch-file", patchFile)
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to patch the ClusterTrustBundle: %s", output)
}

// restartController rolls the controller Deployment and waits for the
// replacement to be serving.
//
// Every log-line count taken before this call is void afterwards: the counts are
// read from one pod's log and the new pod starts from an empty one. Callers must
// not straddle a restart with a before/after comparison.
func restartController() {
	GinkgoHelper()

	By("restarting the controller")
	cmd := exec.Command("kubectl", "rollout", "restart", "deployment/"+releaseName, "-n", namespace)
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to restart the controller: %s", output)

	cmd = exec.Command("kubectl", "rollout", "status", "deployment/"+releaseName,
		"-n", namespace, "--timeout=5m")
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "The controller restart did not complete: %s", output)

	By("re-resolving the controller pod after the restart")
	resolveControllerPod()
}

// expectControllerReady waits for the controller pod to report Ready.
func expectControllerReady() {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		g.Expect(controllerReadyStatus()).To(Equal("True"),
			"the controller pod must be Ready")
	}).Should(Succeed())
}

// expectControllerStaysReady asserts the controller does not drop out of
// readiness. See the readiness note in the invalid-material table for why
// staying Ready is the documented outcome there.
func expectControllerStaysReady() {
	GinkgoHelper()

	Consistently(func(g Gomega) {
		g.Expect(controllerReadyStatus()).To(Equal("True"),
			"a single unloadable write must not remove the replica from readiness")
	}, 15*time.Second, 3*time.Second).Should(Succeed())
}

// controllerReadyStatus reports the controller pod's Ready condition.
func controllerReadyStatus() string {
	cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
		"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`)
	output, err := utils.Run(cmd)
	if err != nil {
		return fmt.Sprintf("unavailable: %v", err)
	}
	return strings.TrimSpace(output)
}

// mountedTrustAnchors reads the trust anchors a running workload actually has,
// out of its projected volume.
//
// This is the only way to answer the question a rotation raises for a workload
// that is already running: the request status and the ClusterTrustBundle both
// describe what the control plane believes, and neither says whether the file
// the container opened has been updated. The file is public material, so reading
// it out whole is safe; nothing here touches the credential bundle next to it.
func mountedTrustAnchors(g Gomega, ref podRef) []*x509.Certificate {
	cmd := exec.Command("kubectl", "exec", ref.name, "-n", ref.namespace, "--",
		"cat", certTestPodMountPath+"/ca.crt")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(),
		"Failed to read the projected trust anchors from pod %s; %s", ref, podStatusSummary(ref))
	return parseCertificateChain(g, output)
}

// expectVerifiesAgainst proves a leaf chains to a set of trust anchors, which is
// what a peer holding those anchors will do with it.
func expectVerifiesAgainst(leaf *x509.Certificate, anchors []*x509.Certificate, description string) {
	GinkgoHelper()

	pool := x509.NewCertPool()
	for _, anchor := range anchors {
		pool.AddCert(anchor)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots: pool,
		// The EKU is asserted where the certificate is issued; here the question
		// is only whether the chain builds.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	Expect(err).NotTo(HaveOccurred(), description)
}

// terminalConditionsOf returns the request's terminal conditions, if any.
//
// It is the counterpart of terminalCondition for a spec that expects *none*:
// that helper asserts exactly one and would fail the wrong way round here.
func terminalConditionsOf(pcr *capiv1beta1.PodCertificateRequest) []metav1.Condition {
	var terminal []metav1.Condition
	for _, cond := range pcr.Status.Conditions {
		for _, want := range terminalConditionTypes {
			if cond.Type == want {
				terminal = append(terminal, cond)
			}
		}
	}
	return terminal
}

// uniqueStrings returns the distinct values of s, for the duplicate check on the
// published bundle.
func uniqueStrings(s []string) []string {
	seen := make(map[string]struct{}, len(s))
	unique := make([]string, 0, len(s))
	for _, value := range s {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}
