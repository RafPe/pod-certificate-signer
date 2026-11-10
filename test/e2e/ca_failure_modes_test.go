//go:build e2e
// +build e2e

package e2e

import (
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// defineCAFailureModeTests is called from the parent container in
// ca_lifecycle_test.go. It is split out only to keep that file readable; the
// specs run in the same ordered position they always had.
func defineCAFailureModeTests() {
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
				// share the "load key pair" wrapper, so a spec that
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
				"load key pair", "private key does not match public key"),
			Entry("a certificate that is not PEM at all",
				"pcs-ca-bad-cert-pem",
				func() ([]byte, []byte) {
					return []byte("this is not a certificate\n"), currentCA().KeyPEM
				},
				"load key pair", "failed to find any PEM data in certificate input"),
			Entry("a key that is not PEM at all",
				"pcs-ca-bad-key-pem",
				func() ([]byte, []byte) {
					return currentCA().CertPEM, []byte("this is not a private key\n")
				},
				"load key pair", "failed to find any PEM data in key input"),
			Entry("a well-formed certificate that is not a CA",
				"pcs-ca-bad-non-ca",
				func() ([]byte, []byte) {
					leaf := newLifecycleNonCA("ca-lifecycle-not-a-ca")
					return leaf.CertPEM, leaf.KeyPEM
				},
				"certificate is not a valid CA certificate", "certificate is not a valid CA certificate"),
			Entry("a CA certificate that is not yet valid",
				"pcs-ca-bad-not-yet-valid",
				func() ([]byte, []byte) {
					// A perfectly good CA, hours early. Loading it would
					// keep the signer green while every leaf it issues
					// fails chain verification on the peer, because the
					// verifier checks the validity window of the whole
					// chain - which is why it must be refused up front
					// like the other unusable material here.
					kp := newLifecycleNotYetValidCA("ca-lifecycle-not-yet-valid")
					return kp.CertPEM, kp.KeyPEM
				},
				"CA certificate is not yet valid", "CA certificate is not yet valid"),
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
		// drift-repair tick (driftRepairInterval). Ten minutes is far
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
}
