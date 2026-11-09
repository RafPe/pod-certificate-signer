//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
)

// defineHAReconciliationLifecycleTests is called from the parent container in
// ha_test.go. It is split out only to keep that file readable; the
// specs run in the same ordered position they always had.
func defineHAReconciliationLifecycleTests() {
	// Reconciliation lifecycle.
	//
	// These are the reachable half of the review's reconciliation-lifecycle
	// list. They run on the two-replica installation above rather than
	// paying for a third one - and the burst spec is more meaningful there,
	// since it proves a leader-elected controller produces one terminal
	// outcome per request rather than one per replica.
	//
	// What is deliberately absent: any PodCertificateRequest this suite
	// created itself. Every request below is one kubelet generated from a
	// projected volume, which is the only shape a signer sees in
	// production. Hand-built requests belong in envtest, where their
	// classification can be stated explicitly.
	Context("Reconciliation lifecycle", func() {
		It("drops a request whose pod was removed before it was processed", func() {
			// Getting a pod out from under an in-flight reconcile is a
			// race that cannot be won reliably: issuance takes a couple of
			// seconds and the delete would land after it. So the
			// controller is scaled to zero first, which makes the ordering
			// deterministic - the request exists, unprocessed, before the
			// pod goes away.
			//
			// The pod is deleted with --cascade=orphan so the request
			// survives its owner. That is a first-class API deletion
			// option, not a manufactured object: the request is still the
			// one kubelet created, with the fields kubelet set. What is
			// being removed is the pod, which is exactly the situation the
			// controller's live-read gate exists for.
			By("scaling the controller down so the request cannot be processed")
			scaleController(0)
			DeferCleanup(func() {
				scaleController(haReplicas)
			})

			const podName = "pcs-ha-pod-gone"
			By("creating a workload pod, which makes kubelet raise the request")
			pod := createCertTestPod(certTestPod{name: podName})

			var requestName string
			By("waiting for the request to exist, unprocessed")
			Eventually(func(g Gomega) {
				pcr := findPodCertificateRequest(g, pod)
				g.Expect(terminalConditionsOf(pcr)).To(BeEmpty(),
					"the request must still be pending while no controller is running")
				requestName = pcr.Name
			}).Should(Succeed())
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "podcertificaterequest", requestName,
					"-n", pod.namespace, "--ignore-not-found=true", "--wait=false")
				_, _ = utils.Run(cmd)
			})

			By("removing the pod while leaving its request behind")
			cmd := exec.Command("kubectl", "delete", "pod", podName, "-n", pod.namespace, "--cascade=orphan")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to orphan-delete the pod: %s", output)

			By("verifying the request outlived its pod")
			Consistently(func(g Gomega) {
				findPodCertificateRequest(g, pod)
			}, 5*time.Second, time.Second).Should(Succeed())

			By("scaling the controller back up to process it")
			scaleController(haReplicas)

			By("verifying the controller reported the pod gone")
			expectEvent(pod.namespace, requestName, corev1.EventTypeWarning, "AssociatedPodGone", podName)

			By("verifying it wrote no terminal outcome")
			// The drop is not a terminal outcome and must not be recorded
			// as one: a Denied or Failed condition here would be a
			// permanent verdict on a request that was simply stale.
			Consistently(func(g Gomega) {
				pcr := findPodCertificateRequest(g, pod)
				g.Expect(terminalConditionsOf(pcr)).To(BeEmpty(),
					"a stale request must be dropped, not terminally judged")
				g.Expect(pcr.Status.CertificateChain).To(BeEmpty(),
					"a request with no pod must never be issued a certificate")
			}, haSettleWindow, 5*time.Second).Should(Succeed())
		})

		It("issues independently for a recreated pod with the same name and a new UID", func() {
			const podName = "pcs-ha-recreated"

			By("issuing for the first pod")
			first := createCertTestPod(certTestPod{name: podName})
			firstLeaf := expectIssued(first)[0]

			By("deleting it and waiting for the name to be free")
			cmd := exec.Command("kubectl", "delete", "pod", podName, "-n", first.namespace, "--wait=true")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to delete the first pod: %s", output)

			By("recreating a pod with the same name")
			second := createCertTestPod(certTestPod{name: podName})
			Expect(second.uid).NotTo(Equal(first.uid),
				"a recreated pod must carry a new UID, otherwise this spec proves nothing")

			By("verifying the second pod gets its own certificate")
			// findPodCertificateRequest selects on the pod UID and aborts
			// on an ambiguous match, so reaching an issued outcome here is
			// itself the proof that the two requests stayed distinct - a
			// signer that reused the first request's status would be
			// caught by the serial comparison below.
			secondLeaf := expectIssued(second)[0]
			Expect(secondLeaf.SerialNumber.String()).NotTo(Equal(firstLeaf.SerialNumber.String()),
				"the recreated pod must get a freshly signed certificate, not the previous pod's")
		})

		It("leaves another signer's request untouched", func() {
			const podName = "pcs-ha-foreign-signer"
			By("creating a workload pod requesting a certificate from a signer nothing serves")
			pod := createCertTestPod(certTestPod{
				name:               podName,
				signerNameOverride: haForeignSigner,
			})

			By("waiting for kubelet to raise the request against the other signer")
			var requestName string
			Eventually(func(g Gomega) {
				pcr := findRequestForSigner(g, pod, haForeignSigner)
				requestName = pcr.Name
			}).Should(Succeed())

			By("issuing for this signer, so the controller has demonstrably been reconciling")
			// Without this the settle window below would also pass against
			// a controller that had stopped working altogether.
			expectIssued(applyCertTestPod("pcs-ha-own-signer", nil))

			By("verifying the other signer's request was never touched")
			Consistently(func(g Gomega) {
				pcr := findRequestForSigner(g, pod, haForeignSigner)
				g.Expect(terminalConditionsOf(pcr)).To(BeEmpty(),
					"this controller must not judge a request addressed to %q", haForeignSigner)
				g.Expect(pcr.Status.CertificateChain).To(BeEmpty(),
					"this controller must not sign for a signer it does not serve")
				g.Expect(pcr.Status.Conditions).To(BeEmpty(),
					"this controller must write no condition at all on another signer's request")
			}, haSettleWindow, 5*time.Second).Should(Succeed())

			By("verifying it recorded no events against it either")
			cmd := exec.Command("kubectl", "get", "events", "-n", pod.namespace,
				"--field-selector", "involvedObject.name="+requestName, "-o", "json")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to list events for %s", requestName)
			var events corev1.EventList
			Expect(json.Unmarshal([]byte(trimToJSON(output)), &events)).To(Succeed())
			Expect(events.Items).To(BeEmpty(),
				"another signer's request must attract no events from this controller")
		})

		It("leaves a terminal request unchanged across a controller restart", func() {
			By("issuing a certificate")
			pod := applyCertTestPod("pcs-ha-terminal-across-restart", nil)
			expectIssued(pod)

			By("recording the terminal status")
			before := getPodCertificateRequest(pod)
			beforeCondition := terminalCondition(Default, before)

			By("restarting every replica")
			rollHAController()

			By("verifying the status is byte-for-byte what it was")
			after := getPodCertificateRequest(pod)
			afterCondition := terminalCondition(Default, after)
			Expect(afterCondition).To(Equal(beforeCondition),
				"a restart must not re-record the terminal condition")
			Expect(after.Status.CertificateChain).To(Equal(before.Status.CertificateChain),
				"a restart must not re-issue the certificate")
			Expect(after.Status.NotBefore).To(Equal(before.Status.NotBefore))
			Expect(after.Status.NotAfter).To(Equal(before.Status.NotAfter))
			Expect(after.Status.BeginRefreshAt).To(Equal(before.Status.BeginRefreshAt))

			By("verifying the restarted controller drops it on the immutability check")
			// The comparison above holds trivially for a controller that
			// never looked at the request. Nudging it and requiring the
			// immutability log line is what proves the restarted process
			// reconciled the request and declined to touch it.
			//
			// Written out rather than delegated to
			// expectTerminalConditionStable: that helper also asserts the
			// status fields are *cleared*, which is right for the denial it
			// was written for and wrong for an issued request, whose
			// certificate and timestamps must survive.
			focusControllerOnLeader()
			immutableLines := controllerLogLineCount(before.Name, "PodCertificateRequest is immutable")
			annotateReconcileNudge(pod.namespace, before.Name)
			Eventually(func() int {
				return controllerLogLineCount(before.Name, "PodCertificateRequest is immutable")
			}, time.Minute).Should(BeNumerically(">", immutableLines),
				"the restarted controller must reconcile request %s and decline to touch it", before.Name)

			By("verifying the nudged reconcile still changed nothing")
			nudged := getPodCertificateRequest(pod)
			Expect(terminalCondition(Default, nudged)).To(Equal(beforeCondition))
			Expect(nudged.Status.CertificateChain).To(Equal(before.Status.CertificateChain))
		})

		It("records one denial event, not a storm", func() {
			const podName = "pcs-ha-denial-events"
			By("creating a workload pod requesting an identity it does not own")
			// An IP SAN has no verified derivation from the request, and
			// the escape hatch is shut on this installation, so this is
			// denied by the shipped identity constraints.
			pod := createCertTestPod(certTestPod{
				name: podName,
				userAnnotations: map[string]string{
					signerName + "-ip-san": "10.96.0.99",
				},
			})

			By("waiting for the denial")
			// expectDenied already nudges one further reconcile and
			// asserts the outcome did not move, so by the time it returns
			// the controller has been given a second look at the request.
			expectDenied(pod, certificatesv1.PodCertificateRequestConditionInvalidUserConfig)

			var requestName string
			Eventually(func(g Gomega) {
				requestName = findPodCertificateRequest(g, pod).Name
			}).Should(Succeed())

			By("recording how the denial was reported")
			// Both halves of the measurement matter. Kubernetes aggregates
			// repeated identical events into one object and counts the
			// repeats, so counting objects alone would sail straight
			// through a real storm; and a signer that varied the message
			// would produce new objects instead of incrementing a count.
			var warnings []corev1.Event
			Eventually(func(g Gomega) {
				warnings = requestEvents(g, pod.namespace, requestName, corev1.EventTypeWarning)
				g.Expect(warnings).NotTo(BeEmpty())
			}).Should(Succeed())
			Expect(warnings).To(HaveLen(1),
				"a denied request must produce exactly one warning event object")
			recorded := eventOccurrences(warnings[0])
			Expect(recorded).To(BeNumerically("<=", 1),
				"a denied request must be recorded once, not %d times", recorded)

			By("nudging the controller repeatedly")
			for range 3 {
				annotateReconcileNudge(pod.namespace, requestName)
				time.Sleep(2 * time.Second)
			}

			By("verifying the further reconciles recorded nothing more")
			Consistently(func(g Gomega) {
				warnings := requestEvents(g, pod.namespace, requestName, corev1.EventTypeWarning)
				g.Expect(warnings).To(HaveLen(1),
					"a re-reconciled denial must not add a second warning event object")
				g.Expect(eventOccurrences(warnings[0])).To(Equal(recorded),
					"a re-reconciled denial must not be recorded again")
			}, haSettleWindow, 5*time.Second).Should(Succeed())
		})

		It("issues unique serials and exactly one terminal outcome for a burst", func() {
			By("raising " + strconv.Itoa(haBurstSize) + " requests at once")
			refs := make([]podRef, 0, haBurstSize)
			for i := range haBurstSize {
				refs = append(refs, createCertTestPod(certTestPod{
					name: fmt.Sprintf("pcs-ha-burst-%d", i),
				}))
			}

			By("verifying every request reached exactly one terminal outcome")
			// expectIssued goes through terminalCondition, which fails on
			// anything other than exactly one terminal condition - so the
			// "exactly one terminal result per request" half of the
			// contract is asserted for all of them here.
			serials := make([]string, 0, haBurstSize)
			for _, ref := range refs {
				serials = append(serials, expectIssued(ref)[0].SerialNumber.String())
			}

			By("verifying every certificate carries a distinct serial")
			Expect(uniqueStrings(serials)).To(HaveLen(haBurstSize),
				"concurrent issuance must never reuse a serial number: %v", serials)
		})
	})
}
