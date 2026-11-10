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
	"strconv"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// High availability, leader failover and concurrency.
//
// # Why this container installs rather than switching profile
//
// Every install profile in install_profiles_test.go runs at replicaCount=1,
// and the profiles switch by re-running `make helm-install` in place. That
// arrangement is safe only because exactly one replica is live at a time: a
// mid-suite `helm upgrade` rolls a single pod, and the specs that follow read
// logs and readiness off that one pod by name (resolveControllerPod fails
// outright on anything other than one match).
//
// Two replicas breaks all of that, which is why this container does NOT call
// installProfile. It uninstalls the release and installs it again at
// replicaCount=2, so the two-replica deployment is a distinct installation
// rather than one more entry in the profile rotation. **Do not fold it back
// in.** A profile switch from here would roll a two-replica Deployment down to
// one while the profile's own specs ran, and every single-pod assertion in the
// suite would start seeing whichever pod the rollout happened to leave behind.
//
// # Why it is declared last, inside the Manager Describe
//
// It is declared after defineGowebInteropTests(), the last container in
// e2e_test.go, and it lives inside Describe("Manager", Ordered, Serial) rather
// than as a sibling top-level Describe. Both matter:
//
//   - Ginkgo permutes top-level containers by default (only --randomize-all
//     extends that to specs). A sibling Describe would therefore land in a
//     random position relative to the profile rotation and to the previous-CA
//     retention spec, which asserts an exact rotation history. Ordered inside
//     the Manager Describe pins the position.
//   - The Manager Describe's AfterAll uninstalls the release and deletes the
//     namespace, so a sibling container would run against a torn-down
//     deployment - the same reason the profile containers are nested.
//
// Being last also means this container is free to rotate the CA and to leave
// the release at two replicas: nothing follows that either can disturb.
//
// # Cost
//
// Every spec here carries nightlyLabel through the container. The container
// pays a full uninstall/install, two leader deletions, a CA rotation, a rolling
// upgrade, an eviction round trip and a scale-to-zero - minutes of wall time
// the per-PR tier has no room for.

// haInstallArgs is the two-replica installation.
//
// replicaCount is the only override. Leader election is on by the chart default
// (leader_election.enabled), the PodDisruptionBudget is on by the chart default
// (minAvailable: 1), and no signer flag is touched - the identity constraints
// stay enforced and the escape hatch stays shut, so the denial spec below is
// denied for the shipped reason. Anything set here that the chart already
// defaults to would make a regression of that default invisible.
const haInstallArgs = "--set replicaCount=2"

const (
	// haReplicas is the replica count this container installs: one leader and
	// one warm standby, which is the smallest deployment where "only the
	// leader publishes" and "the follower is promoted" are distinguishable
	// outcomes. Keep it in step with haInstallArgs above, which has to spell
	// the number literally for the const expression to stay constant.
	haReplicas = 2

	// haLeaderHandoffTimeout bounds the wait for the Lease to move to another
	// replica after the holder goes away.
	//
	// The manager is built with LeaderElectionReleaseOnCancel
	// (cmd/podcertificate-signer/main.go,
	// docs/adr/0006-release-leader-lease-on-cancel.md), so a leader shutting
	// down voluntarily releases the Lease and the floor is no longer the 15
	// second LeaseDuration: measured handover is ~1.2s, and the worst case is
	// one jittered RetryPeriod plus the leader's shutdown.
	//
	// Not lower than this, for two reasons. currentLeaderPod uses the same
	// bound for the *initial* election after installHighAvailability, which is
	// a ~2.7s cold start rather than a handover. And a spec that asserted a
	// tight bound would be measuring client-go's polling jitter rather than
	// the product.
	haLeaderHandoffTimeout = 30 * time.Second

	// haReadinessTimeout bounds the wait for the deployment to present its
	// full complement of Ready replicas.
	haReadinessTimeout = 3 * time.Minute

	// haRolloutTimeout is passed to `kubectl rollout status`.
	haRolloutTimeout = "5m"

	// haSettleWindow is how long a spec watches an outcome it expects *not* to
	// change. It is deliberately short: every use is paired with a positive
	// assertion that the controller has already had its chance to act (a
	// completed issuance elsewhere, a nudged reconcile, an observed log line),
	// so the window is a guard against a late write, not the proof itself.
	haSettleWindow = 20 * time.Second

	// haForeignSigner names a signer this deployment does not serve.
	haForeignSigner = "example.org/other-signer"

	// leaseAcquiredLogLine is what a replica writes when it wins the election.
	// It comes from client-go's leaderelection package rather than from this
	// project, and it arrives through klog rather than the manager's zap
	// logger, which is why it is capitalised unlike everything else the
	// controller logs. Spelled out as a constant so a client-go rename shows up
	// as one edit rather than a spec that quietly counts zero.
	leaseAcquiredLogLine = "Successfully acquired lease"

	// haBurstSize is the number of certificate requests the concurrency spec
	// raises at once. It is deliberately above the chart's default
	// manager.max_concurrent_reconciles (5), so the burst is larger than the
	// controller's worker pool and requests genuinely queue.
	haBurstSize = 6
)

// haRotatedCA is the CA this container rotates to, and haPreRotationCA the one
// it rotated away from. They are container-scoped state shared by the CA
// freshness spec and the promoted-follower spec that follows it: the second
// asserts against the CA the first installed, and re-rotating to assert it
// would cost another kubelet secret propagation for nothing.
var (
	haRotatedCA     *testutil.KeyPair
	haPreRotationCA *x509.Certificate
)

func defineHighAvailabilityTests() {
	Context("High availability", Label(nightlyLabel), func() {
		BeforeAll(func() {
			installHighAvailability()
		})

		AfterAll(func() {
			// The ClusterTrustBundle is cluster-scoped, so the Manager
			// Describe's namespace deletion does not reach it. Removing it
			// here keeps the container's footprint to what it created.
			By("removing the ClusterTrustBundle this container published")
			cmd := exec.Command("kubectl", "delete", "clustertrustbundle", trustBundleName, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})

		// Point the pod-targeted helpers at the current leader before every
		// spec, not once in BeforeAll: leadership moves twice in this
		// container, and controllerLogLineCount (and therefore
		// expectTerminalConditionStable, and therefore expectDenied) reads one
		// pod's log by name. Aimed at a follower it would wait out its whole
		// timeout for a reconcile that is happening in the other pod, and fail
		// as though the controller had stopped reconciling.
		BeforeEach(func() {
			focusControllerOnLeader()
		})

		Context("Leader election and failover", func() {
			It("runs two Ready replicas with exactly one Lease holder", func() {
				By("waiting for both replicas to report Ready")
				expectHAReplicasReady()

				By("verifying the Deployment itself reports the full complement")
				Eventually(func(g Gomega) {
					g.Expect(deploymentReplicaCounts(g)).To(Equal([2]int{haReplicas, haReplicas}),
						"the Deployment must report %d replicas, all of them ready", haReplicas)
				}, haReadinessTimeout).Should(Succeed())

				By("verifying the leader-election Lease names one of them as holder")
				pods := haControllerPods()
				Expect(pods).To(HaveLen(haReplicas))
				leader := currentLeaderPod()
				Expect(pods).To(ContainElement(leader),
					"the Lease holder must be one of the live replicas")

				By("verifying exactly one replica ever acquired the lease")
				// The Lease naming a holder is the apiserver's view; this is
				// the replicas' own. Two pods both believing they hold it -
				// which is what a broken election looks like from the inside -
				// would leave two logs claiming the acquisition while the
				// Lease still named only one of them.
				var acquired []string
				for _, pod := range pods {
					if podLogLineCount(pod, leaseAcquiredLogLine) > 0 {
						acquired = append(acquired, pod)
					}
				}
				Expect(acquired).To(ConsistOf(leader),
					"exactly one replica must report acquiring the lease, and it must be the Lease holder")
			})

			It("publishes the ClusterTrustBundle from the leader only", func() {
				leader := currentLeaderPod()
				follower := haFollowerPod(leader)

				By("verifying the leader started the publisher and wrote the bundle")
				Eventually(func(g Gomega) {
					g.Expect(podLogLineCount(leader, "starting ClusterTrustBundle publisher")).To(BeNumerically(">", 0),
						"the leader must start the leader-gated ClusterTrustBundle publisher")
					g.Expect(podLogLineCount(leader, publishedBundleLine)).To(BeNumerically(">", 0),
						"the leader must publish the ClusterTrustBundle")
				}).Should(Succeed())

				By("verifying the published bundle is the one the specs read")
				Eventually(func(g Gomega) {
					certs := getTrustBundleCertificates(g)
					g.Expect(certs).NotTo(BeEmpty(), "the leader must have published at least the current CA")
				}).Should(Succeed())

				By("verifying the standby never publishes")
				// Consistently, not a single read: the follower runs the same
				// binary and the same publisher code, and a leader gate that
				// leaked would show up as a late write rather than an
				// immediate one.
				Consistently(func(g Gomega) {
					g.Expect(podLogLineCount(follower, "starting ClusterTrustBundle publisher")).To(Equal(0),
						"a standby replica must not start the ClusterTrustBundle publisher")
					g.Expect(podLogLineCount(follower, publishedBundleLine)).To(Equal(0),
						"a standby replica must never write the shared ClusterTrustBundle")
				}, haSettleWindow, 5*time.Second).Should(Succeed())
			})

			It("hands leadership over promptly when the leader is deleted, and keeps issuing", func() {
				leader := currentLeaderPod()

				By("deleting the leader replica")
				deleteControllerPod(leader)

				By("waiting for another replica to take the Lease")
				// Deliberately not asserting *which* replica wins. The
				// surviving standby and the ReplicaSet's replacement are both
				// candidates, and measurement showed the race is real: the
				// standby becomes eligible one LeaseDuration after the dead
				// leader's last renewal, the replacement one LeaseDuration
				// after it first reads the record, and on a local cluster
				// those two moments land within a couple of seconds of each
				// other. The claim under test is that leadership moves off the
				// deleted replica quickly and issuance resumes - not who picks
				// it up. The spec that does need a warm standby promoted makes
				// that happen deterministically rather than hoping for it.
				start := time.Now()
				Eventually(func(g Gomega) {
					holder := haLeaseHolder(g)
					g.Expect(holder).NotTo(Equal(leader),
						"the Lease must move off the deleted replica")
					g.Expect(haControllerPods()).To(ContainElement(holder),
						"the new Lease holder must be a live replica")
				}, haLeaderHandoffTimeout).Should(Succeed())
				handoff := time.Since(start)
				AddReportEntry("leader handoff", handoff.String())

				By("verifying issuance continues under the new leader")
				pod := applyCertTestPod("pcs-ha-after-handoff", nil)
				leaf := expectIssued(pod)[0]
				Expect(leaf.SerialNumber).NotTo(BeNil())

				By("waiting for the deployment to return to full strength")
				expectHAReplicasReady()
			})

			It("reloads a CA change on every replica, leader or not", func() {
				// The CA watcher reports NeedLeaderElection() == false
				// (cmd/podcertificate-signer/main.go) precisely so a standby
				// keeps its in-memory CA current and never signs with stale
				// material the moment it is promoted. That is what this spec
				// asserts, and the spec that follows is what makes the
				// guarantee matter.
				By("recording the replicas present before the rotation")
				// Captured first: a replica that started *after* the secret
				// changed would load the new CA at boot and log no reload at
				// all, so it would prove nothing about the watcher.
				before := haControllerPods()
				Expect(before).To(HaveLen(haReplicas))

				By("recording the CA in the published bundle before the rotation")
				Eventually(func(g Gomega) {
					certs := getTrustBundleCertificates(g)
					g.Expect(certs).NotTo(BeEmpty())
					haPreRotationCA = certs[0]
				}).Should(Succeed())

				By("rotating the CA")
				haRotatedCA = newLifecycleCA("ha-rotated-ca.example.org")
				rotateCA(haRotatedCA)

				By("verifying both replicas reloaded it, not just the publishing leader")
				for _, pod := range before {
					Eventually(func() int {
						return podLogLineCount(pod, "CA certificate reloaded successfully")
					}, caPropagationTimeout).Should(BeNumerically(">", 0),
						"replica %s must reload the CA even when it is not the leader", pod)
				}
			})

			It("signs with the current CA once a warm standby is promoted", func() {
				Expect(haRotatedCA).NotTo(BeNil(), "the CA freshness spec must have rotated first")

				By("waiting for both replicas to be Ready before choosing which one to remove")
				// Load-bearing for the scale-down below. A ReplicaSet ranks
				// not-ready pods ahead of ready ones when it picks what to
				// delete, and that ordering beats the pod deletion cost - so a
				// standby that happened to be momentarily unready would be the
				// one removed and the spec would fail describing a product
				// problem it had itself created.
				expectHAReplicasReady()

				leader := currentLeaderPod()
				standby := haFollowerPod(leader)
				By("checking the replica about to be promoted is the one that was already running")
				// The point of the spec is that a *warm* standby signs
				// correctly. A replacement pod would load the rotated CA off
				// disk at boot and pass without the watcher existing at all.
				Expect(podLogLineCount(standby, "CA certificate reloaded successfully")).To(BeNumerically(">", 0),
					"the standby must have observed the rotation while it was a follower")

				By("making the standby the only remaining candidate")
				// Deleting the leader would not do: the ReplicaSet's
				// replacement is a candidate too and it frequently wins the
				// election (see the handoff spec above). Scaling down removes
				// the leader without creating a replacement, and the pod
				// deletion cost annotation - a stable Kubernetes API, GA since
				// 1.22 - is what decides *which* replica the ReplicaSet
				// removes. Without it the scale-down would be the same coin
				// flip in a different shape.
				setPodDeletionCost(leader, -100)
				setPodDeletionCost(standby, 100)
				scaleController(1)
				DeferCleanup(func() {
					scaleController(haReplicas)
				})

				By("verifying the warm standby is the survivor and takes the Lease")
				Expect(haControllerPods()).To(ConsistOf(standby),
					"the pod deletion cost must have made the leader the one removed")
				Eventually(func(g Gomega) {
					g.Expect(haLeaseHolder(g)).To(Equal(standby))
				}, haLeaderHandoffTimeout).Should(Succeed())

				By("issuing under the promoted leader")
				pod := applyCertTestPod("pcs-ha-promoted-issuer", nil)
				leaf := expectIssued(pod)[0]

				By("verifying the certificate was signed by the rotated CA")
				Expect(leaf.Issuer.CommonName).To(Equal(haRotatedCA.Cert.Subject.CommonName),
					"the promoted leader must sign with the current CA")
				expectVerifiesAgainst(leaf, []*x509.Certificate{haRotatedCA.Cert},
					"a certificate issued by the promoted leader must chain to the current CA")

				By("verifying it was not signed by the CA in force before the rotation")
				// Asserting only the positive would pass for a signer that
				// somehow produced a certificate valid under both, and would
				// pass trivially if the rotation had never taken effect.
				Expect(haPreRotationCA).NotTo(BeNil())
				stale := x509.NewCertPool()
				stale.AddCert(haPreRotationCA)
				_, err := leaf.Verify(x509.VerifyOptions{
					Roots:     stale,
					KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
				})
				Expect(err).To(HaveOccurred(),
					"a promoted leader signing with the pre-rotation CA would mean the standby was stale")
			})

			It("keeps issuing across a rolling upgrade", func() {
				By("recording the replicas present before the upgrade")
				before := haControllerPods()
				Expect(before).To(HaveLen(haReplicas))

				By("rolling the Deployment")
				cmd := exec.Command("kubectl", "rollout", "restart", "deployment/"+releaseName, "-n", namespace)
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "Failed to roll the controller: %s", output)

				By("requesting a certificate while the upgrade is in flight")
				// Created before the availability watch below, so the request
				// is raised while the rollout is genuinely mid-flight rather
				// than after it has settled.
				pod := applyCertTestPod("pcs-ha-rolling-upgrade", nil)

				By("watching availability until the rollout completes")
				minReady := watchRolloutAvailability()
				AddReportEntry("minimum ready replicas during the rolling upgrade", strconv.Itoa(minReady))
				Expect(minReady).To(BeNumerically(">=", 1),
					"a rolling upgrade must never leave the signer with no Ready replica")

				By("verifying the mid-upgrade request was issued")
				expectIssued(pod)

				By("verifying the upgrade actually replaced both replicas")
				// Without this the availability assertion above would pass for
				// a rollout that never happened.
				after := haControllerPods()
				Expect(after).To(HaveLen(haReplicas))
				for _, pod := range after {
					Expect(before).NotTo(ContainElement(pod),
						"a rolling upgrade must replace every replica; %s survived it", pod)
				}

				By("verifying the new replicas elected a leader")
				Expect(after).To(ContainElement(currentLeaderPod()))
			})

			defineHADisruptionTests()
		})

		defineHAReconciliationLifecycleTests()
	})
}
