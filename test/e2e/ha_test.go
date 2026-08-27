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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"

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
	// The floor is controller-runtime's default LeaseDuration of 15 seconds:
	// the manager is built without LeaderElectionReleaseOnCancel, so a leader
	// shutting down does not release the Lease and a follower must wait for it
	// to expire. The bound here is generous over that floor because the
	// follower then has to observe the expiry on its RetryPeriod, and a spec
	// that asserted a tight bound would be measuring client-go's polling
	// jitter rather than the product.
	haLeaderHandoffTimeout = 90 * time.Second

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
					g.Expect(podLogLineCount(leader, "reconciled ClusterTrustBundle")).To(BeNumerically(">", 0),
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
					g.Expect(podLogLineCount(follower, "reconciled ClusterTrustBundle")).To(Equal(0),
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

			It("lets the PodDisruptionBudget allow one disruption and refuse the second", func() {
				By("waiting for the budget to report a full, healthy deployment")
				var pods []string
				Eventually(func(g Gomega) {
					status := haPodDisruptionBudgetStatus(g)
					g.Expect(status.ExpectedPods).To(BeNumerically("==", haReplicas))
					g.Expect(status.CurrentHealthy).To(BeNumerically("==", haReplicas))
					g.Expect(status.DesiredHealthy).To(BeNumerically("==", 1),
						"the chart ships minAvailable: 1")
					g.Expect(status.DisruptionsAllowed).To(BeNumerically("==", 1),
						"two healthy replicas against minAvailable: 1 must allow exactly one disruption")
					pods = haControllerPods()
					g.Expect(pods).To(HaveLen(haReplicas))
				}, haReadinessTimeout).Should(Succeed())

				evicted, survivor := pods[0], pods[1]

				By("evicting one replica, which the budget must allow")
				output, err := evictControllerPod(evicted)
				Expect(err).NotTo(HaveOccurred(),
					"the first eviction must be allowed by minAvailable: 1: %s", output)

				By("waiting for the budget to report no disruptions left")
				Eventually(func(g Gomega) {
					g.Expect(haPodDisruptionBudgetStatus(g).DisruptionsAllowed).To(BeNumerically("==", 0),
						"a disruption must be deducted from the budget")
				}, time.Minute).Should(Succeed())

				By("checking the survivor is still Ready, so the refusal can only be the budget")
				// unhealthyPodEvictionPolicy is AlwaysAllow, so an unhealthy
				// pod is evictable whatever the budget says. Asserting the
				// survivor is Ready is what makes the 429 below attributable
				// to minAvailable rather than to the eviction policy.
				Expect(podReadyStatus(survivor)).To(Equal("True"))

				By("attempting to evict the survivor, which the budget must refuse")
				output, err = evictControllerPod(survivor)
				Expect(err).To(HaveOccurred(),
					"evicting the last healthy replica must be refused: %s", output)
				Expect(output).To(ContainSubstring("disruption budget"),
					"the refusal must name the budget, not some other admission failure")

				By("waiting for the deployment to recover its budget")
				Eventually(func(g Gomega) {
					g.Expect(haPodDisruptionBudgetStatus(g).DisruptionsAllowed).To(BeNumerically("==", 1),
						"the budget must recover once the replacement replica is healthy")
				}, haReadinessTimeout).Should(Succeed())
				expectHAReplicasReady()
			})

			It("drops a replica that cannot publish from readiness and keeps the standby Ready", func() {
				// Readiness is gated on two checks (main.go): the CA's
				// watcher/reload health, and the ClusterTrustBundle
				// publisher's last outcome. This spec exercises the second.
				//
				// The first - a replica gone *stale*, its reloads failing
				// persistently - is deliberately not attempted here: it needs
				// reloadFailureThreshold consecutive failures sustained across
				// reloadFailureGracePeriod, which is ten minutes of wall time
				// (internal/kubernetes/authority/authority.go). It is covered
				// by authority_readiness_test.go with the clock under test
				// control. Weakening this spec to claim it would be a lie.
				leader := currentLeaderPod()

				By("deleting the published ClusterTrustBundle")
				// Without this the next publish is a no-op patch:
				// publishOnce goes through CreateOrPatch, which issues no
				// write when the object already matches, so the revoked
				// permission below would never be exercised and the replica
				// would stay Ready for the wrong reason.
				cmd := exec.Command("kubectl", "delete", "clustertrustbundle", trustBundleName, "--ignore-not-found=true")
				output, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred(), "Failed to delete the ClusterTrustBundle: %s", output)

				By("revoking the controller's permission to write ClusterTrustBundles")
				// get is left in place on purpose: the controller reads its
				// previous-CA history from the bundle at startup and exits if
				// that read fails for any reason other than NotFound, so
				// revoking it would produce a CrashLoopBackOff and this spec
				// would assert readiness against a pod that never started.
				restrictClusterTrustBundleWrites()

				By("deleting the leader so a replica has to publish from scratch")
				deleteControllerPod(leader)

				By("verifying the publish really failed")
				Eventually(func(g Gomega) {
					cmd := exec.Command("kubectl", "get", "clustertrustbundle", trustBundleName)
					_, err := utils.Run(cmd)
					g.Expect(err).To(HaveOccurred(),
						"the bundle must stay absent while the controller may not write it")
				}, time.Minute).Should(Succeed())

				By("verifying readiness excludes the publishing replica and no other")
				// Both halves in one poll, because the pair is the contract:
				// the replica that cannot publish must fail readiness, and the
				// one that is not publishing must not - a probe that failed
				// everywhere would take the standby with it and leave nothing
				// to promote.
				//
				// Which replica ends up leading is not asserted; the handoff
				// spec above explains why that is a race. The assertion is
				// phrased against whichever replica the Lease names.
				var failing string
				Eventually(func(g Gomega) {
					pods := haControllerPods()
					g.Expect(pods).To(HaveLen(haReplicas))
					failing = haLeaseHolder(g)
					g.Expect(pods).To(ContainElement(failing))
					for _, pod := range pods {
						want := "True"
						if pod == failing {
							want = "False"
						}
						g.Expect(podReadyStatus(pod)).To(Equal(want),
							"replica %s (leader: %t) must report Ready=%s", pod, pod == failing, want)
					}
				}, haReadinessTimeout).Should(Succeed())

				By("restoring the permission")
				restoreClusterTrustBundleWrites()

				By("deleting the failed leader so the next one can publish")
				// The publisher retries only on a CA reload event or on its
				// ten-minute drift-repair tick, so restoring the permission
				// alone would leave the spec waiting out that tick. Moving the
				// Lease is the cheap route back: a newly-elected leader
				// publishes on startup.
				deleteControllerPod(failing)

				By("verifying the bundle is published again and every replica is Ready")
				Eventually(func(g Gomega) {
					certs := getTrustBundleCertificates(g)
					g.Expect(certs).NotTo(BeEmpty(), "the bundle must be republished once writes are permitted")
				}, haReadinessTimeout).Should(Succeed())
				expectHAReplicasReady()
			})
		})

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
	})
}

// installHighAvailability replaces whatever is installed with a two-replica
// deployment.
//
// It uninstalls first rather than upgrading in place, which is the loud version
// of the boundary described at the top of this file: what follows is a distinct
// installation, not another install profile. The uninstall also guarantees the
// replicas below all start from the same CA, since `make helm-install`
// re-applies the ephemeral dev CA secret and the preceding containers leave a
// rotated one behind.
func installHighAvailability() {
	GinkgoHelper()

	By("uninstalling the single-replica release")
	cmd := exec.Command("make", "helm-uninstall")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to uninstall the release: %s", output)

	By("removing the ClusterTrustBundle the previous installation published")
	// The bundle is cluster-scoped and outlives the release. Left in place it
	// would seed the new controller's previous-CA history with certificates
	// from the containers above, and the readiness spec's first publish would
	// be a no-op patch rather than a create.
	cmd = exec.Command("kubectl", "delete", "clustertrustbundle", trustBundleName, "--ignore-not-found=true")
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to delete the ClusterTrustBundle: %s", output)

	By("installing the controller with " + strconv.Itoa(haReplicas) + " replicas")
	cmd = exec.Command("make", "helm-install",
		fmt.Sprintf("IMAGE=%s", projectImage),
		"HELM_EXTRA_ARGS="+haInstallArgs)
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to install the two-replica controller: %s", output)

	By("waiting for the rollout to complete")
	cmd = exec.Command("kubectl", "rollout", "status", "deployment/"+releaseName,
		"-n", namespace, "--timeout="+haRolloutTimeout)
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "The two-replica rollout did not complete: %s", output)

	expectHAReplicasReady()
}

// haControllerPods lists the live controller replicas.
//
// Pods carrying a deletionTimestamp are filtered out for the same reason
// resolveControllerPod filters them: mid-rollout there are briefly three, and
// the one on its way out is not a replica any assertion is about.
func haControllerPods() []string {
	cmd := exec.Command("kubectl", "get", "pods",
		"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", releaseName),
		"-n", namespace,
		"-o", "go-template={{ range .items }}"+
			"{{ if not .metadata.deletionTimestamp }}"+
			"{{ .metadata.name }}{{ \"\\n\" }}{{ end }}{{ end }}")
	output, err := utils.Run(cmd)
	if err != nil {
		return nil
	}
	return utils.GetNonEmptyLines(output)
}

// haLeaseHolder returns the pod holding the leader-election Lease.
//
// controller-runtime writes the holder identity as "<hostname>_<uuid>", and a
// pod's hostname is its name, so the pod is the part before the underscore.
func haLeaseHolder(g Gomega) string {
	cmd := exec.Command("kubectl", "get", "lease", releaseName, "-n", namespace,
		"-o", "jsonpath={.spec.holderIdentity}")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to read the leader-election Lease")

	holder := strings.TrimSpace(output)
	g.Expect(holder).NotTo(BeEmpty(), "the leader-election Lease must name a holder")
	return strings.SplitN(holder, "_", 2)[0]
}

// currentLeaderPod waits until the Lease names a live replica and returns it.
func currentLeaderPod() string {
	GinkgoHelper()

	var leader string
	Eventually(func(g Gomega) {
		leader = haLeaseHolder(g)
		g.Expect(haControllerPods()).To(ContainElement(leader),
			"the Lease holder %q must be a live replica", leader)
	}, haLeaderHandoffTimeout).Should(Succeed())
	return leader
}

// haFollowerPod returns the replica that is not the leader.
func haFollowerPod(leader string) string {
	GinkgoHelper()

	var follower string
	Eventually(func(g Gomega) {
		pods := haControllerPods()
		g.Expect(pods).To(HaveLen(haReplicas))
		follower = ""
		for _, pod := range pods {
			if pod != leader {
				follower = pod
			}
		}
		g.Expect(follower).NotTo(BeEmpty(), "no standby replica alongside leader %q", leader)
	}, haReadinessTimeout).Should(Succeed())
	return follower
}

// focusControllerOnLeader points controllerPodName at the current leader.
//
// The suite's log-reading helpers (controllerLogLineCount, and through it
// expectTerminalConditionStable) read one pod by name. With two replicas only
// the leader runs the reconciler, so aimed anywhere else they observe an
// entirely idle log and report it as the controller having stopped.
func focusControllerOnLeader() {
	GinkgoHelper()
	controllerPodName = currentLeaderPod()
}

// expectHAReplicasReady waits for the full complement of replicas, all Ready.
func expectHAReplicasReady() {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		pods := haControllerPods()
		g.Expect(pods).To(HaveLen(haReplicas), "expected %d controller replicas", haReplicas)
		for _, pod := range pods {
			g.Expect(podReadyStatus(pod)).To(Equal("True"), "replica %s must be Ready", pod)
		}
	}, haReadinessTimeout).Should(Succeed())
}

// podReadyStatus reports a controller pod's Ready condition. It never asserts,
// so a caller's Eventually keeps polling across a pod that is still starting.
func podReadyStatus(pod string) string {
	cmd := exec.Command("kubectl", "get", "pod", pod, "-n", namespace,
		"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`)
	output, err := utils.Run(cmd)
	if err != nil {
		return fmt.Sprintf("unavailable: %v", err)
	}
	return strings.TrimSpace(output)
}

// deploymentReplicaCounts returns the Deployment's spec replicas and its
// currently-ready replicas.
func deploymentReplicaCounts(g Gomega) [2]int {
	cmd := exec.Command("kubectl", "get", "deployment", releaseName, "-n", namespace,
		"-o", "jsonpath={.spec.replicas}/{.status.readyReplicas}")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to read the controller Deployment")

	parts := strings.SplitN(strings.TrimSpace(output), "/", 2)
	g.Expect(parts).To(HaveLen(2), "unexpected Deployment replica output %q", output)

	counts := [2]int{}
	for i, part := range parts {
		value, err := strconv.Atoi(part)
		g.Expect(err).NotTo(HaveOccurred(), "unexpected Deployment replica output %q", output)
		counts[i] = value
	}
	return counts
}

// readyReplicas reports the Deployment's ready replica count, or -1 when it
// cannot be read. It is the sampling half of watchRolloutAvailability and never
// asserts.
func readyReplicas() int {
	cmd := exec.Command("kubectl", "get", "deployment", releaseName, "-n", namespace,
		"-o", "jsonpath={.status.readyReplicas}")
	output, err := utils.Run(cmd)
	if err != nil {
		return -1
	}
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		// The field is omitted, not zeroed, while no replica is ready.
		return 0
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return -1
	}
	return value
}

// watchRolloutAvailability samples the Deployment's ready replicas until the
// rollout has completed, and returns the lowest count it saw.
//
// It samples in the foreground rather than from a goroutine because the whole
// suite is single-threaded and a background sampler would be one more thing
// that can outlive a failing spec. `kubectl rollout status` is deliberately not
// used to wait: it blocks, which would mean the sampling only started once
// there was nothing left to sample.
func watchRolloutAvailability() int {
	GinkgoHelper()

	minReady := haReplicas
	Eventually(func(g Gomega) {
		if ready := readyReplicas(); ready >= 0 && ready < minReady {
			minReady = ready
		}
		g.Expect(rolloutComplete()).To(BeTrue(), "the rolling upgrade has not completed yet")
	}, haReadinessTimeout, 500*time.Millisecond).Should(Succeed())
	return minReady
}

// rolloutComplete reports whether the Deployment has finished rolling: the
// observed generation has caught up and every replica is updated, ready and
// available.
func rolloutComplete() bool {
	cmd := exec.Command("kubectl", "get", "deployment", releaseName, "-n", namespace,
		"-o", "jsonpath={.metadata.generation}/{.status.observedGeneration}"+
			"/{.status.updatedReplicas}/{.status.readyReplicas}/{.status.replicas}")
	output, err := utils.Run(cmd)
	if err != nil {
		return false
	}
	parts := strings.Split(strings.TrimSpace(output), "/")
	if len(parts) != 5 {
		return false
	}
	if parts[0] != parts[1] {
		return false
	}
	want := strconv.Itoa(haReplicas)
	return parts[2] == want && parts[3] == want && parts[4] == want
}

// deleteControllerPod removes one replica and waits for it to be gone.
func deleteControllerPod(pod string) {
	GinkgoHelper()

	cmd := exec.Command("kubectl", "delete", "pod", pod, "-n", namespace, "--wait=true")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to delete controller pod %s: %s", pod, output)
}

// scaleController sets the Deployment's replica count and waits for the cluster
// to reach it.
func scaleController(replicas int) {
	GinkgoHelper()

	By(fmt.Sprintf("scaling the controller to %d replica(s)", replicas))
	cmd := exec.Command("kubectl", "scale", "deployment/"+releaseName,
		"-n", namespace, fmt.Sprintf("--replicas=%d", replicas))
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to scale the controller: %s", output)

	Eventually(func(g Gomega) {
		pods := haControllerPods()
		g.Expect(pods).To(HaveLen(replicas))
		for _, pod := range pods {
			g.Expect(podReadyStatus(pod)).To(Equal("True"), "replica %s must be Ready", pod)
		}
	}, haReadinessTimeout).Should(Succeed())
}

// setPodDeletionCost annotates a replica with its pod deletion cost, which is
// how a ReplicaSet is told which pods to remove first on a scale-down. Lower
// goes first.
func setPodDeletionCost(pod string, cost int) {
	GinkgoHelper()

	cmd := exec.Command("kubectl", "annotate", "pod", pod, "-n", namespace, "--overwrite",
		fmt.Sprintf("controller.kubernetes.io/pod-deletion-cost=%d", cost))
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to set the pod deletion cost on %s: %s", pod, output)
}

// rollHAController restarts every replica and waits for the deployment to
// settle.
//
// It is the multi-replica counterpart of restartController, which cannot be
// used here: that helper ends in resolveControllerPod, which fails on anything
// other than exactly one pod.
func rollHAController() {
	GinkgoHelper()

	cmd := exec.Command("kubectl", "rollout", "restart", "deployment/"+releaseName, "-n", namespace)
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to restart the controller: %s", output)

	cmd = exec.Command("kubectl", "rollout", "status", "deployment/"+releaseName,
		"-n", namespace, "--timeout="+haRolloutTimeout)
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "The controller restart did not complete: %s", output)

	expectHAReplicasReady()
}

// podLogLineCount reports how many lines of the named pod's log contain all of
// the given substrings.
//
// It is the pod-parameterized twin of controllerLogLineCount, which reads the
// single pod the rest of the suite targets. Every assertion in this file is
// about which *replica* did something, so the pod has to be an argument. Like
// its twin it is diagnostic-grade: an unreadable log counts as zero rather than
// failing, so a caller's Eventually keeps polling across a starting pod.
func podLogLineCount(pod string, needles ...string) int {
	cmd := exec.Command("kubectl", "logs", pod, "-n", namespace)
	output, err := utils.Run(cmd)
	if err != nil {
		return 0
	}

	count := 0
	for _, line := range strings.Split(output, "\n") {
		if containsAll(line, needles) {
			count++
		}
	}
	return count
}

// haPodDisruptionBudgetStatus reads the budget the chart renders for the
// controller.
func haPodDisruptionBudgetStatus(g Gomega) policyv1.PodDisruptionBudgetStatus {
	cmd := exec.Command("kubectl", "get", "poddisruptionbudget", releaseName,
		"-n", namespace, "-o", "json")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to read the PodDisruptionBudget")

	var pdb policyv1.PodDisruptionBudget
	g.Expect(json.Unmarshal([]byte(trimToJSON(output)), &pdb)).To(Succeed(),
		"Failed to decode the PodDisruptionBudget")
	return pdb.Status
}

// evictControllerPod asks the apiserver to evict a replica, returning kubectl's
// output and whether the eviction was refused.
//
// It posts an Eviction to the pod's eviction subresource, which is what a node
// drain does and the only path that consults the PodDisruptionBudget. A plain
// `kubectl delete pod` bypasses the budget entirely and would prove nothing.
func evictControllerPod(pod string) (string, error) {
	GinkgoHelper()

	eviction, err := json.Marshal(map[string]any{
		"apiVersion": "policy/v1",
		"kind":       "Eviction",
		"metadata":   map[string]any{"name": pod, "namespace": namespace},
	})
	Expect(err).NotTo(HaveOccurred(), "Failed to build the Eviction body")

	dir, err := os.MkdirTemp("", "pcs-e2e-eviction")
	Expect(err).NotTo(HaveOccurred(), "Failed to create a temp dir for the Eviction")
	DeferCleanup(func() { _ = os.RemoveAll(dir) })

	body := filepath.Join(dir, "eviction.json")
	Expect(os.WriteFile(body, eviction, os.FileMode(0o600))).To(Succeed())

	cmd := exec.Command("kubectl", "create", "--raw",
		fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/eviction", namespace, pod),
		"-f", body)
	return utils.Run(cmd)
}

// clusterTrustBundleWriteVerbs are the verbs the readiness spec revokes. get is
// not among them: see the spec for why revoking it would produce a crash loop
// instead of a readiness failure.
var clusterTrustBundleWriteVerbs = []string{"create", "update", "patch"}

// restrictClusterTrustBundleWrites removes the controller's ClusterTrustBundle
// write permissions and registers their restoration.
//
// The ClusterRole is Helm-managed, so the patch is a targeted verb replacement
// on the rule that grants them, and the cleanup puts the original verb list
// back verbatim rather than reinstating what this file believes it should be.
func restrictClusterTrustBundleWrites() {
	GinkgoHelper()

	index, verbs := clusterTrustBundleRule()
	DeferCleanup(func() {
		patchClusterRoleVerbs(index, verbs)
	})
	patchClusterRoleVerbs(index, []string{"get"})
}

// restoreClusterTrustBundleWrites puts the write verbs back before the spec
// ends, so the assertions that follow the revocation run against a controller
// that is permitted to publish again. The DeferCleanup registered above stays
// as the backstop for a spec that fails in between.
func restoreClusterTrustBundleWrites() {
	GinkgoHelper()

	index, verbs := clusterTrustBundleRule()
	patchClusterRoleVerbs(index, append(verbs, clusterTrustBundleWriteVerbs...))
}

// clusterTrustBundleRule locates the ClusterRole rule granting access to
// ClusterTrustBundles and returns its index and current verbs.
func clusterTrustBundleRule() (int, []string) {
	GinkgoHelper()

	cmd := exec.Command("kubectl", "get", "clusterrole", releaseName, "-o", "json")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to read the controller ClusterRole: %s", output)

	var role rbacv1.ClusterRole
	Expect(json.Unmarshal([]byte(trimToJSON(output)), &role)).To(Succeed(),
		"Failed to decode the controller ClusterRole")

	for i, rule := range role.Rules {
		for _, resource := range rule.Resources {
			if resource == "clustertrustbundles" {
				return i, rule.Verbs
			}
		}
	}

	Fail("the controller ClusterRole has no clustertrustbundles rule")
	return 0, nil
}

// patchClusterRoleVerbs replaces the verbs of one ClusterRole rule.
func patchClusterRoleVerbs(index int, verbs []string) {
	GinkgoHelper()

	patch, err := json.Marshal([]map[string]any{{
		"op":    "replace",
		"path":  fmt.Sprintf("/rules/%d/verbs", index),
		"value": verbs,
	}})
	Expect(err).NotTo(HaveOccurred(), "Failed to build the ClusterRole patch")

	cmd := exec.Command("kubectl", "patch", "clusterrole", releaseName,
		"--type=json", "--patch", string(patch))
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to patch the controller ClusterRole: %s", output)
}

// findRequestForSigner returns the single request belonging to the given pod
// and addressed to the given signer.
//
// findPodCertificateRequest hard-codes the signer under test, which is the
// right default everywhere else in the suite and exactly wrong for the spec
// that asserts another signer's request is left alone.
func findRequestForSigner(g Gomega, ref podRef, signer string) *certificatesv1.PodCertificateRequest {
	cmd := exec.Command("kubectl", "get", "podcertificaterequests", "-n", ref.namespace, "-o", "json")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to list PodCertificateRequests")

	var list certificatesv1.PodCertificateRequestList
	g.Expect(json.Unmarshal([]byte(trimToJSON(output)), &list)).To(Succeed(),
		"Failed to decode the PodCertificateRequest list")

	var matches []*certificatesv1.PodCertificateRequest
	for i := range list.Items {
		pcr := &list.Items[i]
		if pcr.Spec.PodName == ref.name && pcr.Spec.PodUID == ref.uid && pcr.Spec.SignerName == signer {
			matches = append(matches, pcr)
		}
	}
	g.Expect(matches).To(HaveLen(1),
		"expected exactly one request for pod %s and signer %q, got %d", ref, signer, len(matches))
	return matches[0]
}

// requestEvents returns the events of the given type recorded against a
// request, so a spec can assert on how many there are rather than that one
// exists.
func requestEvents(g Gomega, namespace, requestName, eventType string) []corev1.Event {
	cmd := exec.Command("kubectl", "get", "events", "-n", namespace,
		"--field-selector", "involvedObject.name="+requestName, "-o", "json")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to list events for %s", requestName)

	var list corev1.EventList
	g.Expect(json.Unmarshal([]byte(trimToJSON(output)), &list)).To(Succeed(),
		"Failed to decode the event list")

	matches := make([]corev1.Event, 0, len(list.Items))
	for _, event := range list.Items {
		if event.Type == eventType {
			matches = append(matches, event)
		}
	}
	return matches
}

// eventOccurrences reports how many times an event was recorded.
//
// Two fields can carry that, and which one does depends on who wrote the
// event. The controller records through the events.k8s.io recorder, which
// aggregates repeats into a series; the legacy count field is what the
// core/v1 view of a non-aggregated event carries, and it is 0 rather than 1
// for an event that has never repeated. Taking the larger of the two is what
// lets a spec assert "recorded once" without depending on that.
func eventOccurrences(event corev1.Event) int32 {
	if event.Series != nil && event.Series.Count > event.Count {
		return event.Series.Count
	}
	return event.Count
}
