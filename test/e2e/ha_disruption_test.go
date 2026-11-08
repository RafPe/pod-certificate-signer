//go:build e2e
// +build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	policyv1 "k8s.io/api/policy/v1"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// defineHADisruptionTests registers the High availability specs that take a
// replica away on purpose: a voluntary eviction against the
// PodDisruptionBudget, and a leader that loses permission to publish. They run
// last in "Leader election and failover", after the failover specs.
func defineHADisruptionTests() {
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
		// (internal/authority/authority.go). It is covered
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
