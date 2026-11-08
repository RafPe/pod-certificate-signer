//go:build e2e
// +build e2e

package e2e

import (
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

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

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

// haAllControllerPods lists every controller replica, terminating ones included.
//
// The counterpart to haControllerPods, which filters terminating pods out. A pod
// on its way out is not a replica most assertions are about, but it is still
// running and can still reconcile until it is gone, so a caller that needs the
// controller to be genuinely absent has to consult this list as well.
func haAllControllerPods() []string {
	cmd := exec.Command("kubectl", "get", "pods",
		"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", releaseName),
		"-n", namespace,
		"-o", "go-template={{ range .items }}{{ .metadata.name }}{{ \"\\n\" }}{{ end }}")
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
//
// A released Lease transiently reads an empty holder, so the non-empty
// assertion can fire during a passing run; every caller wraps this in an
// Eventually or Consistently, which absorbs it as one more poll.
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
		// Both lists are consulted. haControllerPods filters out terminating
		// pods, so on its own it reports the target count while a scaled-down
		// replica is still inside its grace period - still running, and still
		// able to reconcile. Requiring the unfiltered list to match too means
		// this returns only once the old replicas are really gone.
		g.Expect(haAllControllerPods()).To(HaveLen(replicas),
			"a controller pod is still terminating, and can still reconcile until it is gone")
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
