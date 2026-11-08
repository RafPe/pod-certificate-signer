//go:build e2e
// +build e2e

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
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

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

// newLifecycleNotYetValidCA generates a CA whose validity window opens six
// hours from now - far beyond the signer's clock-skew tolerance and, unlike a
// tighter margin, guaranteed not to become valid while the spec is still
// waiting out kubelet's mounted-secret propagation.
func newLifecycleNotYetValidCA(commonName string) *testutil.KeyPair {
	GinkgoHelper()

	notBefore := time.Now().Add(6 * time.Hour)
	kp, err := testutil.NewCAWithValidity(commonName, notBefore, notBefore.Add(caLifecycleValidity))
	Expect(err).NotTo(HaveOccurred(), "Failed to generate not-yet-valid CA %q", commonName)
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
func terminalConditionsOf(pcr *certificatesv1.PodCertificateRequest) []metav1.Condition {
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
