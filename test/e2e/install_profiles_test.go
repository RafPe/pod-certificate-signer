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
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// Install profiles.
//
// The suite installs the chart once in the top-level BeforeAll and then
// re-installs it, in place, at the head of each profile container below.
// `make helm-install` is `helm upgrade --install` against the same release and
// namespace, so a profile switch is an upgrade, not a second deployment.
//
// This is safe only because the suite is single-threaded: `make test-e2e` runs
// `go test -tags=e2e ./test/e2e/ -v -ginkgo.v`, which is plain `go test` with no
// ginkgo CLI and therefore no `-p`/`--procs`. Ginkgo runs every spec serially in
// one process, in declaration order. Two profiles can never be live at once. If
// the suite is ever moved to the `ginkgo` CLI with parallel procs, these
// containers must be reworked - a mid-suite upgrade would race the other
// profile's specs.
//
// Each profile container lives inside the top-level Describe("Manager",
// Ordered), which is what makes BeforeAll legal here without a further Ordered
// decoration - the same arrangement defineAdmissionPolicyTests already uses. A
// sibling top-level Describe would run against a deployment the Describe's
// AfterAll has already uninstalled.
//
// They are declared before the ClusterTrustBundle context, which rotates the CA
// secret deliberately. `make helm-install` re-applies the CA secret from
// bin/dev-ca, so a profile switch after that rotation would rotate the CA back
// and race the controller's volume reload against the profile's issuance specs.
const (
	// escapeHatchInstallArgs is the historical install: both escape hatches
	// open. Every spec that requests an identity the pod does not own
	// (custom-cn.example.org, literal IP SANs) depends on it.
	escapeHatchInstallArgs = "--set replicaCount=1 " +
		"--set signer.enable_annotation_interpolation=true " +
		"--set signer.allow_unverified_identities=true " +
		"--set admissionPolicies.dnsSANValidation.enabled=true"

	// csrSANsInstallArgs adds the CSR-SAN opt-in to the escape-hatch profile.
	csrSANsInstallArgs = escapeHatchInstallArgs + " --set signer.honor_csr_sans=true"

	// secureDefaultsInstallArgs is the configuration issue #87 proposes and the
	// one the suite never exercised: interpolation on, identity constraints
	// enforced, no escape hatch. Resolved ${...} values must still clear the
	// verified-identity allowlist.
	secureDefaultsInstallArgs = "--set replicaCount=1 " +
		"--set signer.enable_annotation_interpolation=true " +
		"--set admissionPolicies.dnsSANValidation.enabled=true"

	// chartDefaultsInstallArgs is the chart's shipped configuration, with
	// nothing turned on: interpolation off, identity constraints enforced,
	// CSR SANs ignored. Only replicaCount and the admission policy are set, and
	// neither touches issuance semantics.
	chartDefaultsInstallArgs = "--set replicaCount=1 " +
		"--set admissionPolicies.dnsSANValidation.enabled=true"
)

// installProfile re-installs the release with the given HELM_EXTRA_ARGS and
// waits for the new controller pod to be serving. `make helm-install` already
// passes `--wait --timeout 5m`, but that returns as soon as Helm considers the
// release ready; the explicit rollout wait plus re-resolving controllerPodName
// is what keeps the following specs (and the AfterEach log dump) pointed at the
// pod that is actually running the new flags.
func installProfile(extraArgs string) {
	GinkgoHelper()

	By("re-installing the controller with: " + extraArgs)
	cmd := exec.Command("make", "helm-install",
		fmt.Sprintf("IMAGE=%s", projectImage),
		"HELM_EXTRA_ARGS="+extraArgs)
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to re-install the controller: %s", output)

	By("waiting for the controller rollout to complete")
	cmd = exec.Command("kubectl", "rollout", "status", "deployment/"+releaseName,
		"-n", namespace, "--timeout=5m")
	output, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Controller rollout did not complete: %s", output)

	By("re-resolving the controller pod for this profile")
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "pods",
			"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", releaseName),
			"-o", "go-template={{ range .items }}"+
				"{{ if not .metadata.deletionTimestamp }}"+
				"{{ .metadata.name }}{{ \"\\n\" }}{{ end }}{{ end }}",
			"-n", namespace)
		podOutput, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		podNames := utils.GetNonEmptyLines(podOutput)
		g.Expect(podNames).To(HaveLen(1), "expected exactly 1 controller pod after the upgrade")
		controllerPodName = podNames[0]
	}).Should(Succeed())
}

// deniedRequest is the terminal outcome recorded on a PodCertificateRequest the
// signer refuses.
type deniedRequest struct {
	Reason  string
	Message string
}

// waitForDeniedRequest waits until the PodCertificateRequest belonging to the
// given pod carries a Denied condition and returns its reason and message.
//
// This is the counterpart to waitForIssuedChain, which fails on any condition
// that is not Issued and so cannot be used to assert a denial. Asserting on the
// reason and message - not merely on the absence of a certificate - is what
// distinguishes "denied by the identity constraint" from "denied because the
// value was malformed" or "never reconciled at all".
func waitForDeniedRequest(podName string) deniedRequest {
	GinkgoHelper()

	var denial deniedRequest
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "podcertificaterequests",
			"-n", workloadNamespace, "-o", "json")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred(), "Failed to list PodCertificateRequests")

		var list struct {
			Items []struct {
				Spec struct {
					PodName string `json:"podName"`
				} `json:"spec"`
				Status struct {
					CertificateChain string `json:"certificateChain"`
					Conditions       []struct {
						Type    string `json:"type"`
						Reason  string `json:"reason"`
						Message string `json:"message"`
					} `json:"conditions"`
				} `json:"status"`
			} `json:"items"`
		}
		g.Expect(json.Unmarshal([]byte(output), &list)).To(Succeed())

		found := false
		for _, item := range list.Items {
			if item.Spec.PodName != podName {
				continue
			}
			g.Expect(item.Status.CertificateChain).To(BeEmpty(),
				"a denied request must never carry a certificate chain")
			for _, cond := range item.Status.Conditions {
				if cond.Type == "Denied" {
					denial = deniedRequest{Reason: cond.Reason, Message: cond.Message}
					found = true
				}
			}
		}
		g.Expect(found).To(BeTrue(), "no PodCertificateRequest for pod %q carries a Denied condition yet", podName)
	}, 3*time.Minute).Should(Succeed())

	return denial
}

// defineCSRSANProfileTests covers the --honor-csr-sans opt-in.
//
// Scope note, and the reason this container is thin: kubelet generates an empty
// PKCS#10 CSR today (see Options.HonorCSRSANs), so there is no way from a Pod
// manifest to get DNS or IP SANs into the CSR the signer reads. The behavior the
// flag gates - CSR DNS SANs run through the verified-identity allowlist, CSR IP
// SANs denied outright - is therefore unreachable end to end and is covered by
// unit tests instead (internal/kubernetes/podcertificate). What is reachable, and
// what this container asserts, is that turning the flag on does not disturb
// issuance: with an inert CSR the certificate is built from the annotations and
// the controller defaults exactly as with the flag off. Convert these specs into
// real CSR-SAN assertions once Kubernetes starts embedding requested SANs.
func defineCSRSANProfileTests() {
	Context("Install profile: escape hatches with --honor-csr-sans", func() {
		BeforeAll(func() {
			installProfile(csrSANsInstallArgs)
		})

		It("issues from annotations and defaults while kubelet CSRs stay empty", func() {
			const podName = "pcs-csr-sans"
			By("creating a workload pod with no san annotation, so any CSR SAN would show")
			applyCertTestPod(podName, map[string]string{
				signerName + "-cn": "csr-demo.example.org",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := waitForIssuedChain(podName)[0]

			By("verifying the certificate carries the annotation CN and the controller default SANs")
			Expect(leaf.Subject.CommonName).To(Equal("csr-demo.example.org"))
			Expect(leaf.DNSNames).To(ConsistOf(
				fmt.Sprintf("%s.%s.pod.cluster.local", podName, workloadNamespace),
				fmt.Sprintf("%s.%s.svc.cluster.local", podName, workloadNamespace),
			), "an empty kubelet CSR must contribute no DNS SANs, so the defaults stand")
			Expect(leaf.IPAddresses).To(BeEmpty(),
				"an empty kubelet CSR must contribute no IP SANs")
		})
	})
}

// defineSecureDefaultProfileTests covers the configuration issue #87 proposes:
// ${...} interpolation on, identity constraints enforced, no escape hatch.
//
// Before this container existed the suite only ever ran interpolation with
// --allow-unverified-identities set, so nothing proved that an interpolated
// value clears the allowlist on its own merits - the escape hatch would have
// admitted it either way.
//
// The denials asserted here are current behavior and some of them are expected
// to change: <sa>.<ns>.svc is denied by
// docs/adr/0001-verified-identity-allowlist-boundary.md, and the example
// manifest's IP SAN is denied without the escape hatch. Pinning them now is
// deliberate - a later change to either surfaces as a visible diff in this file
// rather than as silence.
func defineSecureDefaultProfileTests() {
	Context("Install profile: secure defaults with interpolation", func() {
		BeforeAll(func() {
			installProfile(secureDefaultsInstallArgs)
		})

		// Asserts four properties of one issued certificate rather than splitting
		// into four specs: each extra spec costs a pod creation and an issuance
		// round trip to read one more field off a leaf this spec already has in
		// hand. The default EKU in particular has no annotation of its own to
		// exercise - it is what you get when you ask for nothing - so it is only
		// ever observable on a certificate issued for some other reason. The
		// eku=client opt-in is covered separately under the escape-hatch profile
		// in e2e_test.go.
		It("issues an interpolated identity and SPIFFE ID, with no IP SANs and a serverAuth-only EKU", func() {
			const podName = "pcs-secure-interpolated"
			By("creating a workload pod requesting only identities it owns")
			applyCertTestPod(podName, map[string]string{
				signerName + "-cn":   "${pod.name}.${pod.namespace}.svc.${cluster.fqdn}",
				signerName + "-san":  "${pod.name}.${pod.namespace}.svc,${pod.serviceAccountName}.${pod.namespace}",
				signerName + "-uris": "spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := waitForIssuedChain(podName)[0]

			By("verifying every interpolated value cleared the verified-identity allowlist")
			Expect(leaf.Subject.CommonName).To(Equal(
				fmt.Sprintf("%s.%s.svc.cluster.local", podName, workloadNamespace)))
			Expect(leaf.DNSNames).To(ConsistOf(
				fmt.Sprintf("%s.%s.svc", podName, workloadNamespace),
				// The pod runs as the "default" service account, so its short
				// DNS form is default.default.
				fmt.Sprintf("default.%s", workloadNamespace),
			))

			By("verifying the service-account SPIFFE ID from issue #87 was issued")
			// The SPIFFE URI is the blessed spelling of the service-account
			// identity (ADR-0001), so this is the assertion #87 actually needs.
			Expect(leaf.URIs).To(HaveLen(1))
			Expect(leaf.URIs[0].String()).To(Equal(
				fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/default", workloadNamespace)))

			By("verifying no IP SANs were added")
			Expect(leaf.IPAddresses).To(BeEmpty())

			By("verifying the default extended key usage is serverAuth only")
			Expect(leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth),
				"the default EKU must be serverAuth only; clientAuth is an explicit opt-in via the eku annotation")
		})

		DescribeTable("denies identities the pod does not own",
			func(podName string, annotations map[string]string, wantMessage string) {
				By("creating a workload pod requesting an identity it cannot prove")
				applyCertTestPod(podName, annotations)

				By("waiting for the PodCertificateRequest to be denied")
				denial := waitForDeniedRequest(podName)
				Expect(denial.Reason).To(Equal("InvalidUnverifiedUserAnnotations"))
				Expect(denial.Message).To(ContainSubstring(wantMessage))
			},
			// The example manifest requests exactly this, which is why it
			// cannot issue on a default install. ADR-0001 records why the
			// service-account Service DNS form stays out of the allowlist.
			Entry("service-account Service DNS form", "pcs-deny-sa-svc", map[string]string{
				signerName + "-san": "${pod.serviceAccountName}.${pod.namespace}.svc",
			}, "is not derived from a verified pod identity"),
			// The exact-equality check is what closes this: the resolved value
			// starts with a name the pod owns but is not one.
			Entry("verified prefix with an attacker suffix", "pcs-deny-evil-suffix", map[string]string{
				signerName + "-san": "${pod.name}.evil.example.com",
			}, "is not derived from a verified pod identity"),
			// An IP address has no verified derivation from the request, so it
			// is denied before interpolation is even considered.
			Entry("annotation IP SAN", "pcs-deny-ip-san", map[string]string{
				signerName + "-cn":     "${pod.name}",
				signerName + "-ip-san": "10.96.0.99",
			}, "IP SANs are not derived from a verified pod identity"),
			// The API contract tells signers to deny requests carrying
			// annotations they do not understand rather than ignore them.
			Entry("unrecognized annotation key", "pcs-deny-unknown-key", map[string]string{
				signerName + "-cn":    "${pod.name}",
				signerName + "-bogus": "anything",
			}, "unrecognized user annotation key"),
		)

		It("omits the default DNS SANs for an over-long pod name and warns", func() {
			// A pod name is validated as a DNS-1123 *subdomain*, which caps the
			// total at 253 characters but not each label - so a 64-character
			// single-label name is admissible and would produce a >63-character
			// DNS label. Truncating it would give two pods sharing a
			// 63-character prefix identical SANs, so the defaults are dropped
			// instead and the operator is told why. At 64 characters the common
			// name still carries the identity, so the certificate issues.
			podName := "pcs-longname-" + strings.Repeat("a", 51)
			Expect(podName).To(HaveLen(64))

			By("creating a workload pod whose name exceeds the 63-character DNS label limit")
			applyCertTestPod(podName, map[string]string{
				signerName + "-duration": "2h",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := waitForIssuedChain(podName)[0]

			By("verifying the common name carries the identity and no default SANs were emitted")
			Expect(leaf.Subject.CommonName).To(Equal(podName))
			Expect(leaf.DNSNames).To(BeEmpty(),
				"a >63-character DNS label must yield no default SANs rather than a truncated one")

			By("verifying the operator was warned that a default was dropped")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "events", "-n", workloadNamespace,
					"--field-selector", "reason=DefaultSANSkipped",
					"-o", "jsonpath={.items[*].message}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring(podName),
					"a DefaultSANSkipped warning event must name the pod whose SANs were dropped")
				g.Expect(output).To(ContainSubstring("DNS label limit"))
			}).Should(Succeed())
		})
	})
}

// defineChartDefaultProfileTests covers the chart exactly as it ships, with no
// feature flag turned on.
//
// It exists for one assertion that no other profile can make: with
// --enable-annotation-interpolation off, a value containing ${...} is denied
// outright rather than resolved or issued verbatim. Running that assertion under
// the secure-defaults profile would pass for the wrong reason - the value would
// be rejected by the allowlist rather than by the disabled interpolation gate.
func defineChartDefaultProfileTests() {
	Context("Install profile: chart defaults", func() {
		BeforeAll(func() {
			installProfile(chartDefaultsInstallArgs)
		})

		It("denies ${...} values while interpolation is disabled", func() {
			const podName = "pcs-defaults-interp-off"
			By("creating a workload pod requesting an interpolated identity it does own")
			// The pod's own name is inside the verified-identity allowlist, so
			// the only thing that can deny this request is the interpolation
			// gate itself. That is the point of the spec.
			applyCertTestPod(podName, map[string]string{
				signerName + "-cn": "${pod.name}",
			})

			By("waiting for the PodCertificateRequest to be denied")
			denial := waitForDeniedRequest(podName)
			Expect(denial.Reason).To(Equal("InvalidUnverifiedUserAnnotations"))
			Expect(denial.Message).To(ContainSubstring("interpolation, which is disabled on this signer"),
				"the denial must name the disabled flag, not the identity constraint")
		})
	})
}
