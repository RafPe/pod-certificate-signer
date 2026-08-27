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
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// The identity boundary.
//
// This is the security claim the product makes: with the identity allowlist
// enforced, a pod obtains certificates for the identities it owns and for
// nothing else, however the request is spelled. These specs run under the
// verified-interpolation profile, where ${...} resolution is on and the escape
// hatch is closed - the only configuration in which "the value resolved, and
// was then refused on its merits" is a distinguishable outcome.
//
// Two things shape how the negatives are written.
//
// First, a denial that fires for the wrong reason is a false pass. Every
// non-issuing entry below asserts on the message, not only on the Denied
// condition, and the entries that exist to prove *ownership* rejected a value
// also assert that the value had resolved first - a "${" still in the message
// would mean interpolation failed and the boundary was never consulted.
//
// Second, the DNS SAN ValidatingAdmissionPolicy sits in front of the signer and
// reads only the projection's <signer>-san annotation, where it rejects
// anything that still contains "${" after substituting the four variables it
// knows. ${node.name} and ${pod.uid} are not among them, so requesting either
// as a SAN never reaches the signer at all: the pod is refused at admission.
// Those cases are therefore requested through the cn annotation, which the
// policy does not inspect, so the signer is the layer under test. The policy's
// own behavior is covered by defineAdmissionPolicyTests.

// defineVerifiedIdentityBoundaryTests is called from inside the
// verified-interpolation install profile container (install_profiles_test.go),
// so it adds no Helm upgrade of its own.
func defineVerifiedIdentityBoundaryTests() {
	Context("Verified identity boundary", func() {
		It("accepts every identity form derived from the verified request fields", func() {
			const podName = "pcs-identity-forms"

			By("creating a workload pod requesting each form of its own identity at once")
			// One certificate rather than one per form: a single foreign value
			// denies the whole request, so an issued certificate carrying all
			// seven names is proof that each cleared the allowlist, at the cost
			// of one pod instead of nine. The denial message names the offending
			// value, so a regression still says which form broke.
			pod := applyCertTestPod(podName, map[string]string{
				signerName + "-cn": "${pod.name}",
				signerName + "-san": strings.Join([]string{
					"${pod.name}",
					"${pod.name}.${pod.namespace}",
					"${pod.name}.${pod.namespace}.pod",
					"${pod.name}.${pod.namespace}.svc",
					"${pod.name}.${pod.namespace}.pod.${cluster.fqdn}",
					"${pod.name}.${pod.namespace}.svc.${cluster.fqdn}",
					"${pod.serviceAccountName}.${pod.namespace}",
				}, ","),
				signerName + "-uris": strings.Join([]string{
					"spiffe://${cluster.fqdn}/ns/${pod.namespace}/pod/${pod.name}",
					"spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}",
				}, ","),
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]

			By("verifying the common name is the pod's bare name")
			Expect(leaf.Subject.CommonName).To(Equal(podName))

			By("verifying every canonical DNS form of the pod and its service account was issued")
			Expect(leaf.DNSNames).To(ConsistOf(
				podName,
				fmt.Sprintf("%s.%s", podName, workloadNamespace),
				fmt.Sprintf("%s.%s.pod", podName, workloadNamespace),
				fmt.Sprintf("%s.%s.svc", podName, workloadNamespace),
				fmt.Sprintf("%s.%s.pod.cluster.local", podName, workloadNamespace),
				fmt.Sprintf("%s.%s.svc.cluster.local", podName, workloadNamespace),
				// The pod runs as the "default" service account, so its short
				// DNS form is default.default.
				fmt.Sprintf("default.%s", workloadNamespace),
			))

			By("verifying both SPIFFE IDs the pod owns were issued")
			Expect(uriStrings(leaf)).To(ConsistOf(
				fmt.Sprintf("spiffe://cluster.local/ns/%s/pod/%s", workloadNamespace, podName),
				fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/default", workloadNamespace),
			))

			By("verifying nothing else came along")
			Expect(leaf.IPAddresses).To(BeEmpty())
			Expect(leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth))
		})

		DescribeTable("denies identities that only resemble ones the pod owns",
			func(podName string, annotations map[string]string, inspect func(podRef, deniedRequest)) {
				By("creating a workload pod requesting an identity it cannot prove")
				pod := applyCertTestPod(podName, annotations)

				By("waiting for the PodCertificateRequest to be denied")
				// expectDenied also proves the request carries no certificate
				// and no timestamps, and that the outcome survives another
				// reconcile - a partially-issued denial would be the worse bug.
				denial := expectDenied(pod, certificatesv1.PodCertificateRequestConditionInvalidUserConfig)

				By("verifying the denial names the identity constraint and not something else")
				inspect(pod, denial)
			},

			// Resolvable, deliberately unclaimable. ${node.name} and ${pod.uid}
			// are interpolation variables - they resolve - but neither is an
			// identity the workload owns: the node belongs to the kubelet, and a
			// UID identifies nothing. The distinction between "did not parse"
			// and "parsed and was refused" is the whole point of these two
			// entries, so both assert the resolved value appears in the message.
			Entry("the name of the node it happens to run on", "pcs-deny-node-name", map[string]string{
				signerName + "-cn": "${node.name}",
			}, func(pod podRef, denial deniedRequest) {
				Expect(denial.Message).To(ContainSubstring(podNodeName(pod)),
					"the message must quote the resolved node name, proving interpolation ran")
				expectOwnershipDenial(denial)
			}),
			Entry("its own pod UID", "pcs-deny-pod-uid", map[string]string{
				signerName + "-cn": "${pod.uid}",
			}, func(pod podRef, denial deniedRequest) {
				Expect(denial.Message).To(ContainSubstring(string(pod.uid)),
					"the message must quote the resolved UID, proving interpolation ran")
				expectOwnershipDenial(denial)
			}),

			// Exact-match edges. The allowlist is exact string equality, and
			// each of these is a way of being nearly equal to something the pod
			// owns.
			Entry("a verified name behind an attacker prefix", "pcs-deny-name-prefix", map[string]string{
				signerName + "-san": "evil.${pod.name}",
			}, func(pod podRef, denial deniedRequest) {
				Expect(denial.Message).To(ContainSubstring("evil." + pod.name))
				expectOwnershipDenial(denial)
			}),
			// Requested as a common name, not a SAN: an upper-case DNS SAN
			// would be refused as malformed DNS, which is a different layer and
			// would pass this spec for the wrong reason. A common name has no
			// such syntax rule, so only case sensitivity can deny it.
			Entry("an upper-case spelling of the pod name", "pcs-deny-case-cn", map[string]string{
				signerName + "-cn": "PCS-DENY-CASE-CN",
			}, func(_ podRef, denial deniedRequest) {
				Expect(denial.Message).To(ContainSubstring("PCS-DENY-CASE-CN"))
				expectOwnershipDenial(denial)
			}),
			Entry("an upper-case service account in a SPIFFE ID", "pcs-deny-case-uri", map[string]string{
				signerName + "-uris": "spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/DEFAULT",
			}, func(_ podRef, denial deniedRequest) {
				Expect(denial.Message).To(ContainSubstring("/sa/DEFAULT"))
				expectOwnershipDenial(denial)
			}),
			Entry("a verified name with a trailing dot", "pcs-deny-trailing-dot", map[string]string{
				signerName + "-cn": "${pod.name}.${pod.namespace}.svc.${cluster.fqdn}.",
			}, func(pod podRef, denial deniedRequest) {
				Expect(denial.Message).To(ContainSubstring(
					fmt.Sprintf("%s.%s.svc.cluster.local.", pod.name, pod.namespace)))
				expectOwnershipDenial(denial)
			}),

			// A mixed list must deny the request, not filter it. Silently
			// dropping the foreign name would issue a certificate the requester
			// did not ask for and hide that it tried.
			Entry("one foreign name in an otherwise verified list", "pcs-deny-mixed-list", map[string]string{
				signerName + "-san": "${pod.name},evil.example.com",
			}, func(_ podRef, denial deniedRequest) {
				Expect(denial.Message).To(ContainSubstring("evil.example.com"),
					"the denial must name the foreign entry")
				expectOwnershipDenial(denial)
			}),

			// A URI is compared whole. Neither re-parenting an owned SPIFFE path
			// under a foreign trust domain nor extending an owned path makes it
			// an identity the pod owns.
			Entry("an owned SPIFFE path under a foreign trust domain", "pcs-deny-foreign-td", map[string]string{
				signerName + "-uris": "spiffe://attacker.example/ns/${pod.namespace}/sa/${pod.serviceAccountName}",
			}, func(_ podRef, denial deniedRequest) {
				Expect(denial.Message).To(ContainSubstring("spiffe://attacker.example/"))
				expectOwnershipDenial(denial)
			}),
			Entry("an owned SPIFFE ID with an extra path element", "pcs-deny-uri-extra-path", map[string]string{
				signerName + "-uris": "spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}/extra",
			}, func(_ podRef, denial deniedRequest) {
				Expect(denial.Message).To(ContainSubstring("/sa/default/extra"))
				expectOwnershipDenial(denial)
			}),
		)
	})
}

// customClusterFQDN is the DNS suffix the profile below configures. It is not
// cluster.local, which is the point: everything the signer derives must follow
// the operator's setting rather than a constant.
const customClusterFQDN = "e2e.internal"

// customClusterFQDNInstallArgs is the verified-interpolation profile with the
// cluster's DNS suffix changed.
var customClusterFQDNInstallArgs = verifiedInterpolationInstallArgs +
	" --set signer.cluster_fqdn=" + customClusterFQDN

// defineCustomClusterFQDNProfileTests proves the identity allowlist and the
// generated defaults both follow signer.cluster_fqdn.
//
// It costs one further `helm upgrade`, which is why it is a container of its
// own with every FQDN-dependent assertion inside it rather than an option other
// specs set. It is declared after the verified-interpolation container it
// derives from and before chart-defaults, whose install resets the suffix.
func defineCustomClusterFQDNProfileTests() {
	Context("Install profile: custom-cluster-fqdn", func() {
		BeforeAll(func() {
			installProfile(customClusterFQDNInstallArgs)
		})

		It("derives the default DNS SANs from the configured cluster FQDN", func() {
			const podName = "pcs-fqdn-defaults"

			By("creating a workload pod that asks for nothing")
			pod := applyCertTestPod(podName, nil)

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]

			By("verifying the generated SANs carry the configured suffix")
			Expect(leaf.DNSNames).To(ConsistOf(
				fmt.Sprintf("%s.%s.pod.%s", podName, workloadNamespace, customClusterFQDN),
				fmt.Sprintf("%s.%s.svc.%s", podName, workloadNamespace, customClusterFQDN),
			), "the default SANs must use signer.cluster_fqdn, not a hard-coded cluster.local")
		})

		It("accepts interpolated identities under the configured cluster FQDN", func() {
			const podName = "pcs-fqdn-interpolated"

			By("creating a workload pod requesting its identity under ${cluster.fqdn}")
			pod := applyCertTestPod(podName, map[string]string{
				signerName + "-san":  "${pod.name}.${pod.namespace}.svc.${cluster.fqdn}",
				signerName + "-uris": "spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]

			By("verifying the allowlist admitted the identities under the configured suffix")
			Expect(leaf.DNSNames).To(ConsistOf(
				fmt.Sprintf("%s.%s.svc.%s", podName, workloadNamespace, customClusterFQDN)))
			Expect(uriStrings(leaf)).To(ConsistOf(
				fmt.Sprintf("spiffe://%s/ns/%s/sa/default", customClusterFQDN, workloadNamespace)))
		})

		It("denies the same identity under a cluster FQDN the signer is not configured with", func() {
			const podName = "pcs-fqdn-foreign"

			By("creating a workload pod requesting its identity under cluster.local")
			// Byte-for-byte the name the verified-interpolation profile issues
			// happily. Only the operator's configuration changed, so this is the
			// allowlist following it.
			pod := applyCertTestPod(podName, map[string]string{
				signerName + "-san": fmt.Sprintf("%s.%s.svc.cluster.local", podName, workloadNamespace),
			})

			By("waiting for the PodCertificateRequest to be denied")
			denial := expectDenied(pod, certificatesv1.PodCertificateRequestConditionInvalidUserConfig)
			Expect(denial.Message).To(ContainSubstring("svc.cluster.local"))
			expectOwnershipDenial(denial)
		})
	})
}

// refusedIdentityPattern extracts the value the allowlist refused from a
// denial message, which quotes it:
//
//	common name "x.example.org" is not derived from a verified pod identity; ...
//
// The value has to be read out rather than searched for in the whole message:
// the message continues with advice that itself mentions ${...} interpolation,
// so "the message contains no placeholder" is not a statement anything can
// satisfy. What matters is that the *refused value* carries none.
var refusedIdentityPattern = regexp.MustCompile(`"([^"]*)" is not derived from a verified pod identity`)

// expectOwnershipDenial asserts that a denial was the identity allowlist
// refusing a resolved value, and not one of the layers in front of it.
//
// The reason string cannot make this distinction: a malformed DNS name, an
// unresolvable placeholder and an unowned identity all record
// InvalidUserConfig. Only the message can.
func expectOwnershipDenial(denial deniedRequest) {
	GinkgoHelper()

	refused := refusedIdentityPattern.FindStringSubmatch(denial.Message)
	Expect(refused).To(HaveLen(2),
		"the denial must come from the identity allowlist, and name the value it refused; message was: %s",
		denial.Message)
	Expect(refused[1]).NotTo(ContainSubstring("${"),
		"the requested value must have been resolved before ownership refused it, but %q still carries a placeholder",
		refused[1])
	Expect(denial.Message).NotTo(ContainSubstring("unknown interpolation variable"),
		"an unresolvable placeholder is a different denial and must not be mistaken for this one")
}

// uriStrings renders a certificate's URI SANs for comparison.
func uriStrings(cert *x509.Certificate) []string {
	uris := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}
	return uris
}

// podNodeName returns the node the pod was scheduled onto, which is what
// ${node.name} resolves to for its request.
func podNodeName(ref podRef) string {
	GinkgoHelper()

	cmd := exec.Command("kubectl", "get", "pod", ref.name, "-n", ref.namespace,
		"-o", "jsonpath={.spec.nodeName}")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to read the node name for pod %s", ref)

	nodeName := strings.TrimSpace(output)
	Expect(nodeName).NotTo(BeEmpty(), "pod %s must be scheduled for ${node.name} to resolve", ref)
	return nodeName
}
