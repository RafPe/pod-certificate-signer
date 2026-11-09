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
	"net"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
)

// Escape-hatch invariants.
//
// --allow-unverified-identities lets a pod ask for identities it does not own.
// That is what it is for, and the specs above it prove it works. What it must
// not become is a switch that turns off validation in general: with the hatch
// open, a malformed DNS name is still malformed, an unparseable duration is
// still unparseable, and an unknown extended key usage is still unknown. This
// container asserts that the relaxation is scoped to ownership and to nothing
// else.
//
// It runs under the suite's initial unverified-identities install
// (e2e_test.go), so it adds no Helm upgrade.

// defineEscapeHatchInvariantTests is called from the top-level Describe while
// the unverified-identities profile is installed.
func defineEscapeHatchInvariantTests() {
	Context("Escape-hatch invariants", func() {
		It("issues literal identities the pod does not own", func() {
			const podName = "pcs-hatch-literals"

			By("creating a workload pod requesting a name, addresses and a URI belonging to nobody")
			// Every value here is a literal: no ${...}, nothing derived from the
			// request, and none of it in the allowlist. Only the open hatch can
			// issue this certificate, which is what makes it the baseline the
			// denials below are measured against.
			pod := applyCertTestPod(podName, map[string]string{
				signerName + "-cn":     "hatch.example.org",
				signerName + "-san":    "api.hatch.example.org,web.hatch.example.org",
				signerName + "-ip-san": "10.96.0.7,2001:db8::7",
				signerName + "-uris":   "spiffe://attacker.example/ns/foreign/sa/root",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]

			By("verifying every requested identity was issued verbatim")
			Expect(leaf.Subject.CommonName).To(Equal("hatch.example.org"))
			Expect(leaf.DNSNames).To(ConsistOf("api.hatch.example.org", "web.hatch.example.org"))
			Expect(leaf.IPAddresses).To(HaveLen(2))
			Expect(leaf.IPAddresses[0].Equal(net.ParseIP("10.96.0.7"))).To(BeTrue(),
				"the first IP SAN must be the requested IPv4 address, got %v", leaf.IPAddresses[0])
			Expect(leaf.IPAddresses[1].Equal(net.ParseIP("2001:db8::7"))).To(BeTrue(),
				"the second IP SAN must be the requested IPv6 address, got %v", leaf.IPAddresses[1])
			Expect(uriStrings(leaf)).To(ConsistOf("spiffe://attacker.example/ns/foreign/sa/root"))

			By("verifying the hatch changed who may be named, not what else is issued")
			Expect(leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth),
				"the default extended key usage must not change with the hatch open")
			Expect(leaf.IsCA).To(BeFalse())
		})

		DescribeTable("still rejects malformed values when the ownership check is off",
			func(fixture certTestPod, wantMessage string) {
				By("creating a workload pod requesting a value no configuration can make valid")
				pod := createCertTestPod(fixture)

				By("waiting for the PodCertificateRequest to be denied")
				denial := expectDenied(pod, certificatesv1.PodCertificateRequestConditionInvalidUserConfig)
				Expect(denial.Message).To(ContainSubstring(wantMessage))

				By("verifying the denial is about the malformed value, not about ownership")
				Expect(denial.Message).NotTo(ContainSubstring("is not derived from a verified pod identity"),
					"the ownership check is off; a denial citing it would mean the hatch did not apply")
			},

			// The DNS SAN goes through the deprecated pod-annotation fallback
			// rather than the projection. The DNS SAN ValidatingAdmissionPolicy
			// reads only the projection's userAnnotations and would refuse this
			// pod at admission, so requesting it there would prove the policy
			// works - which defineAdmissionPolicyTests already does - and would
			// never reach the signer's own DNS validation, which is what this
			// entry is for. When the deprecated pod-annotation path is removed,
			// this entry needs an install profile with the policy disabled.
			Entry("a malformed DNS name", certTestPod{
				name: "pcs-hatch-bad-dns",
				podAnnotations: map[string]string{
					signerName + "-san": "not_a_dns_name.example.org",
				},
			}, `DNS name "not_a_dns_name.example.org" is invalid`),

			Entry("a malformed IP address", certTestPod{
				name: "pcs-hatch-bad-ip",
				userAnnotations: map[string]string{
					signerName + "-ip-san": "10.96.0.999",
				},
			}, `invalid IP address "10.96.0.999"`),

			Entry("a URI with no scheme", certTestPod{
				name: "pcs-hatch-bad-uri",
				userAnnotations: map[string]string{
					signerName + "-uris": "hatch.example.org/workload",
				},
			}, "missing scheme"),

			Entry("an unknown extended key usage", certTestPod{
				name: "pcs-hatch-bad-eku",
				userAnnotations: map[string]string{
					signerName + "-eku": "sign-anything",
				},
			}, `unknown extended key usage "sign-anything"`),

			Entry("an unparseable duration", certTestPod{
				name: "pcs-hatch-bad-duration",
				userAnnotations: map[string]string{
					signerName + "-duration": "2 hours",
				},
			}, `invalid duration "2 hours"`),

			Entry("an unparseable refresh window", certTestPod{
				name: "pcs-hatch-bad-refresh",
				userAnnotations: map[string]string{
					signerName + "-refresh": "soon",
				},
			}, `invalid duration "soon"`),
		)
	})
}
