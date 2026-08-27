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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// Workload credential conformance.
//
// Everything else in this suite reads the PodCertificateRequest status from
// outside the cluster, which answers "did the signer produce a certificate" and
// nothing about whether the workload can use it. These specs close that: the
// workload is the credential probe (test/credprobe), it reads the projected
// volume as the non-root user the container runs as, and it completes real TLS
// 1.3 handshakes with the projected key against the projected trust anchors.
// The suite then judges the probe's report against the request status and the
// published ClusterTrustBundle, so neither half can grade its own homework.
//
// They run under the chart-defaults profile, where nothing is turned on. That
// is deliberate and is the other gap this file closes: until now the shipped
// configuration was only ever proven to *deny* (see
// defineChartDefaultsProfileTests), and nothing showed that an unmodified
// install hands a workload a usable credential.

// defaultCertificateLifetime is what the signer issues when nothing asks for
// anything else: podcertificate.DefaultDuration, clamped by the projection's
// maxExpirationSeconds, which kube-apiserver defaults to the same 24 hours.
const defaultCertificateLifetime = 24 * time.Hour

// defaultMaxExpirationSeconds is kube-apiserver's default for a podCertificate
// projection that does not set maxExpirationSeconds. It is asserted rather than
// assumed: it is the other half of the lifetime above, so if the apiserver
// default ever moves, this says why the lifetime changed.
const defaultMaxExpirationSeconds = int32(86400)

// defaultChainLength is how many certificates an issued chain carries: the leaf
// and the CA that signed it.
const defaultChainLength = 2

// probeTimeout bounds the wait for the probe to publish its report. It covers
// pulling nothing (the image is loaded into Kind) but does cover kubelet
// blocking pod start until the certificate is issued.
const probeTimeout = 3 * time.Minute

// defineCredentialConformanceTests is called from the chart-defaults install
// profile, so these specs describe the chart exactly as it ships.
func defineCredentialConformanceTests() {
	Context("Workload credential conformance", func() {
		var trustAnchors []string

		BeforeAll(func() {
			By("waiting for the signer to publish its ClusterTrustBundle")
			// The probe pods project the bundle by name, and kubelet blocks pod
			// start until it exists. Waiting here turns a missing bundle into
			// one clear failure rather than every spec below timing out on a
			// pod stuck in ContainerCreating.
			Eventually(func(g Gomega) {
				certs := getTrustBundleCertificates(g)
				g.Expect(certs).NotTo(BeEmpty(), "the trust bundle must carry the current CA")
				trustAnchors = certificateFingerprints(certs)
			}).Should(Succeed())
		})

		It("delivers a usable default credential to a workload that asks for nothing", func() {
			const podName = "pcs-defaults-credential"

			By("creating a workload pod with no annotations and no feature flags in play")
			pod := createCertTestPod(certTestPod{
				name:                   podName,
				image:                  workloadProbeImage,
				args:                   probeArgs(podName, report.RoleServer),
				clusterTrustBundleName: trustBundleName,
			})

			By("waiting for the PodCertificateRequest to be issued")
			chain := expectIssued(pod)

			By("verifying the chain is the leaf and its issuing CA")
			Expect(chain).To(HaveLen(defaultChainLength),
				"an issued chain must carry the leaf and the CA that signed it")
			leaf, issuer := chain[0], chain[1]
			Expect(issuer.IsCA).To(BeTrue(), "the second chain entry must be the issuing CA")
			Expect(leaf.CheckSignatureFrom(issuer)).To(Succeed(),
				"the leaf must be signed by the CA it is served with")

			By("verifying the default subject and the two canonical DNS SANs")
			Expect(leaf.Subject.CommonName).To(Equal(podName),
				"the default common name is the pod name")
			Expect(leaf.DNSNames).To(ConsistOf(
				fmt.Sprintf("%s.%s.pod.cluster.local", podName, workloadNamespace),
				fmt.Sprintf("%s.%s.svc.cluster.local", podName, workloadNamespace),
			), "the default SANs are the canonical pod and service DNS forms")

			By("verifying no identity beyond those DNS names was asserted")
			Expect(leaf.IPAddresses).To(BeEmpty(), "the defaults must add no IP SAN")
			Expect(leaf.URIs).To(BeEmpty(), "the defaults must add no URI SAN")

			By("verifying the default extended key usage and lifetime")
			Expect(leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth),
				"the default EKU is serverAuth only")
			Expect(leaf.UnknownExtKeyUsage).To(BeEmpty(),
				"the defaults must add no extended key usage the suite cannot name")
			request := getPodCertificateRequest(pod)
			Expect(request.Spec.MaxExpirationSeconds).NotTo(BeNil(),
				"kube-apiserver defaults maxExpirationSeconds on the projection")
			Expect(*request.Spec.MaxExpirationSeconds).To(Equal(defaultMaxExpirationSeconds),
				"the default lifetime below is the signer default clamped by this")
			Expect(leaf.NotAfter.Sub(leaf.NotBefore)).To(Equal(defaultCertificateLifetime),
				"the default certificate lifetime must be exact")

			By("waiting for the pod to run with the projected credential")
			expectPodRunning(pod)

			By("verifying the workload can read and use the credential it was given")
			observed := expectProbeReport(pod, report.RoleServer)

			By("verifying the projected chain is the one the request status published")
			Expect(observed.Facts.ChainSHA256).To(Equal(certificateFingerprints(chain)),
				"the credential bundle must carry exactly the chain from the request status")

			By("verifying the projected trust anchors are the published ClusterTrustBundle")
			Expect(observed.Facts.TrustSHA256).To(Equal(trustAnchors),
				"ca.crt must carry exactly the anchors the signer published")
			Expect(observed.Facts.TrustSHA256).To(ContainElement(fingerprint(issuer)),
				"the trust anchors must include the CA that signed the leaf")
		})

		It("delivers a client-auth credential that works only in the client role", func() {
			const podName = "pcs-defaults-client-credential"

			By("creating a workload pod requesting a client-auth certificate")
			// The eku annotation names a key usage, not an identity, so it is
			// accepted under the chart defaults: no ${...} to resolve, and
			// nothing for the identity allowlist to judge.
			pod := createCertTestPod(certTestPod{
				name:                   podName,
				image:                  workloadProbeImage,
				args:                   probeArgs(podName, report.RoleClient),
				clusterTrustBundleName: trustBundleName,
				userAnnotations:        map[string]string{signerName + "-eku": "client"},
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]

			By("verifying the certificate is restricted to client authentication")
			Expect(leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageClientAuth))

			By("waiting for the pod to run with the projected credential")
			expectPodRunning(pod)

			By("verifying the credential authenticates as a client and is refused as a server")
			observed := expectProbeReport(pod, report.RoleClient)
			Expect(observed.Facts.LeafExtKeyUsage).To(ConsistOf("clientAuth"),
				"the projected leaf must carry the same restriction as the issued one")
		})
	})
}

// probeArgs configures the credential probe for a pod.
//
// The unrelated name is built from the pod's own name under a foreign suffix
// rather than something arbitrary: the interesting negative is not "a name from
// another universe is rejected" but "a name that starts like mine is", which is
// the same exact-match boundary the identity allowlist enforces on the issuing
// side.
func probeArgs(podName, role string) []string {
	return []string{
		"-role=" + role,
		fmt.Sprintf("-expect-chain-len=%d", defaultChainLength),
		fmt.Sprintf("-allowed-dns=%s.%s.pod.cluster.local", podName, workloadNamespace),
		fmt.Sprintf("-unrelated-dns=%s.%s.pod.attacker.example", podName, workloadNamespace),
		fmt.Sprintf("-bundle=%s/%s", certTestPodMountPath, defaultCredentialBundlePath),
		fmt.Sprintf("-trust=%s/ca.crt", certTestPodMountPath),
	}
}

// expectProbeReport waits for the probe to publish its report and asserts that
// it ran every check for its role and passed all of them.
//
// The report is the failure message. A red check states what it observed - the
// PEM block types it found, the fingerprints, the classified TLS error - so a
// failing run needs no second run to explain itself.
func expectProbeReport(ref podRef, role string) report.Report {
	GinkgoHelper()

	var observed report.Report
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "logs", ref.name, "-n", ref.namespace)
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred(),
			"reading the probe log for pod %s failed; %s", ref, podStatusSummary(ref))

		parsed, err := report.Parse(output)
		g.Expect(err).NotTo(HaveOccurred(),
			"the probe for pod %s has not reported: %v; %s; log was: %s",
			ref, err, podStatusSummary(ref), output)
		observed = parsed
	}, probeTimeout).Should(Succeed())

	Expect(observed.Role).To(Equal(role), "the probe reported for the wrong role")
	Expect(observed.CheckNames()).To(Equal(report.ExpectedChecks(role)),
		"the probe must run every check for the %s role; a short report means it stopped early\n%s",
		role, observed)
	Expect(observed.Failures()).To(BeEmpty(),
		"the projected credential failed conformance checks\n%s", observed)

	return observed
}

// expectPodRunning waits for the workload pod to reach Running.
//
// For a pod with a podCertificate projection this is an assertion about the
// signer: kubelet does not start the container until the request is issued and
// the credential is written, so a pod that never runs is a credential that was
// never delivered.
func expectPodRunning(ref podRef) {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "pod", ref.name, "-n", ref.namespace,
			"-o", "jsonpath={.status.phase}")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(output).To(Equal("Running"),
			"pod %s must run once kubelet mounts the issued credential; %s", ref, podStatusSummary(ref))
	}, probeTimeout).Should(Succeed())
}

// podStatusSummary renders a pod's phase and container states for a failure
// message. It never asserts: it runs while something else is already failing.
func podStatusSummary(ref podRef) string {
	cmd := exec.Command("kubectl", "get", "pod", ref.name, "-n", ref.namespace,
		"-o", "jsonpath={.status.phase}{\" \"}{.status.containerStatuses[*].state}")
	output, err := utils.Run(cmd)
	if err != nil {
		return fmt.Sprintf("pod status for %s unavailable: %v", ref, err)
	}
	return fmt.Sprintf("pod status: %s", strings.TrimSpace(output))
}

// getPodCertificateRequest returns the request belonging to the pod, for the
// spec fields expectIssued does not surface.
func getPodCertificateRequest(ref podRef) *certificatesv1.PodCertificateRequest {
	GinkgoHelper()

	var request *certificatesv1.PodCertificateRequest
	Eventually(func(g Gomega) {
		request = findPodCertificateRequest(g, ref)
	}).Should(Succeed())
	return request
}

// certificateFingerprints returns the SHA-256 fingerprints of a chain, in the
// same encoding the probe reports, so the two can be compared directly.
func certificateFingerprints(certs []*x509.Certificate) []string {
	fingerprints := make([]string, 0, len(certs))
	for _, cert := range certs {
		fingerprints = append(fingerprints, fingerprint(cert))
	}
	return fingerprints
}

// fingerprint returns the SHA-256 fingerprint of a certificate.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
