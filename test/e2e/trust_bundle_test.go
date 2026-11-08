//go:build e2e
// +build e2e

package e2e

import (
	"crypto/x509"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// defineClusterTrustBundleTests registers the specs for the published
// ClusterTrustBundle: that the controller publishes it, and that a CA rotation
// keeps the previous CA in it. They rotate the CA secret, so they run after the
// install profiles (see the Manager Describe in e2e_test.go).
func defineClusterTrustBundleTests() {
	Context("ClusterTrustBundle", func() {
		AfterAll(func() {
			By("removing the ClusterTrustBundle created by the controller")
			cmd := exec.Command("kubectl", "delete", "clustertrustbundle", trustBundleName, "--ignore-not-found=true")
			_, _ = utils.Run(cmd)
		})

		It("should publish the ClusterTrustBundle for the signer", func() {
			By("waiting for the controller to create the ClusterTrustBundle")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "clustertrustbundle", trustBundleName,
					"-o", "jsonpath={.spec.signerName}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "ClusterTrustBundle should exist")
				g.Expect(output).To(Equal(signerName), "ClusterTrustBundle signerName mismatch")
			}).Should(Succeed())

			By("verifying the trust bundle contains valid CA certificates")
			var certs []*x509.Certificate
			Eventually(func(g Gomega) {
				certs = getTrustBundleCertificates(g)
				g.Expect(certs).NotTo(BeEmpty(), "trust bundle must contain at least one certificate")
			}).Should(Succeed())
			for _, cert := range certs {
				Expect(cert.IsCA).To(BeTrue(), "every trust bundle entry must be a CA certificate")
				Expect(time.Now().Before(cert.NotAfter)).To(BeTrue(), "trust bundle CA must not be expired")
			}
		})

		It("should retain the previous CA in the trust bundle after CA rotation", func() {
			By("capturing the currently published CA")
			var previousCA *x509.Certificate
			Eventually(func(g Gomega) {
				certs := getTrustBundleCertificates(g)
				g.Expect(certs).NotTo(BeEmpty())
				previousCA = certs[0]
			}).Should(Succeed())

			By("generating a new CA and updating the CA secret")
			// caLifecycleValidity, because this CA stays current for whatever
			// runs next: a CA valid for exactly the default certificate
			// lifetime cannot sign a default certificate, since the signer
			// backdates notBefore by a minute. See the constant.
			rotatedCA, err := testutil.NewCA("rotated-ca.example.org", caLifecycleValidity)
			Expect(err).NotTo(HaveOccurred(), "Failed to generate the rotated CA")
			updateCASecret(rotatedCA)

			// Kubelet propagates secret updates to the mounted volume on its
			// sync period (~1 minute), after which the controller reloads the
			// CA and updates the ClusterTrustBundle.
			By("waiting for the trust bundle to publish the new CA and retain the previous one")
			Eventually(func(g Gomega) {
				certs := getTrustBundleCertificates(g)
				g.Expect(certs).NotTo(BeEmpty())
				g.Expect(certs[0].Equal(rotatedCA.Cert)).To(BeTrue(),
					"the first trust bundle entry must be the rotated CA")
				g.Expect(containsCertificate(certs, previousCA)).To(BeTrue(),
					"the previous CA must be retained in the trust bundle")
			}, 5*time.Minute).Should(Succeed())
		})
	})
}
