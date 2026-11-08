//go:build e2e
// +build e2e

package e2e

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	metricsOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
	return metricsOutput
}

// getTrustBundleCertificates reads the ClusterTrustBundle of the signer and
// parses all certificates from its trust bundle PEM.
func getTrustBundleCertificates(g Gomega) []*x509.Certificate {
	cmd := exec.Command("kubectl", "get", "clustertrustbundle", trustBundleName,
		"-o", "jsonpath={.spec.trustBundle}")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to read the ClusterTrustBundle")

	var certs []*x509.Certificate
	data := []byte(output)
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		g.Expect(block.Type).To(Equal("CERTIFICATE"), "trust bundle must contain only CERTIFICATE blocks")
		cert, err := x509.ParseCertificate(block.Bytes)
		g.Expect(err).NotTo(HaveOccurred(), "trust bundle entry must be a valid certificate")
		certs = append(certs, cert)
	}
	return certs
}

// containsCertificate reports whether certs contains the given certificate.
func containsCertificate(certs []*x509.Certificate, want *x509.Certificate) bool {
	for _, cert := range certs {
		if cert.Equal(want) {
			return true
		}
	}
	return false
}

// updateCASecret replaces the controller CA secret with the given key pair.
// Kubelet propagates the change to the mounted volume, which the controller
// picks up via its file watcher.
func updateCASecret(kp *testutil.KeyPair) {
	dir, err := os.MkdirTemp("", "pcs-e2e-ca")
	Expect(err).NotTo(HaveOccurred(), "Failed to create temp dir for the rotated CA")
	DeferCleanup(func() { _ = os.RemoveAll(dir) })

	certPath, keyPath, err := kp.WriteFiles(dir)
	Expect(err).NotTo(HaveOccurred(), "Failed to write the rotated CA files")

	cmd := exec.Command("kubectl", "create", "secret", "tls", caSecretName,
		"-n", namespace,
		"--cert", certPath,
		"--key", keyPath,
		"--dry-run=client", "-o", "yaml")
	secretYAML, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to render the rotated CA secret")

	secretFile := filepath.Join(dir, "ca-secret.yaml")
	Expect(os.WriteFile(secretFile, []byte(secretYAML), os.FileMode(0o600))).To(Succeed())

	cmd = exec.Command("kubectl", "apply", "-f", secretFile)
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to apply the rotated CA secret")
}
