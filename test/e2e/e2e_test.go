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
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// namespace where the project is deployed in
const namespace = "pcs-system"

// releaseName is the Helm release (and thereby resource fullname) of the deployment
const releaseName = "podcertificate-signer"

// serviceAccountName created by the Helm chart
const serviceAccountName = releaseName

// metricsServiceName is the name of the service exposing the metrics port
const metricsServiceName = releaseName

// signerName the controller is deployed with (see the chart values signer.name)
const signerName = "example.org/signer"

// trustBundleName is the ClusterTrustBundle the controller maintains for the signer
const trustBundleName = "example.org:signer:bundle"

// caSecretName is the kubernetes.io/tls secret mounted into the controller as its CA
// (see examples/ca_tls_secret.yaml)
const caSecretName = "podcertificate-signer-ca"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("deploying the controller-manager via Helm")
		// A single replica keeps the pod-targeted assertions (logs, pod
		// phase) deterministic; the chart default is 2 for leader election.
		cmd = exec.Command("make", "helm-install",
			fmt.Sprintf("IMAGE=%s", projectImage),
			"HELM_EXTRA_ARGS=--set replicaCount=1")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("uninstalling the Helm release")
		cmd = exec.Command("make", "helm-uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect logs, events,
	// and pod descriptions for debugging.
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", fmt.Sprintf("app.kubernetes.io/instance=%s", releaseName),
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring(releaseName))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("validating that the metrics service is available")
			cmd := exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("9090"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v http://%s.%s.svc.cluster.local:9090/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring(
				"controller_runtime_reconcile_total",
			))
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		// TODO: Customize the e2e test suite with scenarios specific to your project.
		// Consider applying sample/CR(s) and check their status and/or verifying
		// the reconciliation by using the metrics, i.e.:
		// metricsOutput := getMetricsOutput()
		// Expect(metricsOutput).To(ContainSubstring(
		//    fmt.Sprintf(`controller_runtime_reconcile_total{controller="%s",result="success"} 1`,
		//    strings.ToLower(<Kind>),
		// ))
	})

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
			rotatedCA, err := testutil.NewCA("rotated-ca.example.org", 24*time.Hour)
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
})

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
