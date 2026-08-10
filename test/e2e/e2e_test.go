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
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// workloadPodName / workloadNamespace identify the example workload pod
// (examples/workload-pod.yaml) used by the certificate issuance spec
const workloadPodName = "pcs-example-workload"
const workloadNamespace = "default"

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
		// Interpolation is enabled so specs can use ${...} placeholders, and
		// unverified identities are allowed so the issuance specs can exercise
		// custom cn/san/ip-san/eku values end to end. Denial of unverified
		// identities under the secure default is covered by the podcertificate
		// unit tests (identity_constraints_test.go).
		cmd = exec.Command("make", "helm-install",
			fmt.Sprintf("IMAGE=%s", projectImage),
			"HELM_EXTRA_ARGS=--set replicaCount=1 --set signer.enable_annotation_interpolation=true --set signer.allow_unverified_identities=true")
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

	Context("Certificate issuance", func() {
		It("should issue a certificate with interpolated pod identity", func() {
			By("creating a workload pod requesting an interpolated certificate")
			applyWorkloadPod()
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", workloadPodName,
					"-n", workloadNamespace, "--ignore-not-found=true", "--wait=false")
				_, _ = utils.Run(cmd)
			})

			By("waiting for the PodCertificateRequest to be issued")
			chain := waitForIssuedChain(workloadPodName)

			By("verifying the leaf certificate carries the interpolated values")
			leaf := chain[0]
			wantCN := fmt.Sprintf("%s.%s.svc.cluster.local", workloadPodName, workloadNamespace)
			Expect(leaf.Subject.CommonName).To(Equal(wantCN),
				"common name must be interpolated from the pod identity")
			Expect(leaf.DNSNames).To(ConsistOf(
				fmt.Sprintf("%s.%s.svc", workloadPodName, workloadNamespace),
				fmt.Sprintf("default.%s.svc", workloadNamespace), // ${pod.serviceAccountName} = default
			), "SANs must be interpolated from the pod identity")
			Expect(leaf.IPAddresses).To(HaveLen(1), "the ip-san annotation must yield one IP SAN")
			Expect(leaf.IPAddresses[0].Equal(net.ParseIP("10.96.0.99"))).To(BeTrue(),
				"IP SAN must match the ip-san annotation in examples/workload-pod.yaml")

			By("waiting for the pod to run with the projected certificate")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pod", workloadPodName,
					"-n", workloadNamespace, "-o", "jsonpath={.status.phase}")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"),
					"pod must start once kubelet mounts the issued credential bundle")
			}, 3*time.Minute).Should(Succeed())
		})

		It("should deliver a custom common name and DNS SANs in the issued certificate", func() {
			const podName = "pcs-custom-san"
			By("creating a workload pod with static cn and san annotations")
			applyCertTestPod(podName, map[string]string{
				signerName + "-cn":  "custom-cn.example.org",
				signerName + "-san": "api.example.org,web.example.org",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := waitForIssuedChain(podName)[0]

			By("verifying the configured values are delivered in the leaf certificate")
			Expect(leaf.Subject.CommonName).To(Equal("custom-cn.example.org"),
				"common name must match the cn annotation")
			Expect(leaf.DNSNames).To(ConsistOf("api.example.org", "web.example.org"),
				"DNS SANs must match the san annotation, replacing the defaults")
			Expect(leaf.IPAddresses).To(BeEmpty(),
				"no IP SANs were requested")
		})

		It("should deliver the requested IP SANs in the issued certificate", func() {
			const podName = "pcs-ip-san"
			By("creating a workload pod with an ip-san annotation")
			applyCertTestPod(podName, map[string]string{
				signerName + "-cn":     "ip-demo.example.org",
				signerName + "-ip-san": "10.96.0.42,2001:db8::42",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := waitForIssuedChain(podName)[0]

			By("verifying the IP SANs are delivered in the leaf certificate")
			Expect(leaf.IPAddresses).To(HaveLen(2), "both requested IP SANs must be present")
			Expect(leaf.IPAddresses[0].Equal(net.ParseIP("10.96.0.42"))).To(BeTrue(),
				"first IP SAN must be the requested IPv4 address, got %v", leaf.IPAddresses[0])
			Expect(leaf.IPAddresses[1].Equal(net.ParseIP("2001:db8::42"))).To(BeTrue(),
				"second IP SAN must be the requested IPv6 address, got %v", leaf.IPAddresses[1])

			By("verifying the DNS SANs fall back to the defaults")
			Expect(leaf.DNSNames).To(ConsistOf(
				fmt.Sprintf("%s.%s.pod.cluster.local", podName, workloadNamespace),
				fmt.Sprintf("%s.%s.svc.cluster.local", podName, workloadNamespace),
			), "DNS SANs must be the controller defaults when no san annotation is set")
		})

		It("should deliver a client-only certificate when eku restricts it", func() {
			const podName = "pcs-eku-client"
			By("creating a workload pod with an eku annotation")
			applyCertTestPod(podName, map[string]string{
				signerName + "-cn":  "eku-demo.example.org",
				signerName + "-eku": "client",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := waitForIssuedChain(podName)[0]

			By("verifying the certificate is restricted to client auth")
			Expect(leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageClientAuth),
				"eku=client must yield a client-auth-only certificate")
		})
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

// applyWorkloadPod creates the example workload pod, whose podCertificate
// projected volume requests a certificate customized via ${...}
// interpolation (see examples/workload-pod.yaml).
func applyWorkloadPod() {
	cmd := exec.Command("kubectl", "apply", "-f", "examples/workload-pod.yaml")
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to create the workload pod")
}

// applyCertTestPod creates a minimal workload pod whose podCertificate
// projected volume carries the given userAnnotations, and registers its
// cleanup.
func applyCertTestPod(podName string, userAnnotations map[string]string) {
	var annotations strings.Builder
	for key, value := range userAnnotations {
		fmt.Fprintf(&annotations, "            %s: %q\n", key, value)
	}

	manifest := fmt.Sprintf(`apiVersion: v1
kind: Pod
metadata:
  name: %s
  namespace: %s
spec:
  restartPolicy: Never
  containers:
  - name: sleeper
    image: busybox:1.37
    command: ["sleep", "600"]
    securityContext:
      allowPrivilegeEscalation: false
      runAsNonRoot: true
      runAsUser: 65532
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: x509
      mountPath: /var/run/x509
      readOnly: true
  volumes:
  - name: x509
    projected:
      sources:
      - podCertificate:
          keyType: ED25519
          signerName: %s
          credentialBundlePath: credentialbundle.pem
          userAnnotations:
%s`, podName, workloadNamespace, signerName, annotations.String())

	dir, err := os.MkdirTemp("", "pcs-e2e-pod")
	Expect(err).NotTo(HaveOccurred(), "Failed to create temp dir for the pod manifest")
	DeferCleanup(func() { _ = os.RemoveAll(dir) })

	manifestFile := filepath.Join(dir, "pod.yaml")
	Expect(os.WriteFile(manifestFile, []byte(manifest), os.FileMode(0o600))).To(Succeed())

	cmd := exec.Command("kubectl", "apply", "-f", manifestFile)
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to create pod %s", podName)

	DeferCleanup(func() {
		cmd := exec.Command("kubectl", "delete", "pod", podName,
			"-n", workloadNamespace, "--ignore-not-found=true", "--wait=false")
		_, _ = utils.Run(cmd)
	})
}

// waitForIssuedChain waits until the PodCertificateRequest of the given pod
// is issued and returns the parsed certificate chain.
func waitForIssuedChain(podName string) []*x509.Certificate {
	GinkgoHelper()
	var chain []*x509.Certificate
	Eventually(func(g Gomega) {
		chain = getIssuedCertificateChain(g, podName, workloadNamespace)
		g.Expect(chain).NotTo(BeEmpty())
	}, 3*time.Minute).Should(Succeed())
	return chain
}

// getIssuedCertificateChain finds the PodCertificateRequest belonging to the
// given pod and, once it carries an Issued condition, parses its certificate
// chain.
func getIssuedCertificateChain(g Gomega, podName, namespace string) []*x509.Certificate {
	cmd := exec.Command("kubectl", "get", "podcertificaterequests",
		"-n", namespace, "-o", "json")
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

	for _, item := range list.Items {
		if item.Spec.PodName != podName {
			continue
		}
		for _, cond := range item.Status.Conditions {
			g.Expect(cond.Type).To(Equal("Issued"),
				"request must not be %s: %s: %s", cond.Type, cond.Reason, cond.Message)
		}
		if item.Status.CertificateChain == "" {
			continue
		}

		var certs []*x509.Certificate
		data := []byte(item.Status.CertificateChain)
		for {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			g.Expect(err).NotTo(HaveOccurred(), "chain entry must be a valid certificate")
			certs = append(certs, cert)
		}
		return certs
	}

	return nil
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
