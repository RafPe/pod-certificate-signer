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
	"net"
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
const releaseName = "pod-certificate-signer"

// serviceAccountName created by the Helm chart
const serviceAccountName = releaseName

// metricsServiceName is the name of the service exposing the metrics port
const metricsServiceName = releaseName

// metricsReaderClusterRole is the ClusterRole the chart renders granting GET on
// the /metrics nonResourceURL; a scraper's ServiceAccount must be bound to it to
// be authorized by the secured metrics endpoint.
const metricsReaderClusterRole = releaseName + "-metrics-reader"

// metricsReaderBinding is the ClusterRoleBinding the e2e creates to authorize the
// controller ServiceAccount (used by the curl pod) to scrape the metrics endpoint.
const metricsReaderBinding = releaseName + "-e2e-metrics-reader"

// signerName the controller is deployed with (see the chart values signer.name)
const signerName = "example.org/signer"

// trustBundleName is the ClusterTrustBundle the controller maintains for the signer
const trustBundleName = "example.org:signer:bundle"

// caSecretName is the kubernetes.io/tls secret mounted into the controller as its CA.
// `make helm-install` generates an ephemeral dev CA into this secret (DEV_CA_SECRET)
// and points the chart's CA volume at it, so the e2e must use the same name.
const caSecretName = "podcertificate-signer-ca-dev"

// workloadPodName / workloadNamespace identify the example workload pod
// (examples/workload-pod.yaml) used by the certificate issuance spec
const workloadPodName = "pcs-example-workload"
const workloadNamespace = "default"

// controllerPodName is the controller pod the pod-targeted assertions and the
// AfterEach failure dump read from. It is package-level rather than a closure
// variable because each install profile (install_profiles_test.go) rolls the
// deployment, after which the previously resolved name points at a terminated
// pod; installProfile re-resolves it.
var controllerPodName string

// The suite is Serial as well as Ordered. Ordered fixes the declaration order
// the install profiles depend on; Serial states the other half of the
// contract - no other spec may run alongside these, because installProfile
// re-installs the release in place and a profile switch is cluster-wide. The
// belt-and-braces single-process guard lives in BeforeSuite (e2e_suite_test.go),
// which fails the whole run rather than letting a parallel invocation corrupt
// state one spec at a time.
var _ = Describe("Manager", Ordered, Serial, func() {
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
		// A single replica keeps the pod-targeted assertions (logs, pod phase)
		// deterministic; the chart default is 2 for leader election.
		//
		// This is the unverified-identities profile: the identity allowlist
		// disabled, so the specs below can request literal values
		// (custom-cn.example.org, literal IP SANs) that a pod does not own.
		// Interpolation is on because it is the chart default, not because this
		// profile asks for it - see the note above the const block in
		// install_profiles_test.go. It is deliberately not the whole suite: the
		// chart's shipped defaults, the verified-interpolation path and the
		// interpolation opt-out are exercised by their own install profiles.
		// Keeping this profile first means the pre-existing specs are
		// unaffected by the profile split.
		cmd = exec.Command("make", "helm-install",
			fmt.Sprintf("IMAGE=%s", projectImage),
			"HELM_EXTRA_ARGS="+unverifiedIdentitiesInstallArgs)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("removing the metrics-reader ClusterRoleBinding")
		cmd = exec.Command("kubectl", "delete", "clusterrolebinding", metricsReaderBinding, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)

		By("uninstalling the Helm release")
		cmd = exec.Command("make", "helm-uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	// After each test, check for failures and collect the full diagnostic set
	// (see diagnostics_test.go) so a CI failure is debuggable from the run's
	// output alone.
	AfterEach(func() {
		if CurrentSpecReport().Failed() {
			dumpDiagnostics()
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

		It("should reject unauthenticated scrapes and serve metrics to an authorized client", func() {
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

			By("verifying that the controller manager is serving the metrics server securely")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("authorizing the controller ServiceAccount to scrape via the metrics-reader ClusterRole")
			// The secured endpoint authorizes GET on the /metrics nonResourceURL
			// via SubjectAccessReview. Bind the chart's metrics-reader ClusterRole
			// to the controller ServiceAccount, which the curl pod runs as, so the
			// authenticated scrape is authorized.
			cmd = exec.Command("kubectl", "create", "clusterrolebinding", metricsReaderBinding,
				"--clusterrole", metricsReaderClusterRole,
				"--serviceaccount", fmt.Sprintf("%s:%s", namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create the metrics-reader ClusterRoleBinding")
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "clusterrolebinding", metricsReaderBinding, "--ignore-not-found=true")
				_, _ = utils.Run(cmd)
			})

			By("creating the curl-metrics pod that probes the endpoint unauthenticated and authenticated")
			// One pod issues both requests so cleanup, the failure-dump and
			// getMetricsOutput() all key off the single "curl-metrics" pod:
			//   1. an unauthenticated HTTPS scrape, expected to be rejected 401;
			//   2. an authenticated HTTPS scrape presenting the pod's projected
			//      ServiceAccount token, expected 200 with the metrics body.
			// -k skips verification of the controller's in-memory self-signed
			// serving certificate; the guarantee under test is authn/authz, not
			// the serving-cert trust chain. --http1.1 keeps the verbose status
			// line as "HTTP/1.1 200 OK": the server advertises h2 via ALPN, and
			// without pinning the version curl would negotiate HTTP/2.
			// The authorized scrape retries: the SubjectAccessReview can briefly
			// deny (and cache the deny for 30s) if the ClusterRoleBinding has not
			// propagated to the apiserver authorizer when the first request fires.
			metricsURL := fmt.Sprintf("https://%s.%s.svc.cluster.local:9090/metrics", metricsServiceName, namespace)
			curlScript := fmt.Sprintf(
				"echo '=== unauthenticated ==='; "+
					"curl -sk --http1.1 -o /dev/null -w 'unauth_status=%%{http_code}\\n' %s; "+
					"echo '=== authenticated ==='; "+
					"for i in 1 2 3 4 5 6; do "+
					// -f makes curl exit non-zero on an HTTP error (e.g. a 403
					// from a not-yet-propagated authorization) so the loop retries
					// rather than breaking on the first non-200.
					"curl -fsk --http1.1 -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" -v %s "+
					"&& break; echo 'retrying authorized scrape'; sleep 10; done",
				metricsURL, metricsURL)
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
							"args": [%q],
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
				}`, curlScript, serviceAccountName))
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

			By("verifying the unauthenticated scrape was rejected")
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring("unauth_status=401"),
				"an unauthenticated scrape of the secured endpoint must be rejected with 401")

			By("verifying the authenticated scrape returned the metrics")
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
			pod := applyWorkloadPod()
			DeferCleanup(func() {
				cmd := exec.Command("kubectl", "delete", "pod", workloadPodName,
					"-n", workloadNamespace, "--ignore-not-found=true", "--wait=false")
				_, _ = utils.Run(cmd)
			})

			By("waiting for the PodCertificateRequest to be issued")
			chain := expectIssued(pod)

			By("verifying the leaf certificate carries the interpolated values")
			leaf := chain[0]
			wantCN := fmt.Sprintf("%s.%s.svc.cluster.local", workloadPodName, workloadNamespace)
			Expect(leaf.Subject.CommonName).To(Equal(wantCN),
				"common name must be interpolated from the pod identity")
			Expect(leaf.DNSNames).To(ConsistOf(
				fmt.Sprintf("%s.%s.svc", workloadPodName, workloadNamespace),
				// The short service-account form. ${pod.serviceAccountName} is
				// "default", and <sa>.<ns> - not <sa>.<ns>.svc - is what the
				// verified-identity allowlist grants (ADR-0001).
				fmt.Sprintf("default.%s", workloadNamespace),
			), "SANs must be interpolated from the pod identity")
			Expect(leaf.URIs).To(HaveLen(1), "the uris annotation must yield the service-account SPIFFE ID")
			Expect(leaf.URIs[0].String()).To(Equal(
				fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/default", workloadNamespace)),
				"SPIFFE ID must match the uris annotation in examples/workload-pod.yaml")
			Expect(leaf.IPAddresses).To(BeEmpty(),
				"the example's ip-san is commented out: an IP SAN has no verified derivation and "+
					"would need --allow-unverified-identities")

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
			pod := applyCertTestPod(podName, map[string]string{
				signerName + "-cn":  "custom-cn.example.org",
				signerName + "-san": "api.example.org,web.example.org",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]

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
			pod := applyCertTestPod(podName, map[string]string{
				signerName + "-cn":     "ip-demo.example.org",
				signerName + "-ip-san": "10.96.0.42,2001:db8::42",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]

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
			pod := applyCertTestPod(podName, map[string]string{
				signerName + "-cn":  "eku-demo.example.org",
				signerName + "-eku": "client",
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]

			By("verifying the certificate is restricted to client auth")
			Expect(leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageClientAuth),
				"eku=client must yield a client-auth-only certificate")
		})
	})

	// The escape hatch is open on this install, so this is where the specs that
	// bound it belong: what --allow-unverified-identities admits, and what it
	// still refuses. See escape_hatch_test.go.
	defineEscapeHatchInvariantTests()

	// Install profiles that re-install the release in place. They run after the
	// unverified-identities specs above and must stay inside this Describe: its
	// AfterAll uninstalls the release, so a sibling top-level container would run
	// against a torn-down deployment. See install_profiles_test.go for why a
	// mid-suite upgrade is safe here.
	//
	// They also run *before* the ClusterTrustBundle context, which deliberately
	// rotates the CA secret out from under the controller. `make helm-install`
	// re-applies the CA secret from bin/dev-ca, so a profile switch after that
	// rotation would rotate the CA back mid-suite and race the controller's
	// volume reload against the profile's own issuance specs.
	defineHonorCSRSANsProfileTests()
	defineVerifiedInterpolationProfileTests()
	// Declared between the two profiles it sits between in configuration: it is
	// verified-interpolation with a different signer.cluster_fqdn, and the
	// chart-defaults install that follows resets the suffix. See
	// identity_boundary_test.go for why it is worth its own rollout.
	defineCustomClusterFQDNProfileTests()
	defineChartDefaultsProfileTests()
	// Last of the profiles, and the only one that overrides a signer default:
	// it closes the interpolation gate the other four rely on being open. See
	// install_profiles_test.go.
	defineInterpolationDisabledProfileTests()

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
			// caLifecycleValidity, not 24 hours, which is what this asked for
			// until the CA-lifecycle specs were written. A CA valid for exactly
			// the default certificate lifetime cannot sign a default certificate
			// at all: the signer backdates notBefore by a minute, so the
			// certificate would outlive the CA by that minute and every request
			// returns ErrCASignerUnusable. This spec never noticed - it asserts
			// on the published bundle and issues nothing afterwards - but it
			// leaves that CA current for whatever runs next. See the constant.
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

	// The CA lifecycle specs go last of the CA-mutating containers: they
	// deliberately rotate, break and restore the CA, so nothing that assumes a
	// stable signer may follow them. See ca_lifecycle_test.go.
	defineCALifecycleTests()

	// The admission specs are dry-run creates judged by a
	// ValidatingAdmissionPolicy, so they neither reach the signer nor care what
	// state the CA was left in.
	defineAdmissionPolicyTests()

	// Interoperability with a real TLS workload goes last of everything. It
	// installs its own profile and rotates the CA, and the previous-CA retention
	// spec above asserts an exact rotation history that any rotation before it
	// would invalidate. Declared here, nothing follows that it can disturb. See
	// goweb_interop_test.go.
	defineGowebInteropTests()
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
