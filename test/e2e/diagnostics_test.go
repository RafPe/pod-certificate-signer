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
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// Failure diagnostics.
//
// A CI e2e failure is only debuggable from what the run printed, so the dump
// below is deliberately broad: every controller replica's log including the
// previous container, the workload objects, the requests, the trust bundle, the
// admission resources, the release as Helm rendered it, and the cluster's own
// version. It runs after a failed spec and must never turn a spec failure into
// a different failure - nothing here asserts, and every command that cannot run
// records why and moves on.
//
// Secret material is never collected. There is no `kubectl get secret` and no
// `describe secret` in this file, which matters because the suite runs with a
// live signing CA in the cluster: the dev CA's private key sits in the
// podcertificate-signer-ca-dev secret, and the rotation spec creates more. The
// Helm collectors are safe by construction - the chart takes its CA by
// secretRef only (charts/pod-certificate-signer/values.yaml: signer.ca.source is
// secretRef or file), so neither the release values nor the rendered manifest
// carry key material. Every collected output is still passed through
// redactSensitive as a backstop, so a future chart change that starts
// templating key material degrades to a redaction marker rather than a leak.

// privateKeyBlockPattern matches a PEM private key block of any flavour
// (PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY, ENCRYPTED PRIVATE KEY).
var privateKeyBlockPattern = regexp.MustCompile(
	`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

// secretDataPattern matches the payload of the Secret data keys that hold key
// material, in case an object carrying one is ever collected indirectly. The
// key names are spelled out rather than matched loosely so the dump does not
// redact the chart's own `key: tls.key` volume-item wiring, which is
// configuration and often the thing under investigation.
var secretDataPattern = regexp.MustCompile(`(?m)^(\s*)(tls\.key|ca\.key|password):\s*\S+$`)

// redactSensitive removes private key material from diagnostic output.
func redactSensitive(output string) string {
	output = privateKeyBlockPattern.ReplaceAllString(output, "[REDACTED PRIVATE KEY]")
	output = secretDataPattern.ReplaceAllString(output, "$1$2: [REDACTED]")
	return output
}

// dump runs a command purely for diagnostics and writes its redacted output to
// the Ginkgo report. Failures are reported, never raised.
func dump(title string, name string, args ...string) {
	cmd := exec.Command(name, args...)
	output, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- %s: unavailable (%v)\n", title, err)
		return
	}
	_, _ = fmt.Fprintf(GinkgoWriter, "\n--- %s ---\n%s\n", title, redactSensitive(output))
}

// dumpKubectl is the kubectl-shaped shorthand for dump.
func dumpKubectl(title string, args ...string) {
	dump(title, "kubectl", args...)
}

// dumpHelm runs the repo-pinned helm tool. helm lives in the tools module, so it
// is invoked the same way the Makefile invokes it.
func dumpHelm(title string, args ...string) {
	dump(title, "go", append([]string{"tool", "-modfile", "internal/tools/go.mod", "helm"}, args...)...)
}

// controllerPodNames lists every pod of the release, so a multi-replica or
// mid-rollout failure dumps all of them rather than only the one the specs
// happen to target.
func controllerPodNames() []string {
	cmd := exec.Command("kubectl", "get", "pods",
		"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", releaseName),
		"-n", namespace, "-o", "jsonpath={.items[*].metadata.name}")
	output, err := utils.Run(cmd)
	if err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- controller pod list: unavailable (%v)\n", err)
		return nil
	}
	return strings.Fields(output)
}

// metricsDumpBinding and metricsDumpPod name the throwaway RBAC binding and
// scraper the metrics dump creates.
const (
	metricsDumpBinding = releaseName + "-e2e-metrics-dump"
	metricsDumpPod     = "e2e-metrics-dump"
)

// dumpMetrics scrapes the controller's metrics endpoint.
//
// The endpoint is secured (SecureServing plus a SubjectAccessReview on the
// /metrics nonResourceURL) and only listens on a ClusterIP, which rules out the
// two cheap options: an unauthenticated scrape is refused, and the apiserver's
// service proxy reaches the port but presents its own identity, which the
// authorizer rejects with a 401. So the dump does what a real scraper does -
// runs in the cluster, presents a projected ServiceAccount token, and is bound
// to the chart's metrics-reader ClusterRole for the duration.
//
// Everything here is best-effort and time-bounded: curl by --max-time and its
// retry count, the wait for the scraper by its own deadline, so a broken cluster
// makes the dump print less rather than hang.
func dumpMetrics() {
	binding := exec.Command("kubectl", "create", "clusterrolebinding", metricsDumpBinding,
		"--clusterrole", metricsReaderClusterRole,
		"--serviceaccount", fmt.Sprintf("%s:%s", namespace, serviceAccountName))
	if _, err := utils.Run(binding); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- metrics: unavailable, could not authorize the scraper (%v)\n", err)
		return
	}
	defer func() {
		cleanup := exec.Command("kubectl", "delete", "clusterrolebinding", metricsDumpBinding, "--ignore-not-found=true")
		_, _ = utils.Run(cleanup)
	}()

	// -k skips verification of the controller's self-signed serving
	// certificate: this is a diagnostic scrape, not an assertion about the
	// serving chain. -f plus the retry loop covers the SubjectAccessReview
	// deny that the authorizer caches for 30s when the binding above has not
	// propagated yet, and --show-error keeps a failed scrape visible instead of
	// dumping an empty section.
	scrape := fmt.Sprintf(
		"for i in 1 2 3 4 5; do "+
			"curl -fsSk --max-time 20 "+
			"-H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" "+
			"https://%s.%s.svc.cluster.local:9090/metrics && exit 0; "+
			"echo 'scrape failed, retrying'; sleep 5; done; exit 0",
		metricsServiceName, namespace)
	overrides := fmt.Sprintf(`{
		"spec": {
			"containers": [{
				"name": "curl",
				"image": "curlimages/curl:latest",
				"command": ["/bin/sh", "-c"],
				"args": [%q],
				"securityContext": {
					"readOnlyRootFilesystem": true,
					"allowPrivilegeEscalation": false,
					"capabilities": {"drop": ["ALL"]},
					"runAsNonRoot": true,
					"runAsUser": 1000,
					"seccompProfile": {"type": "RuntimeDefault"}
				}
			}],
			"serviceAccountName": %q
		}
	}`, scrape, serviceAccountName)

	// The scraper is created and then read back from its logs rather than run
	// with --attach: curl finishes in milliseconds and an attach that has not
	// been established by then silently yields nothing.
	run := exec.Command("kubectl", "run", metricsDumpPod,
		"--restart=Never",
		"--namespace", namespace,
		"--image=curlimages/curl:latest",
		"--overrides", overrides)
	if _, err := utils.Run(run); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- metrics: unavailable, scraper pod not created (%v)\n", err)
		return
	}
	defer func() {
		cleanup := exec.Command("kubectl", "delete", "pod", metricsDumpPod,
			"-n", namespace, "--ignore-not-found=true", "--wait=false")
		_, _ = utils.Run(cleanup)
	}()

	if !waitForScraperToFinish() {
		_, _ = fmt.Fprintf(GinkgoWriter, "\n--- metrics: unavailable, scraper pod did not finish\n")
		return
	}
	dumpKubectl("metrics", "logs", metricsDumpPod, "-n", namespace)
}

// waitForScraperToFinish polls the metrics scraper until it terminates,
// reporting whether it got there. It polls rather than asserting: this runs
// while a spec is already failing and must not raise a second failure.
func waitForScraperToFinish() bool {
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		cmd := exec.Command("kubectl", "get", "pod", metricsDumpPod,
			"-n", namespace, "-o", "jsonpath={.status.phase}")
		phase, err := utils.Run(cmd)
		if err == nil && (phase == "Succeeded" || phase == "Failed") {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

// dumpDiagnostics collects everything needed to debug a failed spec after the
// fact. It is called from the suite's AfterEach on failure only.
func dumpDiagnostics() {
	_, _ = fmt.Fprintf(GinkgoWriter, "\n===== e2e failure diagnostics: %s =====\n",
		CurrentSpecReport().FullText())

	By("collecting controller replica logs")
	pods := controllerPodNames()
	if len(pods) == 0 && controllerPodName != "" {
		// The label query failed; fall back to the pod the specs were using.
		pods = []string{controllerPodName}
	}
	for _, pod := range pods {
		dumpKubectl("logs "+pod, "logs", pod, "-n", namespace, "--all-containers=true")
		// --previous fails outright when the container has never restarted,
		// which is the common case; dump reports that and carries on.
		dumpKubectl("logs "+pod+" (previous)", "logs", pod, "-n", namespace, "--all-containers=true", "--previous")
	}

	By("collecting the controller workload objects")
	dumpKubectl("controller workloads", "get", "deployment,replicaset,pod", "-n", namespace, "-o", "wide")
	dumpKubectl("controller deployment", "describe", "deployment", releaseName, "-n", namespace)
	dumpKubectl("controller replicasets", "describe", "replicaset",
		"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", releaseName), "-n", namespace)
	dumpKubectl("controller pods", "describe", "pod",
		"-l", fmt.Sprintf("app.kubernetes.io/instance=%s", releaseName), "-n", namespace)
	dumpKubectl("leader election leases", "get", "leases", "-n", namespace, "-o", "yaml")
	dumpKubectl("controller namespace events", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")

	By("collecting the curl-metrics probe output")
	dumpKubectl("curl-metrics logs", "logs", "curl-metrics", "-n", namespace)

	By("collecting the workload pods and their certificate requests")
	dumpKubectl("workload pods", "get", "pods", "-n", workloadNamespace, "-o", "yaml")
	// The credential probe reports what it saw inside the pod; for a spec that
	// failed before parsing that report, the raw log is the only place it
	// exists. Selecting on the suite's own label keeps this to pods these specs
	// created. The probe publishes fingerprints and block types, never key
	// material, and the output passes through redactSensitive regardless.
	dumpKubectl("workload pod logs", "logs", "-l", e2eWorkloadLabel+"=true",
		"-n", workloadNamespace, "--all-containers=true", "--prefix=true", "--tail=-1")
	dumpKubectl("pod certificate requests", "get", "podcertificaterequests", "-n", workloadNamespace, "-o", "yaml")
	dumpKubectl("workload namespace events", "get", "events", "-n", workloadNamespace, "--sort-by=.lastTimestamp")

	By("collecting the published trust bundles")
	dumpKubectl("cluster trust bundles", "get", "clustertrustbundles", "-o", "yaml")

	By("collecting the admission resources")
	dumpKubectl("validating admission policies", "get",
		"validatingadmissionpolicies,validatingadmissionpolicybindings", "-o", "yaml")

	By("collecting the Helm release")
	dumpHelm("helm values", "get", "values", releaseName, "-n", namespace, "--all")
	dumpHelm("helm manifest", "get", "manifest", releaseName, "-n", namespace)

	By("collecting the cluster version")
	dumpKubectl("nodes", "get", "nodes", "-o", "wide")
	dumpKubectl("versions", "version")

	By("collecting the controller metrics")
	dumpMetrics()

	_, _ = fmt.Fprintf(GinkgoWriter, "\n===== end e2e failure diagnostics =====\n")
}
