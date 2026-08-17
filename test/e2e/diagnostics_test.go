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
	// Reached through the apiserver's service proxy so the dump needs no token
	// and no scraper pod; the secured endpoint may still refuse, in which case
	// dump records the refusal.
	dumpKubectl("metrics", "get", "--raw",
		fmt.Sprintf("/api/v1/namespaces/%s/services/https:%s:9090/proxy/metrics", namespace, metricsServiceName))

	_, _ = fmt.Fprintf(GinkgoWriter, "\n===== end e2e failure diagnostics =====\n")
}
