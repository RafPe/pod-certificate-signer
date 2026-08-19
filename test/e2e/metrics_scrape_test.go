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
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// Repeatable scrapes of the controller's metrics endpoint.
//
// The suite already scrapes it once, from a one-shot pod whose logs it reads
// (e2e_test.go). That proves the endpoint is authenticated and serving; it is
// not something a spec can sample twice to assert a delta. These helpers are
// the second thing: a scrape that can be taken before an action and again
// after it.
//
// Three properties are deliberate.
//
// The scrape targets the controller **pod**, not the metrics Service. Counters
// are per replica, so a Service that round-robins would silently mix two of
// them and a delta would be nonsense on any multi-replica install.
//
// Counters reset when the process does, so a delta is only meaningful within
// one controller lifetime. No spec using these may put a restartController()
// between its baseline and its assertion.
//
// And the scrape runs `kubectl exec` into one long-lived pod rather than
// creating a pod per sample. That is not only about cost. A `kubectl run --rm
// --attach` pod that curls and exits races the attach: the container can finish
// before kubectl is streaming, in which case the command succeeds and returns
// an empty body - a silent wrong answer, not an error. An exec into a pod that
// is already running has no such window.

// metricsScrapeBinding authorizes the scraper. It is a separate
// ClusterRoleBinding from the one the metrics spec creates and deletes within
// its own It, so the two cannot collide on name or lifetime.
const metricsScrapeBinding = releaseName + "-e2e-metrics-scrape"

// metricsScraperPod is the long-lived pod every scrape execs into. It runs as
// the controller ServiceAccount so its projected token is the one the endpoint
// authorizes.
const metricsScraperPod = "pcs-metrics-scraper"

// metricsScraperLifetime is how long the scraper idles before exiting. It has
// to outlast the whole container that installs it, so it is set generously; the
// pod is deleted on cleanup either way.
const metricsScraperLifetime = "7200"

// metricsScrapePollInterval is how often an Eventually over a scrape may run.
// A scrape is an exec round trip, which is cheap but not free, and the CA
// changes these specs wait on take tens of seconds to propagate.
const metricsScrapePollInterval = 5 * time.Second

// authorizeMetricsScrapes binds the chart's metrics-reader ClusterRole to the
// controller ServiceAccount and starts the scraper pod, removing both when the
// calling container finishes. The secured endpoint authorizes GET on the
// /metrics nonResourceURL via SubjectAccessReview, so without the binding every
// scrape is a 403.
func authorizeMetricsScrapes() {
	GinkgoHelper()

	cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsScrapeBinding,
		"--clusterrole", metricsReaderClusterRole,
		"--serviceaccount", fmt.Sprintf("%s:%s", namespace, serviceAccountName))
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to authorize the metrics scrapes")
	DeferCleanup(func() {
		cmd := exec.Command("kubectl", "delete", "clusterrolebinding", metricsScrapeBinding, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	})

	cmd = exec.Command("kubectl", "run", metricsScraperPod,
		"--restart=Never",
		"--namespace", namespace,
		"--image=curlimages/curl:latest",
		"--overrides",
		fmt.Sprintf(`{
			"spec": {
				"containers": [{
					"name": "curl",
					"image": "curlimages/curl:latest",
					"command": ["/bin/sh", "-c"],
					"args": ["sleep %s"],
					"securityContext": {
						"readOnlyRootFilesystem": true,
						"allowPrivilegeEscalation": false,
						"capabilities": { "drop": ["ALL"] },
						"runAsNonRoot": true,
						"runAsUser": 1000,
						"seccompProfile": { "type": "RuntimeDefault" }
					}
				}],
				"serviceAccountName": %q
			}
		}`, metricsScraperLifetime, serviceAccountName))
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to create the metrics scraper pod")
	DeferCleanup(func() {
		cmd := exec.Command("kubectl", "delete", "pod", metricsScraperPod, "-n", namespace,
			"--ignore-not-found=true", "--wait=false")
		_, _ = utils.Run(cmd)
	})

	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "pod", metricsScraperPod, "-n", namespace,
			"-o", "jsonpath={.status.phase}")
		phase, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(phase).To(Equal("Running"), "the metrics scraper pod is not running yet")
	}).Should(Succeed())
}

// scrapeControllerMetrics returns the exposition body from the controller pod's
// metrics endpoint, read through the scraper pod's projected ServiceAccount
// token.
func scrapeControllerMetrics(g Gomega) string {
	cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
		"-o", "jsonpath={.status.podIP}")
	podIP, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to read the controller pod IP")
	g.Expect(podIP).NotTo(BeEmpty(), "the controller pod has no IP yet")

	// -k skips verification of the controller's in-memory self-signed serving
	// certificate: the guarantee under test here is the metric value, not the
	// serving-cert trust chain, which the metrics spec already covers.
	script := fmt.Sprintf(
		"curl -fsk -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://%s:9090/metrics",
		podIP)
	cmd = exec.Command("kubectl", "exec", metricsScraperPod, "-n", namespace, "--", "/bin/sh", "-c", script)
	body, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to scrape the controller metrics endpoint")
	g.Expect(body).To(ContainSubstring("podcertificatesigner_"),
		"the scrape returned no signer metrics at all: %s", body)

	return body
}

// metricValue reads one sample out of a Prometheus text exposition body. series
// is the full series identity as exposed, e.g.
// `podcertificatesigner_ca_reload_attempts_total{result="changed"}`.
//
// Every series this suite reads is pre-initialised by the signer, so an absent
// one is a failure rather than a zero: reporting it as zero would let a
// misspelled name pass as "nothing has happened yet".
func metricValue(g Gomega, body, series string) float64 {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sep := strings.LastIndex(line, " ")
		if sep < 0 || line[:sep] != series {
			continue
		}
		value, err := strconv.ParseFloat(line[sep+1:], 64)
		g.Expect(err).NotTo(HaveOccurred(), "unparseable sample for %s: %q", series, line)

		return value
	}

	g.Expect(false).To(BeTrue(), "the scrape carried no sample for %s; the signer pre-initialises every series it can expose, "+
		"so an absent one means the name is wrong or the metric was removed", series)

	return 0
}

// scrapeMetricValue takes one scrape and reads a single series out of it.
func scrapeMetricValue(g Gomega, series string) float64 {
	return metricValue(g, scrapeControllerMetrics(g), series)
}

// Series the CA-lifecycle specs sample. Spelled out in full rather than
// assembled, so a rename in internal/metrics shows up here as a failing scrape
// rather than as a silently-zero assertion.
const (
	// caReloadFailuresGauge is the consecutive-failure streak backing readiness.
	caReloadFailuresGauge = `podcertificatesigner_ca_reload_consecutive_failures`

	// caReloadLastSuccessGauge is when the CA was last read successfully, as a
	// Unix timestamp. It advances on every successful reload, including one
	// that changed nothing, which is what makes it the observable for a
	// recovery that restores the CA the signer already had.
	caReloadLastSuccessGauge = `podcertificatesigner_ca_reload_last_success_timestamp_seconds`

	// caUnusableRequeueSeries counts reconciles requeued because the CA could
	// not cover the request.
	caUnusableRequeueSeries = `podcertificatesigner_podcertificaterequest_requeues_total{reason="CASignerUnusable"}`
)
