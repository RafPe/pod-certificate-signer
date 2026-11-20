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
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// The issuance audit record.
//
// The signer writes one JSON line on stdout for each signing attempt and each
// terminal outcome (docs/auditing.md). The point of the record is the join it
// makes: from the certificate a workload was served back to the request and the
// pod that asked for it. These specs take the certificate off an issued
// request, compute its fingerprint the way an operator would, and look for the
// record that names the pod.
//
// The records are read the way docs/auditing.md tells an operator to read them
// without a log backend: `kubectl logs`, which merges stdout and stderr, and
// keeps the lines that decode as JSON with kind CertificateAuditRecord. The
// records are decoded into maps, not into the signer's own audit.Record type,
// so a renamed JSON field fails here instead of being decoded by the same tags
// that wrote it.

const (
	// auditLabel marks the audit record specs, so they can be selected with
	// E2E_LABEL_FILTER. It does not move them out of either tier.
	auditLabel = "audit"

	// auditRecordKind is the kind field of every audit record.
	auditRecordKind = "CertificateAuditRecord"

	// auditFingerprintPrefix is the credential-id form of a SHA-256 fingerprint
	// that the record uses: the prefix, then the lowercase hex digest of the
	// certificate's DER bytes.
	auditFingerprintPrefix = "X509SHA256="

	// auditEventSigned and auditEventPublished are the two records of a
	// successful issuance, in the order the signer writes them.
	auditEventSigned    = "signed"
	auditEventPublished = "published"

	// auditEventDenied is the record of a Denied outcome.
	auditEventDenied = "denied"

	// auditSummaryLimit caps how many records a failure message lists.
	auditSummaryLimit = 20

	// auditSettleWindow is how long a spec watches for a record it expects not
	// to appear. Each use follows a positive proof that the signer already
	// acted on the request, so the window guards against a late write only.
	auditSettleWindow = 5 * time.Second
)

// auditDisabledInstallArgs is the chart defaults with the audit record turned
// off. It is the only profile that names audit.enabled.
const auditDisabledInstallArgs = chartDefaultsInstallArgs + " --set audit.enabled=false"

// defineAuditRecordTests is called from inside the chart-defaults install
// profile (install_profiles_test.go). That profile ships the audit record on,
// runs one replica and enforces the identity allowlist, which the denial spec
// needs: under the first profile the escape hatch is open and the same request
// would issue.
func defineAuditRecordTests() {
	Context("Issuance audit record", Label(auditLabel), func() {
		It("joins a served certificate to its pod", func() {
			By("creating a workload pod that asks for nothing")
			pod := applyCertTestPod("pcs-audit-issued", nil)

			By("waiting for the PodCertificateRequest to be issued")
			certs := expectIssued(pod)
			leaf := certs[0]
			wantFingerprint := auditFingerprintPrefix + fingerprint(leaf)
			request := getPodCertificateRequest(pod)
			live := getLivePod(pod)

			By("finding the signed and published records for the served certificate")
			signed, published := expectIssuanceAuditRecords(auditRecords, wantFingerprint)
			AddReportEntry("signed audit record", prettyAuditRecord(signed))

			By("verifying the signed record names the pod that requested the certificate")
			Expect(auditString(signed, "workload", "pod", "uid")).To(Equal(string(live.UID)),
				"workload.pod.uid must be the UID of the live pod")
			Expect(auditString(signed, "workload", "pod", "uid")).To(Equal(string(pod.uid)),
				"workload.pod.uid must be the UID of the pod this spec created")
			Expect(auditString(signed, "workload", "pod", "name")).To(Equal(pod.name))
			Expect(auditString(signed, "workload", "serviceAccount", "name")).To(Equal(live.Spec.ServiceAccountName),
				"workload.serviceAccount.name must be the pod's ServiceAccount")

			By("verifying the signed record names the request and the certificate")
			Expect(auditString(signed, "request", "uid")).To(Equal(string(request.UID)),
				"request.uid must be the UID of the pod's PodCertificateRequest")
			Expect(auditString(signed, "request", "namespace")).To(Equal(request.Namespace))
			Expect(auditString(signed, "request", "name")).To(Equal(request.Name))
			Expect(auditString(signed, "certificate", "serialDecimal")).To(Equal(leaf.SerialNumber.String()),
				"certificate.serialDecimal must be the serial of the served certificate")

			By("verifying the published record names the same request and certificate")
			Expect(auditString(published, "request", "uid")).To(Equal(string(request.UID)))
			Expect(auditString(published, "certificate", "serialDecimal")).To(Equal(leaf.SerialNumber.String()))

			By("verifying the Issued condition message carries the serial and the fingerprint of the record")
			wantSerialHex := leaf.SerialNumber.Text(16)
			Expect(auditString(signed, "certificate", "serialHex")).To(Equal(wantSerialHex),
				"certificate.serialHex must be the serial of the served certificate in lowercase hex")
			Expect(auditString(signed, "certificate", "fingerprint")).To(Equal(wantFingerprint),
				"certificate.fingerprint must be the fingerprint of the served certificate")
			issued := terminalCondition(Default, request)
			Expect(issued.Message).To(Equal(
				"certificate issued: serial="+wantSerialHex+" fingerprint="+wantFingerprint),
				"the Issued condition message must carry the serial and the fingerprint of the signed record")
		})

		It("records a denial without a certificate", func() {
			By("creating a workload pod requesting one foreign name next to its own")
			// The mixed-list fixture from identity_boundary_test.go: the
			// allowlist denies the whole request.
			pod := applyCertTestPod("pcs-audit-denied", map[string]string{
				signerName + "-san": "${pod.name},evil.example.com",
			})

			By("waiting for the PodCertificateRequest to be denied")
			// expectDenied also nudges one more reconcile of the terminal request
			// and waits until the controller logs it, so a second record from
			// that reconcile would already be on its way when the checks below
			// run.
			denial := expectDenied(pod, certificatesv1.PodCertificateRequestConditionInvalidUserConfig)
			request := getPodCertificateRequest(pod)
			requestUID := string(request.UID)

			By("finding the one denied record for the request")
			var denied map[string]any
			Eventually(func(g Gomega) {
				all := auditRecords(g)
				matched := filterAuditRecords(all, requestUID, "request", "uid")
				g.Expect(auditEvents(matched)).To(Equal([]string{auditEventDenied}),
					"want exactly one %s record for request %s, found:\n%s\nall audit records:\n%s",
					auditEventDenied, requestUID, summarizeAuditRecords(matched), summarizeAuditRecords(all))
				denied = matched[0]
			}).Should(Succeed())
			AddReportEntry("denied audit record", prettyAuditRecord(denied))

			By("verifying no further record arrives for the request")
			Consistently(func(g Gomega) {
				matched := filterAuditRecords(auditRecords(g), requestUID, "request", "uid")
				g.Expect(auditEvents(matched)).To(Equal([]string{auditEventDenied}),
					"the request must keep exactly one record, found:\n%s", summarizeAuditRecords(matched))
			}, auditSettleWindow, time.Second).Should(Succeed())

			By("verifying the denied record carries the reason and no certificate")
			Expect(auditString(denied, "reason")).To(Equal(denial.Reason),
				"the denied record must carry the condition reason")
			Expect(auditString(denied, "message")).NotTo(BeEmpty(),
				"the denied record must carry the condition message")
			Expect(denied).NotTo(HaveKey("certificate"), "a denied record must have no certificate group")
			Expect(denied).NotTo(HaveKey("issuer"), "a denied record must have no issuer group")
			Expect(auditString(denied, "workload", "pod", "uid")).To(Equal(string(pod.uid)),
				"workload.pod.uid must be the UID of the pod this spec created")
		})
	})
}

// defineAuditDisabledProfileTests covers audit.enabled=false.
//
// It costs one `helm upgrade`. It is declared after the chart-defaults profile
// and before the interpolation-disabled profile, whose install sets
// audit.enabled back to the chart default, so no other spec runs with the
// record off.
func defineAuditDisabledProfileTests() {
	Context("Install profile: audit-disabled", Label(auditLabel), func() {
		BeforeAll(func() {
			installProfile(auditDisabledInstallArgs)
		})

		It("writes nothing when audit is disabled", func() {
			By("verifying the controller runs with the audit record off")
			// The chart passes the flags in the container command, not in args.
			cmd := exec.Command("kubectl", "get", "pod", controllerPodName, "-n", namespace,
				"-o", "jsonpath={.spec.containers[0].command}")
			output, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to read the controller command: %s", output)
			Expect(output).To(ContainSubstring("--audit-enabled=false"),
				"controller pod %s must run with --audit-enabled=false, its command is: %s", controllerPodName, output)

			By("creating a workload pod that asks for nothing")
			pod := applyCertTestPod("pcs-audit-off", nil)

			By("waiting for the PodCertificateRequest to be issued")
			expectIssued(pod)
			requestName := getPodCertificateRequest(pod).Name

			By("waiting for the controller log to show the issuance")
			// Proves the log read below is the log of the pod that signed, and
			// that it covers the signing. Without it, zero records could mean
			// the wrong pod or an empty log.
			Eventually(func() int {
				return controllerLogLineCount("issued certificate", requestName)
			}).Should(BeNumerically(">", 0),
				"controller pod %s must log the issuance of request %s", controllerPodName, requestName)

			By("verifying the controller wrote no audit record")
			Consistently(func(g Gomega) {
				records := podAuditRecords(g, controllerPodName)
				g.Expect(records).To(BeEmpty(),
					"controller pod %s must write no audit record with audit.enabled=false, found:\n%s",
					controllerPodName, summarizeAuditRecords(records))
			}, auditSettleWindow, time.Second).Should(Succeed())
		})
	})
}

// expectIssuanceAuditRecords waits until read returns exactly one signed and
// one published record with the given fingerprint, signed first, and returns
// them.
//
// read is auditRecords for a spec that only cares that some replica wrote the
// records, or a closure over podAuditRecords for a spec that cares which one.
func expectIssuanceAuditRecords(read func(Gomega) []map[string]any, wantFingerprint string) (signed, published map[string]any) {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		all := read(g)
		matched := filterAuditRecords(all, wantFingerprint, "certificate", "fingerprint")
		g.Expect(auditEvents(matched)).To(Equal([]string{auditEventSigned, auditEventPublished}),
			"want one %s then one %s record for %s, found:\n%s\nall audit records:\n%s",
			auditEventSigned, auditEventPublished, wantFingerprint,
			summarizeAuditRecords(matched), summarizeAuditRecords(all))
		signed, published = matched[0], matched[1]
	}).Should(Succeed())
	return signed, published
}

// auditRecords returns the audit records of every controller pod of the
// release, terminating ones included, in log order within each pod.
//
// Only the leader signs, and which replica that is moves across a handover, so
// a spec that does not care which replica wrote a record reads them all.
// Records are matched by fingerprint or request UID, which no two requests
// share, so reading more pods than needed cannot produce a false match.
func auditRecords(g Gomega) []map[string]any {
	pods := haAllControllerPods()
	g.Expect(pods).NotTo(BeEmpty(), "no controller pod of release %s to read audit records from", releaseName)

	records := make([]map[string]any, 0, len(pods))
	for _, pod := range pods {
		records = append(records, podAuditRecords(g, pod)...)
	}
	return records
}

// podAuditRecords returns the audit records in the named controller pod's
// log, in the order the pod wrote them.
//
// It reads the previous container first, when there is one, so a record that
// was written before a container restart is still found. That read is best
// effort: kubectl fails it when the container never restarted. The current
// container's log must be readable, so an unreadable log fails the caller's
// poll rather than reading as zero records.
func podAuditRecords(g Gomega, pod string) []map[string]any {
	var records []map[string]any

	cmd := exec.Command("kubectl", "logs", pod, "-n", namespace, "--previous")
	if output, err := utils.Run(cmd); err == nil {
		records = append(records, parseAuditRecords(output)...)
	}

	cmd = exec.Command("kubectl", "logs", pod, "-n", namespace)
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to read the log of controller pod %s", pod)
	return append(records, parseAuditRecords(output)...)
}

// parseAuditRecords keeps the lines of a merged stdout and stderr log that are
// audit records.
//
// Everything else is skipped without error: a console-encoded operational
// line, a JSON-encoded operational line, a kubectl warning, and a line that
// starts like JSON but does not decode.
func parseAuditRecords(log string) []map[string]any {
	var records []map[string]any
	for _, line := range strings.Split(log, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		if record["kind"] != auditRecordKind {
			continue
		}
		records = append(records, record)
	}
	return records
}

// auditField returns the value at the given path of nested JSON objects, or
// nil when a step of the path is absent or is not an object.
func auditField(record map[string]any, path ...string) any {
	var current any = record
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[key]
	}
	return current
}

// auditString returns the string at the given path, or "" when it is absent or
// not a string.
func auditString(record map[string]any, path ...string) string {
	value, _ := auditField(record, path...).(string)
	return value
}

// filterAuditRecords returns the records whose string at the given path is
// want, in their original order.
func filterAuditRecords(records []map[string]any, want string, path ...string) []map[string]any {
	var matched []map[string]any
	for _, record := range records {
		if auditString(record, path...) == want {
			matched = append(matched, record)
		}
	}
	return matched
}

// auditEvents returns the event of each record, in order. A spec compares it
// with the sequence it expects, which checks the count of each event and their
// order in one assertion.
func auditEvents(records []map[string]any) []string {
	events := make([]string, 0, len(records))
	for _, record := range records {
		events = append(events, auditString(record, "event"))
	}
	return events
}

// summarizeAuditRecords renders records for a failure message, one line each,
// with the fields that tell records apart. It lists the last
// auditSummaryLimit records, because the newest are the ones a spec is about.
func summarizeAuditRecords(records []map[string]any) string {
	if len(records) == 0 {
		return "  (none)"
	}
	shown := records
	var lines []string
	if len(records) > auditSummaryLimit {
		shown = records[len(records)-auditSummaryLimit:]
		lines = append(lines, fmt.Sprintf("  ... %d earlier records not shown", len(records)-auditSummaryLimit))
	}
	for _, record := range shown {
		lines = append(lines, fmt.Sprintf("  event=%s reason=%s request=%s/%s request.uid=%s pod.uid=%s fingerprint=%s",
			auditString(record, "event"),
			auditString(record, "reason"),
			auditString(record, "request", "namespace"),
			auditString(record, "request", "name"),
			auditString(record, "request", "uid"),
			auditString(record, "workload", "pod", "uid"),
			auditString(record, "certificate", "fingerprint")))
	}
	return strings.Join(lines, "\n")
}

// prettyAuditRecord renders one record as indented JSON for the run report.
func prettyAuditRecord(record map[string]any) string {
	out, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Sprintf("unrenderable record: %v", err)
	}
	return string(out)
}

// getLivePod reads the pod as it is now.
func getLivePod(ref podRef) *corev1.Pod {
	GinkgoHelper()

	cmd := exec.Command("kubectl", "get", "pod", ref.name, "-n", ref.namespace, "-o", "json")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to read pod %s: %s", ref, output)

	var pod corev1.Pod
	Expect(json.Unmarshal([]byte(trimToJSON(output)), &pod)).To(Succeed(), "Failed to decode pod %s", ref)
	return &pod
}
