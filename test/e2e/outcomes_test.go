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
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// terminalOutcomeTimeout bounds how long a spec waits for the signer to record
// a terminal condition on a request.
const terminalOutcomeTimeout = 3 * time.Minute

// reconcileNudgeAnnotation is written onto a terminal PodCertificateRequest to
// force the controller to reconcile it once more. See
// expectTerminalConditionStable.
const reconcileNudgeAnnotation = "e2e.pod-certificate-signer/reconcile-nudge"

// podRef pins the identity of a workload pod for the lifetime of a spec.
//
// The UID is the load-bearing field. A PodCertificateRequest names the pod it
// belongs to *and* that pod's UID, and only the pair identifies it: a pod name
// is unique in a namespace at a point in time, not over the life of a cluster.
// `make test-e2e` reuses a Kind cluster that is already present, so requests
// from an earlier run outlive the pods that caused them and can share a name
// with a pod the current run just created.
type podRef struct {
	namespace string
	name      string
	uid       types.UID
}

func (p podRef) String() string {
	return fmt.Sprintf("%s/%s (uid %s)", p.namespace, p.name, p.uid)
}

// deniedRequest is the terminal outcome recorded on a PodCertificateRequest the
// signer refuses.
type deniedRequest struct {
	Reason  string
	Message string
}

// terminalConditionTypes are the three condition types the PodCertificateRequest
// API gives special handling: at most one may be present, and it must have
// status True.
var terminalConditionTypes = []string{
	capiv1beta1.PodCertificateRequestConditionTypeIssued,
	capiv1beta1.PodCertificateRequestConditionTypeDenied,
	capiv1beta1.PodCertificateRequestConditionTypeFailed,
}

// findPodCertificateRequest returns the single PodCertificateRequest belonging
// to the given pod.
//
// Selection is on namespace + pod name + pod UID + signer name. Matching on the
// pod name alone - as the suite did before - picks up a request left over from
// a previous run against a reused cluster, or a request another signer is
// serving, and reports its outcome as this pod's.
//
// More than one match is not a condition that resolves by waiting, so it aborts
// the retry loop immediately rather than burning the whole timeout.
func findPodCertificateRequest(g Gomega, ref podRef) *capiv1beta1.PodCertificateRequest {
	cmd := exec.Command("kubectl", "get", "podcertificaterequests", "-n", ref.namespace, "-o", "json")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(), "Failed to list PodCertificateRequests")

	var list capiv1beta1.PodCertificateRequestList
	g.Expect(json.Unmarshal([]byte(output), &list)).To(Succeed(),
		"Failed to decode the PodCertificateRequest list")

	var matches []*capiv1beta1.PodCertificateRequest
	for i := range list.Items {
		pcr := &list.Items[i]
		if pcr.Spec.PodName == ref.name && pcr.Spec.PodUID == ref.uid && pcr.Spec.SignerName == signerName {
			matches = append(matches, pcr)
		}
	}

	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, pcr := range matches {
			names = append(names, pcr.Name)
		}
		StopTrying(fmt.Sprintf(
			"ambiguous PodCertificateRequest selection for pod %s and signer %q: %s; "+
				"a spec must assert against exactly one request",
			ref, signerName, strings.Join(names, ", "))).Now()
	}
	g.Expect(matches).To(HaveLen(1),
		"no PodCertificateRequest for pod %s and signer %q exists yet", ref, signerName)

	return matches[0]
}

// terminalCondition returns the request's single terminal condition, failing if
// the request carries none yet or - which kube-apiserver is supposed to prevent
// - carries more than one.
func terminalCondition(g Gomega, pcr *capiv1beta1.PodCertificateRequest) metav1.Condition {
	var terminal []metav1.Condition
	for _, cond := range pcr.Status.Conditions {
		for _, want := range terminalConditionTypes {
			if cond.Type == want {
				terminal = append(terminal, cond)
			}
		}
	}

	g.Expect(terminal).To(HaveLen(1),
		"request %s must carry exactly one terminal condition, has %d: %v", pcr.Name, len(terminal), terminal)
	g.Expect(terminal[0].Status).To(Equal(metav1.ConditionTrue),
		"a terminal condition must have status True")

	return terminal[0]
}

// expectIssued waits until the pod's request is issued and returns the parsed
// certificate chain.
//
// A complete Issued outcome is: exactly one terminal condition, of type Issued
// with reason CertificateIssued; a parseable certificate chain; all three
// status timestamps populated; and a matching Normal event. Asserting the whole
// set is what distinguishes "issued" from "half-written status that happens to
// carry a certificate".
func expectIssued(ref podRef) []*x509.Certificate {
	GinkgoHelper()

	var chain []*x509.Certificate
	var requestName string
	Eventually(func(g Gomega) {
		pcr := findPodCertificateRequest(g, ref)
		cond := terminalCondition(g, pcr)
		if cond.Type != capiv1beta1.PodCertificateRequestConditionTypeIssued {
			StopTrying(fmt.Sprintf("request %s for pod %s reached the terminal outcome %s (%s): %s",
				pcr.Name, ref, cond.Type, cond.Reason, cond.Message)).Now()
		}
		g.Expect(cond.Reason).To(Equal("CertificateIssued"),
			"an issued request must carry the CertificateIssued reason")

		g.Expect(pcr.Status.CertificateChain).NotTo(BeEmpty(),
			"an issued request must carry a certificate chain")
		g.Expect(pcr.Status.NotBefore).NotTo(BeNil(), "an issued request must carry notBefore")
		g.Expect(pcr.Status.NotAfter).NotTo(BeNil(), "an issued request must carry notAfter")
		g.Expect(pcr.Status.BeginRefreshAt).NotTo(BeNil(), "an issued request must carry beginRefreshAt")

		chain = parseCertificateChain(g, pcr.Status.CertificateChain)
		g.Expect(chain).NotTo(BeEmpty(), "the certificate chain must contain at least the leaf")
		requestName = pcr.Name
	}, terminalOutcomeTimeout).Should(Succeed())

	expectEvent(ref.namespace, requestName, corev1.EventTypeNormal, "CertificateIssued")

	return chain
}

// expectDenied waits until the pod's request is denied with the given reason
// and returns the recorded denial.
//
// A complete Denied outcome is: exactly one terminal condition, of type Denied
// with the expected reason; no certificate and no timestamps; a matching
// Warning event; and no further change once the controller has had another
// chance to reconcile the request.
func expectDenied(ref podRef, wantReason string) deniedRequest {
	GinkgoHelper()
	return expectTerminalDenialOrFailure(ref, capiv1beta1.PodCertificateRequestConditionTypeDenied, wantReason)
}

// expectFailed is the counterpart of expectDenied for requests the signer
// accepts but cannot fulfil.
//
// It has no caller yet: the only path that records a Failed condition is a
// signing failure (ReasonSigningFailed), which needs a broken or unusable CA
// and is therefore reachable only once the CA-lifecycle specs land. It is
// defined here so that stage does not have to re-derive the assertion set, and
// so the Failed shape is documented alongside the Denied one it must match.
//
//nolint:unused // wired up by the CA-lifecycle stage; see the comment above.
func expectFailed(ref podRef, wantReason string) deniedRequest {
	GinkgoHelper()
	return expectTerminalDenialOrFailure(ref, capiv1beta1.PodCertificateRequestConditionTypeFailed, wantReason)
}

// expectTerminalDenialOrFailure implements the shared shape of expectDenied and
// expectFailed: both are non-issuing terminal outcomes, and the guarantees that
// matter - cleared status fields, a warning event, immutability - are identical.
func expectTerminalDenialOrFailure(ref podRef, wantType, wantReason string) deniedRequest {
	GinkgoHelper()

	var outcome deniedRequest
	var requestName string
	var recorded metav1.Condition
	Eventually(func(g Gomega) {
		pcr := findPodCertificateRequest(g, ref)
		cond := terminalCondition(g, pcr)
		if cond.Type != wantType {
			StopTrying(fmt.Sprintf("request %s for pod %s reached the terminal outcome %s (%s), want %s: %s",
				pcr.Name, ref, cond.Type, cond.Reason, wantType, cond.Message)).Now()
		}
		g.Expect(cond.Reason).To(Equal(wantReason),
			"a %s request must carry the expected reason; message was: %s", wantType, cond.Message)

		expectStatusFieldsCleared(g, pcr)

		outcome = deniedRequest{Reason: cond.Reason, Message: cond.Message}
		requestName = pcr.Name
		recorded = cond
	}, terminalOutcomeTimeout).Should(Succeed())

	expectEvent(ref.namespace, requestName, corev1.EventTypeWarning, wantReason)
	expectTerminalConditionStable(ref, recorded)

	return outcome
}

// expectStatusFieldsCleared asserts that a non-issuing terminal outcome left no
// certificate material behind.
//
// The API declares certificateChain, notBefore, notAfter and beginRefreshAt
// immutable once populated, so a signer that populates any of them next to a
// Denied or Failed condition has written a status it can never take back. The
// timestamps matter as much as the chain: kubelet reads beginRefreshAt to
// schedule renewal, and a denied request advertising one is a renewal loop
// waiting to happen.
func expectStatusFieldsCleared(g Gomega, pcr *capiv1beta1.PodCertificateRequest) {
	g.Expect(pcr.Status.CertificateChain).To(BeEmpty(),
		"a non-issuing terminal outcome must never carry a certificate chain")
	g.Expect(pcr.Status.NotBefore).To(BeNil(),
		"a non-issuing terminal outcome must leave notBefore unset")
	g.Expect(pcr.Status.NotAfter).To(BeNil(),
		"a non-issuing terminal outcome must leave notAfter unset")
	g.Expect(pcr.Status.BeginRefreshAt).To(BeNil(),
		"a non-issuing terminal outcome must leave beginRefreshAt unset")
}

// expectTerminalConditionStable proves a terminal outcome is final by giving the
// controller another chance to reconcile the request and asserting nothing
// moved.
//
// The nudge is a metadata annotation on the request. The reconciler's event
// filter only overrides CreateFunc (see SetupWithManager), and predicate.Funcs
// returns true for an unset UpdateFunc, so writing an annotation enqueues a
// real reconcile - which Reconcile then drops on its immutability check. To keep
// this from degrading into a sleep in assertion's clothing if that ever changes,
// the helper counts the controller's "immutable" log lines for this request
// before and after the nudge and requires the count to rise.
func expectTerminalConditionStable(ref podRef, want metav1.Condition) {
	GinkgoHelper()

	var requestName string
	Eventually(func(g Gomega) {
		requestName = findPodCertificateRequest(g, ref).Name
	}).Should(Succeed())

	By("nudging the controller to reconcile the terminal request once more")
	before := controllerLogLineCount(requestName, "PodCertificateRequest is immutable")
	cmd := exec.Command("kubectl", "annotate", "podcertificaterequest", requestName,
		"-n", ref.namespace, "--overwrite",
		fmt.Sprintf("%s=%d", reconcileNudgeAnnotation, time.Now().UnixNano()))
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to annotate request %s: %s", requestName, output)

	By("waiting for the controller to observe the nudged request")
	Eventually(func() int {
		return controllerLogLineCount(requestName, "PodCertificateRequest is immutable")
	}, time.Minute).Should(BeNumerically(">", before),
		"the annotation must produce a further reconcile of request %s, otherwise this proves nothing", requestName)

	By("verifying the terminal outcome did not change")
	Consistently(func(g Gomega) {
		pcr := findPodCertificateRequest(g, ref)
		cond := terminalCondition(g, pcr)
		g.Expect(cond.Type).To(Equal(want.Type), "the terminal condition type must not change")
		g.Expect(cond.Reason).To(Equal(want.Reason), "the terminal condition reason must not change")
		g.Expect(cond.Message).To(Equal(want.Message), "the terminal condition message must not change")
		g.Expect(cond.LastTransitionTime).To(Equal(want.LastTransitionTime),
			"a re-recorded condition would move lastTransitionTime")
		expectStatusFieldsCleared(g, pcr)
	}, 5*time.Second, time.Second).Should(Succeed())
}

// expectEvent waits for an event of the given type and reason naming the given
// object.
//
// The event is the operator-visible half of the outcome: a status condition is
// only reachable by someone who already knows to look at the request, while the
// event is what surfaces in `kubectl get events` and in whatever collects them.
func expectEvent(namespace, involvedName, eventType, reason string) {
	GinkgoHelper()

	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", "events", "-n", namespace,
			"--field-selector", "involvedObject.name="+involvedName, "-o", "json")
		output, err := utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred(), "Failed to list events for %s", involvedName)

		var list corev1.EventList
		g.Expect(json.Unmarshal([]byte(output), &list)).To(Succeed(), "Failed to decode the event list")

		observed := make([]string, 0, len(list.Items))
		for _, event := range list.Items {
			if event.Type == eventType && event.Reason == reason {
				return
			}
			observed = append(observed, fmt.Sprintf("%s/%s", event.Type, event.Reason))
		}
		g.Expect(observed).To(ContainElement(eventType+"/"+reason),
			"no %s event with reason %q was recorded for %s", eventType, reason, involvedName)
	}, time.Minute).Should(Succeed())
}

// controllerLogLineCount reports how many lines of the current controller pod's
// log contain all of the given substrings. It is diagnostic-grade on purpose:
// an unreadable log counts as zero rather than failing, so the caller's
// Eventually keeps polling across a pod that is still starting.
func controllerLogLineCount(needles ...string) int {
	cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
	output, err := utils.Run(cmd)
	if err != nil {
		return 0
	}

	count := 0
	for _, line := range strings.Split(output, "\n") {
		matched := true
		for _, needle := range needles {
			if !strings.Contains(line, needle) {
				matched = false
				break
			}
		}
		if matched {
			count++
		}
	}
	return count
}

// parseCertificateChain decodes every PEM block of an issued chain.
func parseCertificateChain(g Gomega, chainPEM string) []*x509.Certificate {
	var certs []*x509.Certificate
	data := []byte(chainPEM)
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		g.Expect(block.Type).To(Equal("CERTIFICATE"),
			"an issued chain must contain only CERTIFICATE blocks")
		cert, err := x509.ParseCertificate(block.Bytes)
		g.Expect(err).NotTo(HaveOccurred(), "chain entry must be a valid certificate")
		certs = append(certs, cert)
	}
	return certs
}
