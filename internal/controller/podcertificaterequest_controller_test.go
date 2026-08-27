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

package controller

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// durationAnnotation is the spec.unverifiedUserAnnotations key the signer
	// reads the requested certificate duration from. Spelled out here rather
	// than built from the podcertificate constants, which carry a deprecation
	// notice aimed at the pod-annotation fallback.
	durationAnnotation = testSignerName + "-duration"

	// foreignSignerName belongs to no controller in this suite, so requests
	// created under it are never reconciled.
	foreignSignerName = "example.com/some-other-signer"
)

var _ = Describe("PodCertificateRequest Controller", func() {
	Context("When reconciling a request for this signer", func() {
		It("issues a certificate the API server accepts", func() {
			pcr := createPodAndRequest("issued", testSignerName, nil)

			By("waiting for the controller to record the Issued condition")
			issued := waitForCondition(pcr, certificatesv1.PodCertificateRequestConditionTypeIssued)
			Expect(issued.Reason).To(Equal(string(ReasonCertificateIssued)))

			By("reading back the status the API server persisted")
			// Getting the object back with these fields set is the assertion
			// that matters: kube-apiserver validates the certificate chain and
			// the lifetime/refresh bounds on the status subresource, so a
			// rejected write would leave the status empty and time out above.
			var got certificatesv1.PodCertificateRequest
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pcr), &got)).To(Succeed())

			Expect(got.Status.CertificateChain).NotTo(BeEmpty())
			block, _ := pem.Decode([]byte(got.Status.CertificateChain))
			Expect(block).NotTo(BeNil(), "certificate chain is not PEM")
			Expect(block.Type).To(Equal("CERTIFICATE"))
			leaf, err := x509.ParseCertificate(block.Bytes)
			Expect(err).NotTo(HaveOccurred())
			Expect(leaf.Subject.CommonName).To(Equal(got.Spec.PodName))

			Expect(got.Status.NotBefore).NotTo(BeNil())
			Expect(got.Status.NotAfter).NotTo(BeNil())
			Expect(got.Status.BeginRefreshAt).NotTo(BeNil())
			Expect(got.Status.NotAfter.Time).To(BeTemporally(">", got.Status.NotBefore.Time))
			Expect(got.Status.NotAfter.Sub(got.Status.NotBefore.Time)).
				To(BeNumerically("<=", time.Duration(testMaxExpirationSeconds)*time.Second))
		})

		It("emits a single Issued event only once the status is persisted", func() {
			pcr := createPodAndRequest("issued-event", testSignerName, nil)

			By("waiting for the Issued condition, so the status write has landed")
			waitForCondition(pcr, certificatesv1.PodCertificateRequestConditionTypeIssued)

			By("observing exactly one CertificateIssued event for the request")
			// The event recorder is asynchronous, so the event may lag the
			// condition; poll until it appears, then hold to prove the reconcile
			// does not re-emit it on subsequent passes.
			Eventually(func(g Gomega) {
				g.Expect(issuedEventsFor(g, pcr)).To(HaveLen(1))
			}, 30*time.Second, 200*time.Millisecond).Should(Succeed())
			Consistently(func(g Gomega) {
				g.Expect(issuedEventsFor(g, pcr)).To(HaveLen(1))
			}, 3*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	})

	Context("When the request carries an invalid configuration", func() {
		It("records a terminal Denied status the API server accepts", func() {
			// The signer rejects durations below kube-apiserver's one hour
			// minimum, so this drives the reconciler down the terminal path.
			pcr := createPodAndRequest("denied", testSignerName, map[string]string{durationAnnotation: "30m"})

			By("waiting for the controller to record the Denied condition")
			denied := waitForCondition(pcr, certificatesv1.PodCertificateRequestConditionTypeDenied)
			Expect(denied.Reason).To(Equal(string(ReasonInvalidUserAnnotations)))

			By("checking the API server accepted the terminal write with cleared certificate fields")
			var got certificatesv1.PodCertificateRequest
			Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pcr), &got)).To(Succeed())

			Expect(got.Status.CertificateChain).To(BeEmpty())
			Expect(got.Status.NotBefore).To(BeNil())
			Expect(got.Status.NotAfter).To(BeNil())
			Expect(got.Status.BeginRefreshAt).To(BeNil())
		})
	})

	Context("When the request belongs to another signer", func() {
		It("leaves the request untouched", func() {
			pcr := createPodAndRequest("other-signer", foreignSignerName, nil)

			Consistently(func(g Gomega) {
				var got certificatesv1.PodCertificateRequest
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pcr), &got)).To(Succeed())
				g.Expect(got.Status.Conditions).To(BeEmpty())
			}, 3*time.Second, 250*time.Millisecond).Should(Succeed())
		})
	})

	Context("When a status write violates the API server's own rules", func() {
		// This is what makes the specs above meaningful: they assert that the
		// API server accepted the controller's writes, which only says
		// something if the API server rejects bad ones. The request is created
		// for a foreign signer so the controller leaves it alone and the
		// status below is the only write it ever sees.
		It("is rejected", func() {
			pcr := createPodAndRequest("invalid-status", foreignSignerName, nil)

			pcr.Status.Conditions = []metav1.Condition{{
				Type:               certificatesv1.PodCertificateRequestConditionTypeIssued,
				Status:             metav1.ConditionTrue,
				LastTransitionTime: metav1.Now(),
				Reason:             string(ReasonCertificateIssued),
				Message:            "Certificate successfully issued",
			}}
			pcr.Status.CertificateChain = "not a PEM certificate"

			err := k8sClient.Status().Update(ctx, pcr)
			Expect(err).To(HaveOccurred())
			Expect(apierrors.IsInvalid(err)).To(BeTrue(), "expected an Invalid error, got %v", err)
		})
	})
})

// createPodAndRequest creates a pod and a PodCertificateRequest referring to
// it, both named after suffix, and registers their cleanup. The request
// carries the pod's live UID, which the reconciler gates on before signing.
// The signer name is a parameter because the request spec is immutable, so it
// has to be right at creation time.
func createPodAndRequest(suffix, signerName string, userAnnotations map[string]string) *certificatesv1.PodCertificateRequest {
	GinkgoHelper()

	name := "pcr-" + suffix
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: corev1.PodSpec{
			NodeName:   "envtest-node",
			Containers: []corev1.Container{{Name: "app", Image: "busybox"}},
		},
	}
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	Expect(pod.UID).NotTo(BeEmpty())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, pod))).To(Succeed())
	})

	maxExpirationSeconds := testMaxExpirationSeconds
	pcr := &certificatesv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec: certificatesv1.PodCertificateRequestSpec{
			SignerName:                signerName,
			PodName:                   pod.Name,
			PodUID:                    pod.UID,
			ServiceAccountName:        "default",
			ServiceAccountUID:         "envtest-serviceaccount-uid",
			NodeName:                  "envtest-node",
			NodeUID:                   "envtest-node-uid",
			MaxExpirationSeconds:      &maxExpirationSeconds,
			StubPKCS10Request:         newStubPKCS10Request(),
			UnverifiedUserAnnotations: userAnnotations,
		},
	}
	Expect(k8sClient.Create(ctx, pcr)).To(Succeed())
	DeferCleanup(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, pcr))).To(Succeed())
	})

	return pcr
}

// newStubPKCS10Request returns the DER-encoded PKCS#10 request kubelet would
// attach to a PodCertificateRequest. kube-apiserver verifies its signature
// during admission, which is what proves possession of the private key.
func newStubPKCS10Request() []byte {
	GinkgoHelper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	Expect(err).NotTo(HaveOccurred())

	return csr
}

// issuedEventsFor returns the CertificateIssued events the API server holds for
// the given request. Events are listed as core/v1 and filtered in Go, which
// sidesteps field-selector support questions and keeps the assertion explicit.
func issuedEventsFor(g Gomega, pcr *certificatesv1.PodCertificateRequest) []corev1.Event {
	var list corev1.EventList
	g.Expect(k8sClient.List(ctx, &list, client.InNamespace(pcr.Namespace))).To(Succeed())

	var out []corev1.Event
	for _, e := range list.Items {
		if e.InvolvedObject.Name == pcr.Name && e.Reason == string(ReasonCertificateIssued) {
			out = append(out, e)
		}
	}
	return out
}

// waitForCondition polls the request until the controller records the given
// condition type, and returns it.
func waitForCondition(pcr *certificatesv1.PodCertificateRequest, conditionType string) metav1.Condition {
	GinkgoHelper()

	var found metav1.Condition
	Eventually(func(g Gomega) {
		var got certificatesv1.PodCertificateRequest
		g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(pcr), &got)).To(Succeed())
		g.Expect(got.Status.Conditions).To(HaveLen(1))
		g.Expect(got.Status.Conditions[0].Type).To(Equal(conditionType))
		g.Expect(got.Status.Conditions[0].Status).To(Equal(metav1.ConditionTrue))
		found = got.Status.Conditions[0]
	}, 30*time.Second, 200*time.Millisecond).Should(Succeed())

	return found
}
