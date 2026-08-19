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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	capiv1beta1 "k8s.io/api/certificates/v1beta1"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
)

// Key types, certificate semantics and lifetime.
//
// These specs run under the chart-defaults install profile, where no feature
// flag is on and no annotation asks for an identity: what a certificate carries
// here is what the signer produces from the verified request alone. That keeps
// the key-type matrix about the key, and the lifetime matrix about the clock,
// rather than about the identity rules the boundary specs cover separately.

// defaultRefreshBefore is podcertificate.DefaultRefreshBefore: how far ahead of
// notAfter the signer tells kubelet to start renewing when no refresh
// annotation asks for something else.
const defaultRefreshBefore = 15 * time.Minute

// statusTimeTolerance is how far status.beginRefreshAt may sit from the exact
// notAfter - refreshBefore, and the status timestamps from the certificate's
// own. Both sides are metav1.Time, which serializes at second resolution, so
// the arithmetic should be exact; the tolerance states that the assertion is
// about the relationship and not about sub-second serialization.
const statusTimeTolerance = time.Second

// projectionKeyType is one row of the key-type matrix.
type projectionKeyType struct {
	// keyType is the spelling corev1.PodCertificateProjection.KeyType takes.
	keyType string

	// algorithm is the public key algorithm the issued leaf must carry, and
	// probeAlgorithm the same value as the in-pod probe reports it
	// (x509.PublicKeyAlgorithm.String()).
	algorithm      x509.PublicKeyAlgorithm
	probeAlgorithm string

	// curveName is the expected elliptic curve for an ECDSA key ("P-256"),
	// empty otherwise; rsaBits the expected modulus size for an RSA key, zero
	// otherwise.
	curveName string
	rsaBits   int

	// keyUsage is the exact KeyUsage the certificate must carry. It is stated
	// per row rather than derived, because the rule under test is precisely
	// that keyEncipherment appears for RSA key transport and for nothing else.
	keyUsage x509.KeyUsage
}

// supportedProjectionKeyTypes is the set of key types a podCertificate
// projection may request.
//
// The set is not the signer's choice: kubelet generates the keypair and
// kube-apiserver validates the field, so this is Kubernetes' list, taken from
// the KeyType field documentation in k8s.io/api/core/v1 (v0.36.3, the version
// this repository builds against). "the key types Kubernetes supports" is
// asserted rather than trusted - the admission table below submits every one of
// these to the apiserver, and submits key types that are not on the list and
// must be refused.
//
// RSA2048 is deliberately absent: it is not a value the field accepts.
var supportedProjectionKeyTypes = []projectionKeyType{
	{
		keyType:        "ED25519",
		algorithm:      x509.Ed25519,
		probeAlgorithm: "Ed25519",
		keyUsage:       x509.KeyUsageDigitalSignature,
	},
	{
		keyType:        "ECDSAP256",
		algorithm:      x509.ECDSA,
		probeAlgorithm: "ECDSA",
		curveName:      "P-256",
		keyUsage:       x509.KeyUsageDigitalSignature,
	},
	{
		keyType:        "ECDSAP384",
		algorithm:      x509.ECDSA,
		probeAlgorithm: "ECDSA",
		curveName:      "P-384",
		keyUsage:       x509.KeyUsageDigitalSignature,
	},
	{
		keyType:        "ECDSAP521",
		algorithm:      x509.ECDSA,
		probeAlgorithm: "ECDSA",
		curveName:      "P-521",
		keyUsage:       x509.KeyUsageDigitalSignature,
	},
	{
		keyType:        "RSA3072",
		algorithm:      x509.RSA,
		probeAlgorithm: "RSA",
		rsaBits:        3072,
		// keyEncipherment is meaningful only for RSA key transport, so it is
		// the one row set where it must appear.
		keyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	},
	{
		keyType:        "RSA4096",
		algorithm:      x509.RSA,
		probeAlgorithm: "RSA",
		rsaBits:        4096,
		keyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	},
}

// defineKeyTypeAndLifetimeTests is called from the chart-defaults install
// profile (install_profiles_test.go), so nothing here runs with a feature flag
// on.
func defineKeyTypeAndLifetimeTests() {
	Context("Key types and certificate semantics", func() {
		var trustAnchors []*x509.Certificate

		BeforeAll(func() {
			By("reading the trust anchors the signer published")
			// Every leaf below is verified against these, and the probe pods
			// project the same bundle by name, so a missing bundle is one clear
			// failure here rather than a chain-verification failure per row.
			Eventually(func(g Gomega) {
				certs := getTrustBundleCertificates(g)
				g.Expect(certs).NotTo(BeEmpty(), "the trust bundle must carry the current CA")
				trustAnchors = certs
			}).Should(Succeed())
		})

		// Server-side dry run, not issuance: this spec is about which key types
		// the apiserver defines, and it answers that in one admission round trip
		// per row instead of a pod and a certificate. The rejected rows are the
		// half that makes the accepted list mean something.
		DescribeTable("admits exactly the key types the projection defines",
			func(keyType string, admitted bool) {
				output, err := dryRunCertTestPod(certTestPod{
					name:    "pcs-keytype-admission",
					keyType: keyType,
				})
				if admitted {
					Expect(err).NotTo(HaveOccurred(),
						"kube-apiserver must accept the documented key type %q: %s", keyType, output)
					return
				}
				Expect(err).To(HaveOccurred(),
					"kube-apiserver must reject the undefined key type %q: %s", keyType, output)
				// The exact wording of an apiserver validation message is
				// version-specific; that it names the field is not.
				Expect(output).To(ContainSubstring("keyType"),
					"the rejection must name the offending field")
			},
			Entry("ED25519", "ED25519", true),
			Entry("ECDSAP256", "ECDSAP256", true),
			Entry("ECDSAP384", "ECDSAP384", true),
			Entry("ECDSAP521", "ECDSAP521", true),
			Entry("RSA3072", "RSA3072", true),
			Entry("RSA4096", "RSA4096", true),
			// RSA2048 is the interesting negative: it is the size most PKI
			// tooling defaults to, and it is not a value this field takes.
			Entry("RSA2048", "RSA2048", false),
			Entry("RSA1024", "RSA1024", false),
			Entry("a lower-case spelling of a supported type", "ed25519", false),
			Entry("a key type that does not exist", "NOTAKEYTYPE", false),
		)

		DescribeTable("issues a conformant certificate for every supported key type",
			keyTypeMatrix(func(want projectionKeyType) {
				podName := "pcs-keytype-" + strings.ToLower(want.keyType)

				By("creating a probe workload requesting a " + want.keyType + " keypair")
				pod := createCertTestPod(certTestPod{
					name:                   podName,
					keyType:                want.keyType,
					image:                  workloadProbeImage,
					args:                   probeArgs(podName, report.RoleServer),
					clusterTrustBundleName: trustBundleName,
				})

				By("waiting for the PodCertificateRequest to be issued")
				chain := expectIssued(pod)
				request := getPodCertificateRequest(pod)

				By("verifying the leaf carries the requested key and the signer's exact defaults")
				expectConformantLeaf(pod, chain, trustAnchors, want)

				By("verifying the status timestamps describe the certificate that was issued")
				expectStatusTimes(request, chain[0], defaultRefreshBefore)

				By("waiting for the pod to run with the projected credential")
				expectPodRunning(pod)

				By("verifying the workload holds a private key that matches the issued leaf")
				// This is the assertion the suite cannot make from outside: the
				// probe is the only party holding the private key kubelet
				// generated, and bundle.keyMatchesLeaf (asserted by
				// expectProbeReport) is what proves the certificate was issued
				// for that key and not for some other.
				observed := expectProbeReport(pod, report.RoleServer)
				Expect(observed.Facts.LeafKeyAlgorithm).To(Equal(want.probeAlgorithm),
					"the projected leaf must carry a %s key", want.probeAlgorithm)
				Expect(observed.Facts.ChainSHA256).To(Equal(certificateFingerprints(chain)),
					"the projected chain must be the one the request status published, "+
						"otherwise the assertions above describe a different certificate")
			})...,
		)

		It("clamps the default lifetime to the projection's maxExpirationSeconds", func() {
			const podName = "pcs-duration-clamped"
			const maxExpiration = 2 * time.Hour

			By("creating a workload pod whose projection caps the lifetime below the signer default")
			// The signer's own default is 24 hours. Nothing here asks for a
			// duration, so a 2-hour certificate can only be the clamp.
			pod := createCertTestPod(certTestPod{
				name:                 podName,
				maxExpirationSeconds: ptr(int32(maxExpiration / time.Second)),
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]
			request := getPodCertificateRequest(pod)

			By("verifying the request carries the cap the projection asked for")
			Expect(request.Spec.MaxExpirationSeconds).NotTo(BeNil())
			Expect(*request.Spec.MaxExpirationSeconds).To(Equal(int32(maxExpiration/time.Second)),
				"kubelet must copy maxExpirationSeconds onto the request verbatim")

			By("verifying the certificate lifetime is the cap, not the signer default")
			Expect(leaf.NotAfter.Sub(leaf.NotBefore)).To(Equal(maxExpiration))
			Expect(leaf.NotAfter.Sub(leaf.NotBefore)).To(BeNumerically("<", defaultCertificateLifetime),
				"a clamped lifetime must be shorter than the unclamped default, or this proves nothing")

			By("verifying the status timestamps describe the certificate that was issued")
			expectStatusTimes(request, leaf, defaultRefreshBefore)
		})

		It("issues the requested duration and refresh window", func() {
			const podName = "pcs-duration-explicit"
			const duration = 4 * time.Hour
			const refreshBefore = 90 * time.Minute

			By("creating a workload pod requesting an explicit lifetime and refresh window")
			pod := applyCertTestPod(podName, map[string]string{
				signerName + "-duration": duration.String(),
				signerName + "-refresh":  refreshBefore.String(),
			})

			By("waiting for the PodCertificateRequest to be issued")
			leaf := expectIssued(pod)[0]
			request := getPodCertificateRequest(pod)

			By("verifying the certificate lifetime is exactly what was asked for")
			Expect(leaf.NotAfter.Sub(leaf.NotBefore)).To(Equal(duration))

			By("verifying beginRefreshAt is notAfter minus the requested refresh window")
			expectStatusTimes(request, leaf, refreshBefore)
		})

		DescribeTable("denies a lifetime kube-apiserver would refuse on the status subresource",
			func(podName string, annotations map[string]string, wantMessage string) {
				By("creating a workload pod requesting an unusable lifetime")
				// These are validated before signing rather than discovered when
				// the status write is rejected: a rejected write is a requeue
				// loop, a denial is an answer.
				pod := applyCertTestPod(podName, annotations)

				By("waiting for the PodCertificateRequest to be denied")
				denial := expectDenied(pod, capiv1beta1.PodCertificateRequestConditionInvalidUserConfig)
				Expect(denial.Message).To(ContainSubstring(wantMessage))
			},
			// maxExpirationSeconds is unset, so kube-apiserver's 24-hour default
			// is the cap this exceeds.
			Entry("a duration above the projection maximum", "pcs-duration-over-max", map[string]string{
				signerName + "-duration": "48h",
			}, "exceeds the maxExpirationSeconds of the request"),
			Entry("a duration below the API minimum", "pcs-duration-under-min", map[string]string{
				signerName + "-duration": "30m",
			}, "must be at least 1h0m0s"),
			// kube-apiserver requires beginRefreshAt to sit at least 10 minutes
			// inside both ends of the validity window.
			Entry("a refresh window inside the API margin", "pcs-refresh-too-small", map[string]string{
				signerName + "-refresh": "5m",
			}, "must be at least 10m0s"),
			Entry("a refresh window reaching past notBefore", "pcs-refresh-too-large", map[string]string{
				signerName + "-refresh": "23h55m",
			}, "must not exceed the certificate duration"),
		)
	})
}

// keyTypeMatrix renders the spec body and one entry per supported key type as
// the arguments DescribeTable takes.
//
// It is assembled rather than hand-written because DescribeTable's parameter is
// ...any, so a []TableEntry cannot be spread after the body function - and a
// hand-written row per key type is exactly the kind of list that drifts away
// from supportedProjectionKeyTypes above.
func keyTypeMatrix(body func(projectionKeyType)) []any {
	args := make([]any, 0, len(supportedProjectionKeyTypes)+1)
	args = append(args, body)
	for _, keyType := range supportedProjectionKeyTypes {
		args = append(args, Entry(keyType.keyType, keyType))
	}
	return args
}

// expectConformantLeaf asserts everything the signer must get right about an
// issued leaf that was requested with no annotations: the key it was issued
// for, that it is an end-entity certificate and not a CA, its exact usage, its
// exact identity, and that it chains to the published trust anchors.
//
// It is one helper rather than a helper per property because these hold
// together: a certificate that is correct in its key and wrong in its basic
// constraints is not a partially conformant certificate, it is a CA the
// workload was handed.
func expectConformantLeaf(
	ref podRef,
	chain []*x509.Certificate,
	trustAnchors []*x509.Certificate,
	want projectionKeyType,
) {
	GinkgoHelper()

	Expect(chain).To(HaveLen(defaultChainLength),
		"an issued chain must carry the leaf and the CA that signed it")
	leaf, issuer := chain[0], chain[1]

	By("verifying the leaf carries the requested public key")
	Expect(leaf.PublicKeyAlgorithm).To(Equal(want.algorithm))
	switch want.algorithm {
	case x509.Ed25519:
		key, ok := leaf.PublicKey.(ed25519.PublicKey)
		Expect(ok).To(BeTrue(), "an ED25519 request must yield an Ed25519 public key, got %T", leaf.PublicKey)
		Expect(key).To(HaveLen(ed25519.PublicKeySize))
	case x509.ECDSA:
		key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		Expect(ok).To(BeTrue(), "an ECDSA request must yield an ECDSA public key, got %T", leaf.PublicKey)
		Expect(key.Curve.Params().Name).To(Equal(want.curveName),
			"the certificate must carry the curve the projection requested")
	case x509.RSA:
		key, ok := leaf.PublicKey.(*rsa.PublicKey)
		Expect(ok).To(BeTrue(), "an RSA request must yield an RSA public key, got %T", leaf.PublicKey)
		Expect(key.N.BitLen()).To(Equal(want.rsaBits),
			"the certificate must carry the modulus size the projection requested")
	default:
		Fail(fmt.Sprintf("unhandled public key algorithm %s in the key-type matrix", want.algorithm))
	}

	By("verifying the leaf is an end-entity certificate")
	Expect(leaf.SerialNumber).NotTo(BeNil())
	Expect(leaf.SerialNumber.Sign()).To(Equal(1), "a certificate serial number must be positive and non-zero")
	Expect(leaf.IsCA).To(BeFalse(), "a workload certificate must never be a CA")
	// The signer asserts basicConstraints with cA:FALSE rather than leaving the
	// extension out (ADR-0003). RFC 5280 6.1.4 already makes the absence safe
	// for a conforming verifier, but the signer cannot enumerate the TLS stacks
	// that will verify its output, so it says end-entity explicitly instead of
	// relying on the verifier to infer it. BasicConstraintsValid is Go's report
	// that the extension was present in the DER, so this pins presence; IsCA
	// above pins the value.
	Expect(leaf.BasicConstraintsValid).To(BeTrue(),
		"every issued leaf must carry a basicConstraints extension asserting cA:FALSE")

	By("verifying the key usage matches the key type and the extended key usage the default")
	Expect(leaf.KeyUsage).To(Equal(want.keyUsage),
		"key usage must be exactly %d for a %s key, got %d", want.keyUsage, want.keyType, leaf.KeyUsage)
	Expect(leaf.ExtKeyUsage).To(ConsistOf(x509.ExtKeyUsageServerAuth),
		"the default extended key usage is serverAuth only")
	Expect(leaf.UnknownExtKeyUsage).To(BeEmpty(),
		"the signer must add no extended key usage the suite cannot name")

	By("verifying the identity is the pod's own, and nothing else")
	Expect(leaf.Subject.CommonName).To(Equal(ref.name), "the default common name is the pod name")
	Expect(leaf.DNSNames).To(ConsistOf(
		fmt.Sprintf("%s.%s.pod.cluster.local", ref.name, ref.namespace),
		fmt.Sprintf("%s.%s.svc.cluster.local", ref.name, ref.namespace),
	), "the default SANs are the canonical pod and service DNS forms")
	Expect(leaf.IPAddresses).To(BeEmpty(), "the defaults must add no IP SAN")
	Expect(leaf.URIs).To(BeEmpty(), "the defaults must add no URI SAN")
	Expect(leaf.EmailAddresses).To(BeEmpty(), "the defaults must add no email SAN")

	By("verifying the chain verifies against the published ClusterTrustBundle")
	Expect(issuer.IsCA).To(BeTrue(), "the second chain entry must be the issuing CA")
	Expect(leaf.CheckSignatureFrom(issuer)).To(Succeed(),
		"the leaf must be signed by the CA it is served with")
	expectChainVerifies(leaf, trustAnchors)
}

// expectChainVerifies proves the leaf is trusted by a relying party that has
// only the published ClusterTrustBundle - which is the only trust material a
// workload in this cluster is given.
func expectChainVerifies(leaf *x509.Certificate, trustAnchors []*x509.Certificate) {
	GinkgoHelper()

	roots := x509.NewCertPool()
	for _, anchor := range trustAnchors {
		roots.AddCert(anchor)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots,
		// The identity and the extended key usage are asserted exactly
		// elsewhere; what this call answers is whether the chain builds and the
		// signatures verify.
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		CurrentTime: leaf.NotBefore.Add(time.Minute),
	})
	Expect(err).NotTo(HaveOccurred(),
		"the issued leaf must verify against the trust anchors the signer published")
}

// expectStatusTimes asserts that the timestamps on the request status describe
// the certificate that was actually issued, and that the renewal hint sits
// where the signer promised.
//
// kubelet acts on these three fields, not on the certificate it was handed: a
// status whose notAfter disagrees with the certificate is a workload that
// renews at the wrong time, and a beginRefreshAt outside the validity window is
// a status kube-apiserver refuses outright.
func expectStatusTimes(
	request *capiv1beta1.PodCertificateRequest,
	leaf *x509.Certificate,
	wantRefreshBefore time.Duration,
) {
	GinkgoHelper()

	Expect(request.Status.NotBefore).NotTo(BeNil())
	Expect(request.Status.NotAfter).NotTo(BeNil())
	Expect(request.Status.BeginRefreshAt).NotTo(BeNil())

	notBefore := request.Status.NotBefore.Time
	notAfter := request.Status.NotAfter.Time
	beginRefreshAt := request.Status.BeginRefreshAt.Time

	By("verifying the status validity window is the certificate's own")
	Expect(notBefore).To(BeTemporally("~", leaf.NotBefore, statusTimeTolerance),
		"status.notBefore must be the certificate's notBefore")
	Expect(notAfter).To(BeTemporally("~", leaf.NotAfter, statusTimeTolerance),
		"status.notAfter must be the certificate's notAfter")

	By("verifying the renewal hint lies strictly inside the validity window")
	Expect(beginRefreshAt).To(BeTemporally(">", notBefore),
		"beginRefreshAt must lie after notBefore")
	Expect(beginRefreshAt).To(BeTemporally("<", notAfter),
		"beginRefreshAt must lie before notAfter")

	By("verifying the renewal hint is notAfter minus the refresh window")
	Expect(notAfter.Sub(beginRefreshAt)).To(BeNumerically("~", wantRefreshBefore, statusTimeTolerance),
		"beginRefreshAt must be notAfter - %s, within %s", wantRefreshBefore, statusTimeTolerance)
}
