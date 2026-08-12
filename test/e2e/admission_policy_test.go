//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

func dryRunPodAdmission(name, requestedSigner string, annotations map[string]string) (string, error) {
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: workloadNamespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:    "workload",
				Image:   "busybox:1.37",
				Command: []string{"sleep", "60"},
			}},
			Volumes: []corev1.Volume{{
				Name: "certificate",
				VolumeSource: corev1.VolumeSource{
					Projected: &corev1.ProjectedVolumeSource{
						Sources: []corev1.VolumeProjection{{
							PodCertificate: &corev1.PodCertificateProjection{
								SignerName:           requestedSigner,
								KeyType:              "ED25519",
								CredentialBundlePath: "credentialbundle.pem",
								UserAnnotations:      annotations,
							},
						}},
					},
				},
			}},
		},
	}

	manifest, err := json.Marshal(pod)
	if err != nil {
		return "", err
	}
	cmd := exec.Command("kubectl", "create", "--dry-run=server", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	return utils.Run(cmd)
}

func defineAdmissionPolicyTests() {
	Context("DNS SAN ValidatingAdmissionPolicy", func() {
		BeforeAll(func() {
			By("waiting for the admission policy to compile without type-check warnings")
			Eventually(func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "validatingadmissionpolicy",
					releaseName+"-dns-san-validation", "-o", "json")
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).NotTo(ContainSubstring("expressionWarnings"))
			}).Should(Succeed())
		})

		DescribeTable("admits valid or out-of-scope Pod certificate requests",
			func(name, requestedSigner string, annotations map[string]string) {
				output, err := dryRunPodAdmission(name, requestedSigner, annotations)
				Expect(err).NotTo(HaveOccurred(), output)
			},
			Entry("a 63-character DNS label", "vap-valid-63", signerName, map[string]string{
				signerName + "-san": strings.Repeat("a", 63) + ".example.org",
			}),
			Entry("multiple valid DNS SANs", "vap-valid-list", signerName, map[string]string{
				signerName + "-san": "api.example.org, web.example.org",
			}),
			Entry("pod identity interpolation", "vap-valid-pod", signerName, map[string]string{
				signerName + "-san": "${pod.name}.${pod.namespace}.svc.${cluster.fqdn}",
			}),
			Entry("default service account interpolation", "vap-valid-sa", signerName, map[string]string{
				signerName + "-san": "${pod.serviceAccountName}.${pod.namespace}.svc",
			}),
			Entry("matching signer without SAN annotation", "vap-no-san", signerName, map[string]string{
				signerName + "-cn": "valid.example.org",
			}),
			Entry("another signer", "vap-other-signer", "other.example/signer", map[string]string{
				"other.example/signer-san": strings.Repeat("a", 64) + ".example.org",
			}),
		)

		DescribeTable("rejects malformed effective DNS SANs at Pod admission",
			func(name, san string) {
				output, err := dryRunPodAdmission(name, signerName, map[string]string{signerName + "-san": san})
				Expect(err).To(HaveOccurred(), output)
				Expect(output).To(ContainSubstring("each label must be at most 63 characters"))
			},
			Entry("64-character label", "vap-invalid-64", strings.Repeat("a", 64)+".example.org"),
			Entry("prefix makes interpolated pod label too long", strings.Repeat("p", 58), "prefix-${pod.name}.example.org"),
			Entry("one invalid SAN in a list", "vap-invalid-list", "valid.example.org,"+strings.Repeat("a", 64)+".example.org"),
			Entry("empty list member", "vap-empty-member", "valid.example.org,,other.example.org"),
			Entry("empty DNS label", "vap-empty-label", "a..example.org"),
			Entry("trailing hyphen", "vap-trailing-hyphen", "invalid-.example.org"),
			Entry("invalid character", "vap-invalid-char", "invalid_name.example.org"),
			Entry("complete name over 253 characters", "vap-too-long", strings.Repeat("a.", 126)+"aa"),
			Entry("unsupported interpolation variable", "vap-unknown-var", "${pod.uid}.example.org"),
			Entry("unterminated interpolation variable", "vap-unterminated", "${pod.name.example.org"),
		)
	})
}
