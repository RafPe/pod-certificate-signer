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
	"bytes"
	"encoding/json"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// defaultCredentialBundlePath is the file kubelet writes the issued private key
// and certificate chain to, relative to the projected volume's mount point.
const defaultCredentialBundlePath = "credentialbundle.pem"

// certTestPodMountPath is where the projected volume is mounted in the
// workload container.
const certTestPodMountPath = "/var/run/x509"

// certTestPod describes the workload pod the certificate specs create.
//
// The fields mirror the knobs corev1.PodCertificateProjection exposes, so a
// spec states what it wants rather than assembling a YAML document by string
// concatenation. Building a typed corev1.Pod is what makes the projection
// type-checked against the k8s.io/api version the controller itself builds
// against: a field the API renames or drops becomes a compile error here
// instead of a request the apiserver silently admits with the setting ignored.
//
// Zero values are filled in by withDefaults, so a spec sets only what it cares
// about. serviceAccountName, keyType, maxExpirationSeconds and
// clusterTrustBundleName have no caller in this stage's specs; they exist
// because the projection exposes them and the credential-conformance and
// key-type specs that follow need them addressable without another refactor.
type certTestPod struct {
	// name and namespace identify the pod. namespace defaults to
	// workloadNamespace.
	name      string
	namespace string

	// serviceAccountName is the identity the pod runs as, and therefore the
	// identity ${pod.serviceAccountName} resolves to. Defaults to "default".
	serviceAccountName string

	// keyType is the projection's requested key algorithm. Defaults to
	// ED25519.
	keyType string

	// credentialBundlePath is the file kubelet writes the key and chain to.
	// Defaults to defaultCredentialBundlePath.
	credentialBundlePath string

	// maxExpirationSeconds caps the lifetime the signer may issue. nil leaves
	// the field unset, so kube-apiserver applies its own 24-hour default.
	maxExpirationSeconds *int32

	// userAnnotations are the signer-scoped annotations the projection carries
	// into the PodCertificateRequest.
	userAnnotations map[string]string

	// clusterTrustBundleName, when set, adds a clusterTrustBundle projection
	// alongside the podCertificate one so the pod also mounts the signer's
	// published trust anchors at ca.crt.
	clusterTrustBundleName string
}

// withDefaults returns the fixture with every unset field filled in. The
// defaults reproduce the pod the string-built helper created, so switching to
// typed fixtures changes how the manifest is produced and nothing about what
// is deployed.
func (p certTestPod) withDefaults() certTestPod {
	if p.namespace == "" {
		p.namespace = workloadNamespace
	}
	if p.serviceAccountName == "" {
		p.serviceAccountName = "default"
	}
	if p.keyType == "" {
		p.keyType = "ED25519"
	}
	if p.credentialBundlePath == "" {
		p.credentialBundlePath = defaultCredentialBundlePath
	}
	return p
}

// build renders the fixture as a typed corev1.Pod.
func (p certTestPod) build() *corev1.Pod {
	p = p.withDefaults()

	sources := []corev1.VolumeProjection{{
		PodCertificate: &corev1.PodCertificateProjection{
			SignerName:           signerName,
			KeyType:              p.keyType,
			CredentialBundlePath: p.credentialBundlePath,
			MaxExpirationSeconds: p.maxExpirationSeconds,
			UserAnnotations:      p.userAnnotations,
		},
	}}
	if p.clusterTrustBundleName != "" {
		name := p.clusterTrustBundleName
		sources = append(sources, corev1.VolumeProjection{
			ClusterTrustBundle: &corev1.ClusterTrustBundleProjection{
				Name: &name,
				Path: "ca.crt",
			},
		})
	}

	return &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      p.name,
			Namespace: p.namespace,
		},
		Spec: corev1.PodSpec{
			RestartPolicy:      corev1.RestartPolicyNever,
			ServiceAccountName: p.serviceAccountName,
			Containers: []corev1.Container{{
				Name:    "sleeper",
				Image:   "busybox:1.37",
				Command: []string{"sleep", "600"},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: ptr(false),
					RunAsNonRoot:             ptr(true),
					RunAsUser:                ptr(int64(65532)),
					Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
					SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
				},
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "x509",
					MountPath: certTestPodMountPath,
					ReadOnly:  true,
				}},
			}},
			Volumes: []corev1.Volume{{
				Name: "x509",
				VolumeSource: corev1.VolumeSource{
					Projected: &corev1.ProjectedVolumeSource{Sources: sources},
				},
			}},
		},
	}
}

// ptr returns a pointer to v. The corev1 security context fields are all
// pointers and a fixture reads better with the literal inline.
func ptr[T any](v T) *T { return &v }

// applyCertTestPod creates a minimal workload pod whose podCertificate
// projected volume carries the given userAnnotations, registers its cleanup and
// returns a reference that pins the pod's UID.
//
// It is the thin, backwards-compatible spelling of createCertTestPod for the
// specs that only vary the annotations.
func applyCertTestPod(podName string, userAnnotations map[string]string) podRef {
	GinkgoHelper()
	return createCertTestPod(certTestPod{name: podName, userAnnotations: userAnnotations})
}

// createCertTestPod creates the fixture pod and registers its cleanup.
//
// It uses `kubectl create`, not `kubectl apply`, deliberately. `make test-e2e`
// reuses a surviving Kind cluster if one is already present, so a pod left over
// from a previous run can carry the same name. `apply` would return that pod's
// UID and every UID-keyed lookup afterwards would silently follow the stale
// object; `create` fails loudly on the conflict instead.
func createCertTestPod(fixture certTestPod) podRef {
	GinkgoHelper()

	pod := fixture.build()
	manifest, err := json.Marshal(pod)
	Expect(err).NotTo(HaveOccurred(), "Failed to marshal the pod fixture for %s", pod.Name)

	cmd := exec.Command("kubectl", "create", "-f", "-", "-o", "json")
	cmd.Stdin = bytes.NewReader(manifest)
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to create pod %s: %s", pod.Name, output)

	DeferCleanup(func() {
		cmd := exec.Command("kubectl", "delete", "pod", pod.Name,
			"-n", pod.Namespace, "--ignore-not-found=true", "--wait=false")
		_, _ = utils.Run(cmd)
	})

	return decodePodRef(output)
}

// decodePodRef reads the pod the apiserver returned and pins its identity:
// namespace, name and the UID the PodCertificateRequest will carry.
func decodePodRef(createdPodJSON string) podRef {
	GinkgoHelper()

	var created corev1.Pod
	Expect(json.Unmarshal([]byte(trimToJSON(createdPodJSON)), &created)).To(Succeed(),
		"Failed to decode the created pod: %s", createdPodJSON)
	Expect(created.UID).NotTo(BeEmpty(), "the created pod must carry a UID")

	return podRef{
		namespace: created.Namespace,
		name:      created.Name,
		uid:       created.UID,
	}
}

// applyWorkloadPod creates the example workload pod, whose podCertificate
// projected volume requests a certificate customized via ${...} interpolation
// (see examples/workload-pod.yaml), and returns a reference pinning its UID.
//
// This one stays a manifest read rather than a typed fixture on purpose: the
// spec's value is that the manifest shipped to users is the thing that issues.
func applyWorkloadPod() podRef {
	GinkgoHelper()

	cmd := exec.Command("kubectl", "create", "-f", "examples/workload-pod.yaml", "-o", "json")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to create the workload pod: %s", output)

	return decodePodRef(output)
}
