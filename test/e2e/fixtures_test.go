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
	"strconv"

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
// about.
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

	// podAnnotations are annotations on the pod object itself. The signer reads
	// configuration from the request's unverifiedUserAnnotations first and falls
	// back to these (a deprecated path, see NewPodCertificateConfig).
	//
	// One spec needs that fallback rather than the projection: the DNS SAN
	// ValidatingAdmissionPolicy inspects only the projection's userAnnotations,
	// so a malformed SAN requested there never reaches the signer to be judged
	// by it. See defineEscapeHatchInvariantTests.
	podAnnotations map[string]string

	// clusterTrustBundleName, when set, adds a clusterTrustBundle projection
	// alongside the podCertificate one so the pod also mounts the signer's
	// published trust anchors at ca.crt.
	clusterTrustBundleName string

	// image and args replace the default sleeper container. The
	// credential-conformance specs point them at the in-cluster probe
	// (test/credprobe), which is the only workload in the suite that does
	// anything with the credential it is given; every other spec only needs a
	// container that stays up long enough for kubelet to project one.
	image string
	args  []string

	// holdSeconds is how long the sleeper container stays up. Defaults to
	// defaultHoldSeconds, which is ample for a spec that only needs a pod to
	// exist while its request is issued.
	//
	// The CA-lifecycle specs need more: their observer pod is created before a
	// CA rotation and read after it, and a rotation costs a kubelet secret
	// propagation plus a controller reload. Ignored when image is not the
	// sleeper, since only the sleeper's command is the suite's to choose.
	holdSeconds int
}

// defaultHoldSeconds is how long the sleeper container stays up when a fixture
// does not ask for longer.
const defaultHoldSeconds = 600

// sleeperImage is the workload container for the specs that only need a pod to
// exist. It is not the probe: a spec that asserts on the mounted credential
// must set image explicitly, so "the pod is up" can never be mistaken for
// "the credential works".
const sleeperImage = "busybox:1.37"

// e2eWorkloadLabel marks the pods this suite creates, so the failure dump can
// collect their logs without knowing which spec made them.
const e2eWorkloadLabel = "e2e.pod-certificate-signer/workload"

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
	if p.image == "" {
		p.image = sleeperImage
		p.args = nil
	}
	if p.holdSeconds == 0 {
		p.holdSeconds = defaultHoldSeconds
	}
	return p
}

// container renders the workload container. The sleeper keeps the command it
// has always had; anything else runs its image's entrypoint with the fixture's
// arguments, which is how the credential probe is configured.
func (p certTestPod) container() corev1.Container {
	container := corev1.Container{
		Name:  "workload",
		Image: p.image,
		Args:  p.args,
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
	}
	if p.image == sleeperImage {
		container.Command = []string{"sleep", strconv.Itoa(p.holdSeconds)}
	}
	return container
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
			Name:        p.name,
			Namespace:   p.namespace,
			Labels:      map[string]string{e2eWorkloadLabel: "true"},
			Annotations: p.podAnnotations,
		},
		Spec: corev1.PodSpec{
			RestartPolicy:      corev1.RestartPolicyNever,
			ServiceAccountName: p.serviceAccountName,
			Containers:         []corev1.Container{p.container()},
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

// dryRunCertTestPod submits the fixture to the apiserver with
// --dry-run=server and returns kubectl's combined output.
//
// Nothing is created: the request is validated, admitted and discarded. That is
// how a spec asserts on what kube-apiserver itself accepts - which projection
// key types exist, for instance - without paying for a pod, a
// PodCertificateRequest and an issuance. It returns the error rather than
// asserting on it because the interesting cases are the ones the apiserver
// refuses.
func dryRunCertTestPod(fixture certTestPod) (string, error) {
	pod := fixture.build()
	manifest, err := json.Marshal(pod)
	if err != nil {
		return "", err
	}

	cmd := exec.Command("kubectl", "create", "--dry-run=server", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	return utils.Run(cmd)
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
