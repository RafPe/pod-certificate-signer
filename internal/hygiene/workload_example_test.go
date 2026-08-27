package hygiene

import (
	"os"
	"path/filepath"
	"testing"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

// exampleWorkloadPod is the flagship example manifest: operators copy it
// verbatim and the e2e suite applies it as-is.
const exampleWorkloadPod = "workload-pod.yaml"

// TestWorkloadPodExampleIssuesUnderIdentityConstraints guards the flagship
// example against the failure it shipped with until issue #87: it requested
// <sa>.<ns>.svc and a literal IP SAN, neither of which the signer grants, so
// the manifest could not issue unless the operator opened the
// --allow-unverified-identities escape hatch. Everything the live manifest
// requests must resolve to an identity the signer derives from the
// apiserver-verified request fields; a value that needs the escape hatch
// belongs in a commented block, not in the manifest.
//
// This is one half of the guarantee that the example issues on a default
// install. The other half is
// TestAnnotationInterpolationEnabledByDefault in cmd/podcertificate-signer,
// which proves ${...} interpolation is what the binary and the chart ship.
// This test fixes EnableInterpolation itself, so it cannot see a regression of
// that default, and that test says nothing about the example. Neither is
// meaningful alone - do not remove or simplify one without the other.
func TestWorkloadPodExampleIssuesUnderIdentityConstraints(t *testing.T) {
	path := filepath.Join("..", "..", "examples", exampleWorkloadPod)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) = %v, want the workload example to exist", path, err)
	}

	var pod *unstructured.Unstructured
	for _, doc := range decodeDocuments(t, path, data) {
		if doc.GetKind() == "Pod" {
			pod = doc
			break
		}
	}
	if pod == nil {
		t.Fatalf("%s contains no Pod document", path)
	}

	// The service account is read from the manifest rather than assumed. The
	// fallback mirrors both Kubernetes and the chart's DNS-SAN admission
	// policy, which substitutes the literal "default" when
	// spec.serviceAccountName is unset.
	serviceAccountName, _, err := unstructured.NestedString(pod.Object, "spec", "serviceAccountName")
	if err != nil {
		t.Fatalf("%s: spec.serviceAccountName not readable: %v", path, err)
	}
	if serviceAccountName == "" {
		serviceAccountName = "default"
	}

	requests := podCertificateRequests(t, path, pod)
	if len(requests) == 0 {
		t.Fatalf("%s: found no podCertificate projected volume source; the example was restructured "+
			"out from under this test", path)
	}

	for _, request := range requests {
		t.Run(request.signerName, func(t *testing.T) {
			pcr := &certificatesv1.PodCertificateRequest{
				ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: pod.GetNamespace()},
				Spec: certificatesv1.PodCertificateRequestSpec{
					SignerName:                request.signerName,
					PodName:                   pod.GetName(),
					PodUID:                    types.UID("11111111-2222-3333-4444-555555555555"),
					ServiceAccountName:        serviceAccountName,
					NodeName:                  types.NodeName("node-1"),
					UnverifiedUserAnnotations: request.userAnnotations,
				},
			}
			workload := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: pod.GetName(), Namespace: pod.GetNamespace()},
			}

			// AllowUnverifiedIdentities is deliberately left false: that is the
			// property under test. EnableInterpolation is on because the
			// example is written in ${...}; the chart shipping it on is what
			// the cmd-side test named above asserts.
			config, err := podcertificate.NewPodCertificateConfig(pcr, workload,
				podcertificate.Options{EnableInterpolation: true}, nil, 0)
			if err != nil {
				t.Fatalf("%s requests an identity the signer does not grant: %v\n"+
					"every live value must resolve to a verified pod identity; move anything needing "+
					"--allow-unverified-identities into a commented block", path, err)
			}
			if err := config.Validate(); err != nil {
				t.Fatalf("%s resolves to an invalid certificate configuration: %v", path, err)
			}
		})
	}
}

// certificateRequest is one podCertificate projected volume source of the
// example: the signer it names and the annotations it asks that signer for.
type certificateRequest struct {
	signerName      string
	userAnnotations map[string]string
}

// podCertificateRequests collects every podCertificate projected volume source
// declared by the pod.
func podCertificateRequests(t *testing.T, path string, pod *unstructured.Unstructured) []certificateRequest {
	t.Helper()

	volumes, found, err := unstructured.NestedSlice(pod.Object, "spec", "volumes")
	if err != nil || !found {
		t.Fatalf("%s: spec.volumes not readable (found=%t): %v", path, found, err)
	}

	var requests []certificateRequest
	for i, v := range volumes {
		volume, ok := v.(map[string]any)
		if !ok {
			t.Fatalf("%s: spec.volumes[%d] is %T, want a mapping", path, i, v)
		}
		sources, found, err := unstructured.NestedSlice(volume, "projected", "sources")
		if err != nil {
			t.Fatalf("%s: spec.volumes[%d].projected.sources not readable: %v", path, i, err)
		}
		if !found {
			continue
		}
		for j, s := range sources {
			source, ok := s.(map[string]any)
			if !ok {
				t.Fatalf("%s: spec.volumes[%d].projected.sources[%d] is %T, want a mapping", path, i, j, s)
			}
			certificate, found, err := unstructured.NestedMap(source, "podCertificate")
			if err != nil {
				t.Fatalf("%s: podCertificate source not readable: %v", path, err)
			}
			if !found {
				continue
			}
			signerName, _, err := unstructured.NestedString(certificate, "signerName")
			if err != nil {
				t.Fatalf("%s: podCertificate.signerName not readable: %v", path, err)
			}
			userAnnotations, _, err := unstructured.NestedStringMap(certificate, "userAnnotations")
			if err != nil {
				t.Fatalf("%s: podCertificate.userAnnotations not readable: %v", path, err)
			}
			requests = append(requests, certificateRequest{
				signerName:      signerName,
				userAnnotations: userAnnotations,
			})
		}
	}
	return requests
}
