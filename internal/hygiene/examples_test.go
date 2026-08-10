// Package hygiene holds tests that guard repository artifacts which are not
// compiled into the controller - manifests under examples/ that operators copy
// verbatim - against silent rot.
package hygiene

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const admissionregistrationV1 = "admissionregistration.k8s.io/v1"

// TestValidatingAdmissionPolicyExampleParses guards
// examples/validating-admission-policy.yaml. The example is meant to be applied
// as-is, and the failure modes are quiet ones: a policy whose binding names a
// different policy, or a validation with an empty expression, is admitted by
// the apiserver and then permits everything it was written to deny.
func TestValidatingAdmissionPolicyExampleParses(t *testing.T) {
	path := filepath.Join("..", "..", "examples", "validating-admission-policy.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) = %v, want the ValidatingAdmissionPolicy example to exist", path, err)
	}

	byKind := map[string]*unstructured.Unstructured{}
	for _, doc := range decodeDocuments(t, path, data) {
		byKind[doc.GetKind()] = doc
	}

	policy, ok := byKind["ValidatingAdmissionPolicy"]
	if !ok {
		t.Fatalf("%s contains kinds %v, want a ValidatingAdmissionPolicy document", path, kinds(byKind))
	}
	binding, ok := byKind["ValidatingAdmissionPolicyBinding"]
	if !ok {
		t.Fatalf("%s contains kinds %v, want a ValidatingAdmissionPolicyBinding document", path, kinds(byKind))
	}

	for _, doc := range []*unstructured.Unstructured{policy, binding} {
		if got := doc.GetAPIVersion(); got != admissionregistrationV1 {
			t.Errorf("%s: %s apiVersion = %q, want %q", path, doc.GetKind(), got, admissionregistrationV1)
		}
	}

	// A binding that names a policy which does not exist is accepted by the
	// apiserver and enforces nothing, so the example must wire itself up.
	policyName, found, err := unstructured.NestedString(binding.Object, "spec", "policyName")
	if err != nil || !found {
		t.Fatalf("%s: binding spec.policyName not readable (found=%t): %v", path, found, err)
	}
	if policyName != policy.GetName() {
		t.Errorf("%s: binding spec.policyName = %q, want %q (the policy's metadata.name)", path, policyName, policy.GetName())
	}

	validations, found, err := unstructured.NestedSlice(policy.Object, "spec", "validations")
	if err != nil || !found {
		t.Fatalf("%s: policy spec.validations not readable (found=%t): %v", path, found, err)
	}
	if len(validations) == 0 {
		t.Fatalf("%s: policy spec.validations is empty, want at least one CEL rule", path)
	}
	for i, v := range validations {
		validation, ok := v.(map[string]any)
		if !ok {
			t.Errorf("%s: policy spec.validations[%d] is %T, want a mapping", path, i, v)
			continue
		}
		if expr, _ := validation["expression"].(string); expr == "" {
			t.Errorf("%s: policy spec.validations[%d].expression is empty, want a CEL expression", path, i)
		}
	}
}

// decodeDocuments decodes a multi-document YAML stream, skipping empty
// documents such as the one produced by a leading `---` separator.
func decodeDocuments(t *testing.T, path string, data []byte) []*unstructured.Unstructured {
	t.Helper()

	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 4096)
	var docs []*unstructured.Unstructured
	for {
		object := map[string]any{}
		switch err := decoder.Decode(&object); {
		case errors.Is(err, io.EOF):
			return docs
		case err != nil:
			t.Fatalf("decoding %s: %v", path, err)
		}
		if len(object) == 0 {
			continue
		}
		docs = append(docs, &unstructured.Unstructured{Object: object})
	}
}

func kinds(byKind map[string]*unstructured.Unstructured) []string {
	found := make([]string, 0, len(byKind))
	for kind := range byKind {
		found = append(found, kind)
	}
	return found
}
