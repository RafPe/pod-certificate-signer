package podcertificate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

// interpolationPattern matches a ${...} placeholder.
var interpolationPattern = regexp.MustCompile(`\$\{([^}]*)\}`)

// interpolationVars returns the placeholder variables available to ${...}
// interpolation. All values come from fields of the PodCertificateRequest
// spec that kubelet populates and the kube-apiserver verifies (or from the
// controller's own configuration), never from user-controlled input - so a
// requester can only interpolate its own verified identity.
func interpolationVars(pcr *certificatesv1.PodCertificateRequest, clusterFQDN string) map[string]string {
	return map[string]string{
		"pod.name":               pcr.Spec.PodName,
		"pod.namespace":          pcr.Namespace,
		"pod.uid":                string(pcr.Spec.PodUID),
		"pod.serviceAccountName": pcr.Spec.ServiceAccountName,
		"node.name":              string(pcr.Spec.NodeName),
		"cluster.fqdn":           clusterFQDN,
	}
}

// interpolate expands ${var} placeholders in value using vars. When the
// feature is disabled, any value containing a placeholder is rejected: the
// alternative - issuing a certificate with a literal "${pod.name}" subject -
// would silently hide the misconfiguration.
func interpolate(value string, vars map[string]string, enabled bool) (string, error) {
	if !strings.Contains(value, "${") {
		return value, nil
	}
	if !enabled {
		return "", errors.New("value uses ${...} interpolation, which is disabled on this signer (start the controller with --enable-annotation-interpolation)")
	}

	var unknown []string
	result := interpolationPattern.ReplaceAllStringFunc(value, func(match string) string {
		name := strings.TrimSpace(match[2 : len(match)-1])
		if replacement, ok := vars[name]; ok {
			return replacement
		}
		unknown = append(unknown, name)
		return match
	})
	if len(unknown) > 0 {
		return "", fmt.Errorf("unknown interpolation variable(s) %q", unknown)
	}
	// Anything left over is an unterminated placeholder such as "${pod.name":
	// none of the variable values can contain "${" (they are Kubernetes
	// object names and UIDs).
	if strings.Contains(result, "${") {
		return "", fmt.Errorf("unterminated ${...} placeholder in %q", value)
	}

	return result, nil
}

// defaultCommonName returns the default certificate common name for a pod.
// RFC 5280 caps the common name at 64 characters; for longer pod names it
// returns an empty common name, leaving the certificate to be identified by
// its subject alternative names (which carry the verifiable identity anyway).
func defaultCommonName(podName string) string {
	if len(podName) > 64 {
		return ""
	}
	return podName
}

// dnsLabelMaxLen is the maximum length of a single DNS label (RFC 1035 §2.3.4).
const dnsLabelMaxLen = 63

// defaultPodDNSNames returns the canonical pod DNS SANs
// <pod>.<ns>.pod|svc.<fqdn>. The pod name forms the leading DNS label(s), which
// RFC 1035 caps at 63 characters each. When a label would exceed that limit the
// SANs are omitted entirely (skipped=true) rather than truncated: truncation
// would give two pods whose names share their first 63 characters identical
// pod/svc SANs, letting one impersonate the other. The pod stays identifiable by
// its common name (see defaultCommonName) or an explicit san annotation; callers
// surface skipped so the operator can act.
func defaultPodDNSNames(podName, namespace, clusterFQDN string) (names []string, skipped bool) {
	for _, label := range strings.Split(podName, ".") {
		if len(label) > dnsLabelMaxLen {
			return nil, true
		}
	}
	return []string{
		fmt.Sprintf("%s.%s.pod.%s", podName, namespace, clusterFQDN),
		fmt.Sprintf("%s.%s.svc.%s", podName, namespace, clusterFQDN),
	}, false
}

// verifiedIdentities returns the set of identity strings (common names, DNS
// names and URIs) the signer is willing to emit for a request, computed solely
// from its apiserver-verified fields. Resolved annotation values are accepted
// only if they are members of this set, so a pod can never obtain a certificate
// for an identity it does not own. The check is exact string equality on the
// resolved value, which closes literal-injection loopholes such as
// "${pod.name}.attacker.com".
func verifiedIdentities(pcr *certificatesv1.PodCertificateRequest, clusterFQDN string) map[string]struct{} {
	ns := pcr.Namespace
	pod := pcr.Spec.PodName
	sa := pcr.Spec.ServiceAccountName

	allowed := make(map[string]struct{})
	add := func(values ...string) {
		for _, v := range values {
			if v != "" {
				allowed[v] = struct{}{}
			}
		}
	}

	// The pod's own identities: its bare name, the canonical Kubernetes DNS
	// forms (these are exactly what the signer emits by default), and its
	// SPIFFE ID.
	if pod != "" {
		add(
			pod,
			pod+"."+ns,
			pod+"."+ns+".pod",
			pod+"."+ns+".svc",
			pod+"."+ns+".pod."+clusterFQDN,
			pod+"."+ns+".svc."+clusterFQDN,
			"spiffe://"+clusterFQDN+"/ns/"+ns+"/pod/"+pod,
		)
	}

	// The workload's service-account identity - the pod runs as this service
	// account, so it may identify by it (short DNS form and SPIFFE ID).
	//
	// Deliberately excluded:
	//   - node.name (belongs to the kubelet, not the workload) and pod.uid (an
	//     opaque, non-identifying token). Both remain available for ${...}
	//     interpolation but are not claimable as a subject.
	//   - the service-account Service/pod DNS forms <sa>.<ns>.svc[.<fqdn>] and
	//     <sa>.<ns>.pod[.<fqdn>]. <name>.<ns>.svc.<fqdn> is the Kubernetes
	//     *Service* record shape, and ServiceAccount and Service names are
	//     independent within a namespace - granting the form would let a pod
	//     running as ServiceAccount "kubernetes" in "default" present a valid
	//     certificate for kubernetes.default.svc, the canonical example of what
	//     this constraint exists to deny. The names also resolve to nothing in
	//     Kubernetes DNS, so they buy no interoperability. The signer emits no
	//     service-account-derived DNS name of its own; per-pod service-account
	//     identity is carried by the SPIFFE ID below. See
	//     docs/adr/0001-verified-identity-allowlist-boundary.md.
	if sa != "" {
		add(
			sa+"."+ns,
			"spiffe://"+clusterFQDN+"/ns/"+ns+"/sa/"+sa,
		)
	}

	return allowed
}

// assertVerifiedIdentities reports an error when any of values is not in the
// allowed set. A nil set means the identity constraint is off (see
// Options.AllowUnverifiedIdentities), and every value passes.
func assertVerifiedIdentities(kind string, values []string, allowed map[string]struct{}) error {
	if allowed == nil {
		return nil
	}
	for _, value := range values {
		if _, ok := allowed[value]; !ok {
			return fmt.Errorf("%s %q is not derived from a verified pod identity; build it from ${...} interpolation of verified fields, or start the controller with --allow-unverified-identities", kind, value)
		}
	}
	return nil
}

// validateDNSNames verifies that every resolved certificate DNS SAN is a valid
// DNS-1123 subdomain. This syntax check is independent of identity ownership:
// AllowUnverifiedIdentities may relax who owns a name, but it never permits a
// malformed name. Wildcards are deliberately unsupported because the signer
// authorizes identities by exact match.
func validateDNSNames(names []string) error {
	for _, name := range names {
		if problems := validation.IsDNS1123Subdomain(name); len(problems) > 0 {
			return fmt.Errorf("DNS name %q is invalid: %s", name, strings.Join(problems, "; "))
		}
		for _, label := range strings.Split(name, ".") {
			if problems := validation.IsDNS1123Label(label); len(problems) > 0 {
				return fmt.Errorf("DNS name %q is invalid: label %q: %s", name, label, strings.Join(problems, "; "))
			}
		}
	}
	return nil
}

// ValidateClusterFQDN validates the operator-configured DNS suffix used for
// generated and interpolated certificate identities.
func ValidateClusterFQDN(clusterFQDN string) error {
	return validateDNSNames([]string{clusterFQDN})
}
