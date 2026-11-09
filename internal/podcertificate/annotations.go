package podcertificate

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"

	"github.com/go-logr/logr"
)

// AnnotationSuffix names one configuration item the signer understands. Keys
// are formed as <signer-name>-<suffix>, e.g. coolcert.example.com/mysigner-cn,
// and are read from the PodCertificateRequest spec.unverifiedUserAnnotations.
// The resolver takes the type rather than a string so only a declared item can
// be looked up.
type AnnotationSuffix string

// Well-known configuration annotation suffixes understood by the signer.
const (
	// AnnotationSuffixCN configures the certificate common name.
	AnnotationSuffixCN AnnotationSuffix = "cn"
	// AnnotationSuffixSAN configures the certificate DNS names (comma-separated).
	AnnotationSuffixSAN AnnotationSuffix = "san"
	// AnnotationSuffixIPSAN configures the certificate IP SANs (comma-separated).
	AnnotationSuffixIPSAN AnnotationSuffix = "ip-san"
	// AnnotationSuffixEKU configures the certificate extended key usage
	// (comma-separated tokens: "client", "server").
	AnnotationSuffixEKU AnnotationSuffix = "eku"
	// AnnotationSuffixDuration configures the certificate duration.
	AnnotationSuffixDuration AnnotationSuffix = "duration"
	// AnnotationSuffixRefreshBefore configures how long before expiry the
	// certificate should be refreshed.
	AnnotationSuffixRefreshBefore AnnotationSuffix = "refresh"
	// AnnotationSuffixURIs configures the certificate URI SANs (comma-separated).
	AnnotationSuffixURIs AnnotationSuffix = "uris"
)

// annotationSuffixes is every suffix the signer understands, and so the
// closed set of keys it accepts under its own prefix.
var annotationSuffixes = []AnnotationSuffix{
	AnnotationSuffixCN,
	AnnotationSuffixSAN,
	AnnotationSuffixIPSAN,
	AnnotationSuffixEKU,
	AnnotationSuffixDuration,
	AnnotationSuffixRefreshBefore,
	AnnotationSuffixURIs,
}

// annotationKey builds the full annotation key for a configuration suffix,
// e.g. coolcert.example.com/mysigner-cn.
func annotationKey(signerName string, suffix AnnotationSuffix) string {
	return signerName + "-" + string(suffix)
}

// podAnnotation returns the value of the given pod annotation. It reports
// false when the annotation is absent or empty.
//
// Deprecated: pod-annotation configuration is removed in 4.0.0; configure the
// signer through spec.unverifiedUserAnnotations. This is the only function the
// legacy path calls.
func podAnnotation(pod *corev1.Pod, key string) (string, bool) {
	value, ok := pod.Annotations[key]
	return value, ok
}

// validateAnnotationKeys rejects unverifiedUserAnnotations keys the signer
// does not recognize. Signers should deny such requests, see
// https://pkg.go.dev/k8s.io/api/certificates/v1#PodCertificateRequestSpec
//
// Pod annotations are deliberately not checked: they are shared with every
// other consumer of the pod, and a signer-name prefix cannot tell a typo from
// a key belonging to another signer whose name extends this one (example.com/pod
// versus example.com/pod-client).
func validateAnnotationKeys(annotations map[string]string, signerName string) error {
	known := make(map[string]struct{}, len(annotationSuffixes))
	for _, suffix := range annotationSuffixes {
		known[annotationKey(signerName, suffix)] = struct{}{}
	}

	for key := range annotations {
		if _, ok := known[key]; !ok {
			return fmt.Errorf("unrecognized user annotation key %q", key)
		}
	}

	return nil
}

// splitAndTrim splits a comma-separated value, trims whitespace and drops
// empty entries.
func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// annotationResolver resolves one request's certificate configuration from
// its annotations. It is built once per request and carries everything the
// per-field resolvers share: where to read values from, how to expand ${...}
// placeholders, and which identities the request is allowed to claim.
type annotationResolver struct {
	logger     logr.Logger
	pcr        *certificatesv1.PodCertificateRequest
	pod        *corev1.Pod
	csr        *CSR
	signerName string
	vars       map[string]string
	opts       Options
	// verified is the identity allowlist, or nil when identity constraints
	// are off.
	verified map[string]struct{}
}

// rawValue resolves a configuration value before interpolation: the request
// spec.unverifiedUserAnnotations first, then - while Options.AllowPodAnnotations
// is set - the pod's own annotations. A key that is present with an empty value
// is an error rather than a fallback, from either source: an explicitly empty
// value is a misconfiguration, and treating it as absent would silently route
// it onto the deprecated pod path or the default.
//
// The pod-annotation fallback is deprecated and removed in 4.0.0. Every value
// still taken from it is logged so remaining users can be found before then.
func (r *annotationResolver) rawValue(suffix AnnotationSuffix) (string, bool, error) {
	key := annotationKey(r.signerName, suffix)
	value, ok := r.pcr.Spec.UnverifiedUserAnnotations[key]
	if !ok && r.opts.AllowPodAnnotations {
		if value, ok = podAnnotation(r.pod, key); ok {
			r.logger.Info("certificate configuration read from a pod annotation, which is deprecated and will be removed in 4.0.0; "+
				"move it to spec.unverifiedUserAnnotations", "annotation", key)
		}
	}
	if !ok {
		return "", false, nil
	}
	if value == "" {
		return "", true, r.annotationError(suffix, errors.New("must not be empty"))
	}
	return value, true, nil
}

// value resolves a configuration value and expands ${...} placeholders in it
// from the apiserver-verified fields of the request.
func (r *annotationResolver) value(suffix AnnotationSuffix) (string, bool, error) {
	raw, ok, err := r.rawValue(suffix)
	if err != nil || !ok {
		return "", ok, err
	}
	expanded, err := interpolate(raw, r.vars, r.opts.EnableInterpolation)
	if err != nil {
		return "", true, r.annotationError(suffix, err)
	}
	return expanded, true, nil
}

// annotationError names the annotation an error came from.
func (r *annotationResolver) annotationError(suffix AnnotationSuffix, err error) error {
	return fmt.Errorf("annotation %q: %w", annotationKey(r.signerName, suffix), err)
}

// commonName resolves the cn annotation, falling back to def, and checks it
// against the verified identities.
func (r *annotationResolver) commonName(def string) (string, error) {
	cn, ok, err := r.value(AnnotationSuffixCN)
	if err != nil || !ok {
		return def, err
	}
	if err := validateVerifiedIdentities("common name", []string{cn}, r.verified); err != nil {
		return "", r.annotationError(AnnotationSuffixCN, err)
	}
	return cn, nil
}

// dnsNames applies the san-annotation > CSR-requested > default precedence for
// DNS SANs, validates the selected names, and, when identity constraints are
// enforced, verifies each name against the pod's identity.
func (r *annotationResolver) dnsNames(defaults []string) ([]string, error) {
	san, fromAnnotation, err := r.value(AnnotationSuffixSAN)
	if err != nil {
		return nil, err
	}

	// Select the source, then hold every source to the same two checks. Each
	// source labels its errors so a denial names what the requester must fix.
	var names []string
	var attribute func(error) error
	switch {
	case fromAnnotation:
		names = splitAndTrim(san)
		attribute = func(err error) error { return r.annotationError(AnnotationSuffixSAN, err) }
		if len(names) == 0 {
			return nil, attribute(errors.New("contains no DNS names"))
		}
	case r.opts.HonorCSRSANs && len(r.csr.DNSNames) > 0:
		// CSR-requested SANs are attacker-influenced just like annotation
		// values, so they clear the same verified-identity allowlist.
		names = r.csr.DNSNames
		attribute = func(err error) error { return fmt.Errorf("CSR DNS names: %w", err) }
	default:
		// The defaults are the signer's own verified forms, so they always
		// clear the allowlist; the syntax check still applies.
		names = defaults
		attribute = func(err error) error { return err }
	}

	if err := validateDNSNames(names); err != nil {
		return nil, attribute(err)
	}
	if err := validateVerifiedIdentities("DNS name", names, r.verified); err != nil {
		return nil, attribute(err)
	}
	return names, nil
}

// errUnverifiedIPSAN states the one IP SAN policy: an IP has no verified
// derivation from the request fields, so whichever source asks for one is
// denied unless unverified identities are allowed.
var errUnverifiedIPSAN = errors.New("IP SANs are not derived from a verified pod identity and are denied; start the controller with --allow-unverified-identities to allow them")

// ipAddresses applies the ip-san-annotation > CSR-requested > none precedence
// for IP SANs, under errUnverifiedIPSAN.
func (r *annotationResolver) ipAddresses() ([]net.IP, error) {
	ipSAN, ok, err := r.value(AnnotationSuffixIPSAN)
	if err != nil {
		return nil, err
	}
	if !ok {
		if r.opts.HonorCSRSANs && len(r.csr.IPAddresses) > 0 {
			if r.verified != nil {
				return nil, fmt.Errorf("CSR %w", errUnverifiedIPSAN)
			}
			return r.csr.IPAddresses, nil
		}
		return nil, nil
	}
	if r.verified != nil {
		return nil, r.annotationError(AnnotationSuffixIPSAN, errUnverifiedIPSAN)
	}
	ips, err := parseIPs(ipSAN)
	if err != nil {
		return nil, r.annotationError(AnnotationSuffixIPSAN, err)
	}
	return ips, nil
}

// extKeyUsage resolves the eku annotation, if present, into ExtKeyUsage
// values, falling back to current when the annotation is absent.
func (r *annotationResolver) extKeyUsage(current []x509.ExtKeyUsage) ([]x509.ExtKeyUsage, error) {
	eku, ok, err := r.value(AnnotationSuffixEKU)
	if err != nil || !ok {
		return current, err
	}
	usages, err := parseEKU(eku)
	if err != nil {
		return nil, r.annotationError(AnnotationSuffixEKU, err)
	}
	return usages, nil
}

// uris resolves the uris annotation, if present, and checks each URI against
// the verified identities.
func (r *annotationResolver) uris() ([]*url.URL, error) {
	value, ok, err := r.value(AnnotationSuffixURIs)
	if err != nil || !ok {
		return nil, err
	}
	parsed, err := parseURIs(value)
	if err != nil {
		return nil, r.annotationError(AnnotationSuffixURIs, err)
	}
	literals := make([]string, 0, len(parsed))
	for _, uri := range parsed {
		literals = append(literals, uri.String())
	}
	if err := validateVerifiedIdentities("URI", literals, r.verified); err != nil {
		return nil, r.annotationError(AnnotationSuffixURIs, err)
	}
	return parsed, nil
}

// duration resolves a duration-valued annotation (duration, refresh), falling
// back to def when it is absent.
func (r *annotationResolver) duration(suffix AnnotationSuffix, def time.Duration) (time.Duration, error) {
	value, ok, err := r.value(suffix)
	if err != nil || !ok {
		return def, err
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, r.annotationError(suffix, fmt.Errorf("invalid duration %q: %w", value, err))
	}
	return d, nil
}

// parseEKU parses a comma-separated list of extended key usage tokens.
// Recognized tokens: "client" (TLS client auth), "server" (TLS server auth).
// Duplicates collapse; order of first occurrence is preserved.
func parseEKU(value string) ([]x509.ExtKeyUsage, error) {
	tokens := splitAndTrim(value)
	if len(tokens) == 0 {
		return nil, errors.New("contains no extended key usage tokens")
	}

	seen := make(map[string]struct{}, len(tokens))
	usages := make([]x509.ExtKeyUsage, 0, len(tokens))
	for _, token := range tokens {
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		switch token {
		case "client":
			usages = append(usages, x509.ExtKeyUsageClientAuth)
		case "server":
			usages = append(usages, x509.ExtKeyUsageServerAuth)
		default:
			return nil, fmt.Errorf("unknown extended key usage %q (valid: client, server)", token)
		}
	}

	return usages, nil
}

// parseIPs parses a comma-separated list of IP addresses.
func parseIPs(value string) ([]net.IP, error) {
	ipStrings := splitAndTrim(value)
	if len(ipStrings) == 0 {
		return nil, errors.New("contains no IP addresses")
	}

	ips := make([]net.IP, 0, len(ipStrings))
	for _, ipStr := range ipStrings {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", ipStr)
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// parseURIs parses a comma-separated list of absolute URIs.
func parseURIs(value string) ([]*url.URL, error) {
	uriStrings := splitAndTrim(value)
	if len(uriStrings) == 0 {
		return nil, errors.New("contains no URIs")
	}

	uris := make([]*url.URL, 0, len(uriStrings))
	for _, uriStr := range uriStrings {
		uri, err := url.Parse(uriStr)
		if err != nil {
			return nil, fmt.Errorf("invalid URI %q: %w", uriStr, err)
		}
		if uri.Scheme == "" {
			return nil, fmt.Errorf("invalid URI %q: missing scheme", uriStr)
		}
		uris = append(uris, uri)
	}

	return uris, nil
}
