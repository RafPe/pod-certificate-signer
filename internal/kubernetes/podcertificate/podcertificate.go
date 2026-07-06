package podcertificate

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/api"
)

// PodCertificate is a certificate issued for a pod, together with the
// configuration it was issued from and its validity bounds.
type PodCertificate struct {
	certificate      []byte
	certificateChain string
	config           *PodCertificateConfig
	notBefore        time.Time
	notAfter         time.Time
}

// PodCertificateConfig describes the certificate to be issued for a pod.
type PodCertificateConfig struct {
	CommonName    string
	DNSNames      []string
	IPAddresses   []net.IP
	URIs          []*url.URL
	Duration      time.Duration
	RefreshBefore time.Duration
	// MaxExpiration is the maximum certificate lifetime permitted by the
	// PodCertificateRequest spec.maxExpirationSeconds. Zero means no limit.
	MaxExpiration      time.Duration
	KeyUsage           x509.KeyUsage      // TODO: Customizable Key Usage via Policies
	ExtKeyUsage        []x509.ExtKeyUsage // TODO: Customizable Ext Key Usage via Policies or other aliases i.e. client-server-auth , ssl ,
	PublicKey          crypto.PublicKey
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
}

// Well-known configuration annotation suffixes understood by the signer.
//
// Keys are formed as <signer-name>-<suffix>, e.g. coolcert.example.com/mysigner-cn.
// They are read from the PodCertificateRequest spec.unverifiedUserAnnotations
// first, and fall back to the annotations of the associated pod.
//
// Deprecated: configuration via pod annotations will be removed in a future
// release in favour of spec.unverifiedUserAnnotations, which is the standard
// mechanism for passing additional context to a signer.
const (
	// AnnotationSuffixCN configures the certificate common name.
	AnnotationSuffixCN = "cn"
	// AnnotationSuffixSAN configures the certificate DNS names (comma-separated).
	AnnotationSuffixSAN = "san"
	// AnnotationSuffixIPSAN configures the certificate IP SANs (comma-separated).
	AnnotationSuffixIPSAN = "ip-san"
	// AnnotationSuffixEKU configures the certificate extended key usage
	// (comma-separated tokens: "client", "server").
	AnnotationSuffixEKU = "eku"
	// AnnotationSuffixDuration configures the certificate duration.
	AnnotationSuffixDuration = "duration"
	// AnnotationSuffixRefreshBefore configures how long before expiry the
	// certificate should be refreshed.
	AnnotationSuffixRefreshBefore = "refresh"
	// AnnotationSuffixURIs configures the certificate URI SANs (comma-separated).
	AnnotationSuffixURIs = "uris"
)

// Defaults applied when the corresponding annotation is not present.
const (
	// DefaultDuration is the default certificate duration.
	DefaultDuration = 24 * time.Hour
	// DefaultRefreshBefore is the default period before expiry at which the
	// certificate should be refreshed. Certificates have a minimum duration
	// of 1 hour, so 15 minutes is always a safe hint for the kubelet.
	DefaultRefreshBefore = 15 * time.Minute
	// DefaultClusterFQDN is used for the default DNS names when no cluster
	// FQDN is provided.
	DefaultClusterFQDN = "cluster.local"
)

// Constraints enforced by kube-apiserver on PodCertificateRequest status
// updates. Certificates violating them are rejected by the API server, so
// they are validated up front and reported to the user as a denial instead.
//
// https://github.com/kubernetes/kubernetes/blob/release-1.36/pkg/apis/certificates/validation/validation.go
const (
	// MinDuration is the minimum certificate lifetime accepted by
	// kube-apiserver.
	MinDuration = time.Hour
	// RefreshMargin bounds status.beginRefreshAt: kube-apiserver requires it
	// to lie within [notBefore+RefreshMargin, notAfter-RefreshMargin].
	RefreshMargin = 10 * time.Minute
)

// NewPodCertificate creates a new [PodCertificate].
func NewPodCertificate(certificate []byte, certificateChain string, config *PodCertificateConfig, notBefore, notAfter time.Time) *PodCertificate {
	return &PodCertificate{
		certificate:      certificate,
		certificateChain: certificateChain,
		config:           config,
		notBefore:        notBefore,
		notAfter:         notAfter,
	}
}

// Certificate returns the issued certificate in DER format.
func (pc *PodCertificate) Certificate() []byte {
	return pc.certificate
}

// CertificateChain returns the PEM-encoded certificate chain.
func (pc *PodCertificate) CertificateChain() string {
	return pc.certificateChain
}

// Config returns the configuration the certificate was issued from.
func (pc *PodCertificate) Config() *PodCertificateConfig {
	return pc.config
}

// NotBefore returns the start of the certificate validity period.
func (pc *PodCertificate) NotBefore() time.Time {
	return pc.notBefore
}

// NotAfter returns the end of the certificate validity period.
func (pc *PodCertificate) NotAfter() time.Time {
	return pc.notAfter
}

// IsValid reports whether the certificate is currently within its validity
// period.
func (pc *PodCertificate) IsValid() bool {
	now := time.Now()
	return now.After(pc.notBefore) && now.Before(pc.notAfter)
}

// ExpiresIn returns the duration until the certificate expires.
func (pc *PodCertificate) ExpiresIn() time.Duration {
	return time.Until(pc.notAfter)
}

// Options configure how the certificate configuration is built from a
// PodCertificateRequest.
type Options struct {
	// ClusterFQDN is used in the default DNS names. Empty means
	// [DefaultClusterFQDN].
	ClusterFQDN string
	// EnableInterpolation allows ${...} placeholders in the cn, san and
	// uris configuration values, resolved from the apiserver-verified
	// fields of the PodCertificateRequest (see [interpolationVars]).
	// When disabled, values containing ${ are rejected rather than
	// issued verbatim.
	EnableInterpolation bool
	// HonorCSRSANs uses the DNS and IP SANs embedded in the
	// kubelet-generated PKCS#10 CSR (CSRDNSNames/CSRIPAddresses) when no
	// san/ip-san annotation overrides them. Kubelet generates empty CSRs today,
	// so this is inert until Kubernetes starts embedding requested SANs;
	// when disabled, CSR SANs are ignored, which the API contract
	// explicitly allows for signers.
	HonorCSRSANs bool
	// CSRDNSNames are the DNS SANs requested via the PKCS#10 CSR.
	CSRDNSNames []string
	// CSRIPAddresses are the IP SANs requested via the PKCS#10 CSR.
	CSRIPAddresses []net.IP
}

// NewPodCertificateConfig builds the certificate configuration for the given
// PodCertificateRequest and its associated pod.
//
// Configuration values are read from the request spec.unverifiedUserAnnotations
// first, falling back to the pod's annotations (deprecated). Keys follow the
// <signer-name>-<suffix> convention, e.g. coolcert.example.com/mysigner-cn.
//
// Malformed values and unrecognized signer-prefixed keys in
// spec.unverifiedUserAnnotations result in an error, since signers should deny
// requests they do not fully understand rather than silently fall back to
// defaults.
func NewPodCertificateConfig(
	pcr *capiv1beta1.PodCertificateRequest,
	pod *corev1.Pod,
	opts Options,
	publicKey crypto.PublicKey,
	publicKeyAlgorithm x509.PublicKeyAlgorithm,
) (*PodCertificateConfig, error) {
	signerName := pcr.Spec.SignerName
	clusterFQDN := opts.ClusterFQDN
	if clusterFQDN == "" {
		clusterFQDN = DefaultClusterFQDN
	}

	if err := checkUnrecognizedUserAnnotations(pcr.Spec.UnverifiedUserAnnotations, signerName); err != nil {
		return nil, err
	}

	// lookup resolves a configuration value, preferring the request
	// spec.unverifiedUserAnnotations over the deprecated pod annotations.
	lookup := func(suffix string) (string, bool) {
		key := annotationKey(signerName, suffix)
		if value, ok := pcr.Spec.UnverifiedUserAnnotations[key]; ok && value != "" {
			return value, true
		}
		return api.GetPodAnnotation(pod, key)
	}

	// expand resolves ${...} placeholders in a configuration value from the
	// apiserver-verified fields of the request.
	vars := interpolationVars(pcr, clusterFQDN)
	expand := func(suffix, value string) (string, error) {
		expanded, err := interpolate(value, vars, opts.EnableInterpolation)
		if err != nil {
			return "", fmt.Errorf("annotation %q: %w", annotationKey(signerName, suffix), err)
		}
		return expanded, nil
	}

	// The pod author bounds the certificate lifetime via the projected
	// volume's maxExpirationSeconds, which kubelet copies onto the request.
	// kube-apiserver defaults it to 24h and rejects issued certificates
	// which outlive it, so the default duration is clamped to fit.
	maxExpiration := time.Duration(0)
	if pcr.Spec.MaxExpirationSeconds != nil {
		maxExpiration = time.Duration(*pcr.Spec.MaxExpirationSeconds) * time.Second
	}
	duration := DefaultDuration
	if maxExpiration > 0 && duration > maxExpiration {
		duration = maxExpiration
	}

	config := &PodCertificateConfig{
		CommonName: pod.Name,
		DNSNames: []string{
			fmt.Sprintf("%s.%s.pod.%s", pod.Name, pod.Namespace, clusterFQDN),
			fmt.Sprintf("%s.%s.svc.%s", pod.Name, pod.Namespace, clusterFQDN),
		},
		Duration:           duration,
		RefreshBefore:      DefaultRefreshBefore,
		MaxExpiration:      maxExpiration,
		KeyUsage:           keyUsageFor(publicKeyAlgorithm),
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		PublicKey:          publicKey,
		PublicKeyAlgorithm: publicKeyAlgorithm,
	}

	if cn, ok := lookup(AnnotationSuffixCN); ok {
		cn, err := expand(AnnotationSuffixCN, cn)
		if err != nil {
			return nil, err
		}
		config.CommonName = cn
	}

	// DNS SAN precedence: san annotation > CSR-requested SANs > defaults.
	switch san, ok := lookup(AnnotationSuffixSAN); {
	case ok:
		san, err := expand(AnnotationSuffixSAN, san)
		if err != nil {
			return nil, err
		}
		names := splitAndTrim(san)
		if len(names) == 0 {
			return nil, fmt.Errorf("annotation %q contains no DNS names", annotationKey(signerName, AnnotationSuffixSAN))
		}
		config.DNSNames = names
	case opts.HonorCSRSANs && len(opts.CSRDNSNames) > 0:
		config.DNSNames = opts.CSRDNSNames
	}

	// IP SAN precedence: ip-san annotation > CSR-requested SANs > none.
	switch ipSAN, ok := lookup(AnnotationSuffixIPSAN); {
	case ok:
		ipSAN, err := expand(AnnotationSuffixIPSAN, ipSAN)
		if err != nil {
			return nil, err
		}
		ips, err := parseIPs(ipSAN)
		if err != nil {
			return nil, fmt.Errorf("annotation %q: %w", annotationKey(signerName, AnnotationSuffixIPSAN), err)
		}
		config.IPAddresses = ips
	case opts.HonorCSRSANs && len(opts.CSRIPAddresses) > 0:
		config.IPAddresses = opts.CSRIPAddresses
	}

	extKeyUsage, err := resolveExtKeyUsage(lookup, expand, config.ExtKeyUsage, signerName)
	if err != nil {
		return nil, err
	}
	config.ExtKeyUsage = extKeyUsage

	if uris, ok := lookup(AnnotationSuffixURIs); ok {
		uris, err := expand(AnnotationSuffixURIs, uris)
		if err != nil {
			return nil, err
		}
		parsed, err := parseURIs(uris)
		if err != nil {
			return nil, fmt.Errorf("annotation %q: %w", annotationKey(signerName, AnnotationSuffixURIs), err)
		}
		config.URIs = parsed
	}

	if durationStr, ok := lookup(AnnotationSuffixDuration); ok {
		duration, err := time.ParseDuration(durationStr)
		if err != nil {
			return nil, fmt.Errorf("annotation %q: invalid duration %q: %w", annotationKey(signerName, AnnotationSuffixDuration), durationStr, err)
		}
		config.Duration = duration
	}

	if refreshStr, ok := lookup(AnnotationSuffixRefreshBefore); ok {
		refresh, err := time.ParseDuration(refreshStr)
		if err != nil {
			return nil, fmt.Errorf("annotation %q: invalid duration %q: %w", annotationKey(signerName, AnnotationSuffixRefreshBefore), refreshStr, err)
		}
		config.RefreshBefore = refresh
	}

	return config, nil
}

// Validate checks that the configuration can be used to issue a certificate
// which kube-apiserver will accept on the status subresource. Validating up
// front turns misconfigurations into an immediate denial instead of an
// endless requeue loop caused by rejected status updates.
func (pcc *PodCertificateConfig) Validate() error {
	if pcc.CommonName == "" {
		return errors.New("common name is required")
	}
	// RFC 5280 ub-common-name; easily exceeded by interpolated pod names.
	if len(pcc.CommonName) > 64 {
		return fmt.Errorf("common name %q exceeds the 64 character limit", pcc.CommonName)
	}
	if pcc.Duration < MinDuration {
		return fmt.Errorf("duration (%s) must be at least %s", pcc.Duration, MinDuration)
	}
	if pcc.MaxExpiration > 0 && pcc.Duration > pcc.MaxExpiration {
		return fmt.Errorf("duration (%s) exceeds the maxExpirationSeconds of the request (%s)", pcc.Duration, pcc.MaxExpiration)
	}
	if pcc.RefreshBefore < RefreshMargin {
		return fmt.Errorf("refresh before (%s) must be at least %s", pcc.RefreshBefore, RefreshMargin)
	}
	if pcc.RefreshBefore > pcc.Duration-RefreshMargin {
		return fmt.Errorf("refresh before (%s) must not exceed the certificate duration (%s) minus %s", pcc.RefreshBefore, pcc.Duration, RefreshMargin)
	}

	return nil
}

// LogConfiguration logs the resolved certificate configuration.
func (pcc *PodCertificateConfig) LogConfiguration(ctx context.Context) {
	lgr := log.FromContext(ctx)

	lgr.Info("Successfully created PodCertificateConfig",
		"commonName", pcc.CommonName,
		"dnsNames", pcc.DNSNames,
		"uris", pcc.URIs,
		"extKeyUsage", pcc.ExtKeyUsage,
		"duration", pcc.Duration.String(),
		"refreshBefore", pcc.RefreshBefore.String())
}

// annotationKey builds the full annotation key for a configuration suffix,
// e.g. coolcert.example.com/mysigner-cn.
func annotationKey(signerName, suffix string) string {
	return signerName + "-" + suffix
}

// interpolationPattern matches a ${...} placeholder.
var interpolationPattern = regexp.MustCompile(`\$\{([^}]*)\}`)

// interpolationVars returns the placeholder variables available to ${...}
// interpolation. All values come from fields of the PodCertificateRequest
// spec that kubelet populates and the kube-apiserver verifies (or from the
// controller's own configuration), never from user-controlled input - so a
// requester can only interpolate its own verified identity.
func interpolationVars(pcr *capiv1beta1.PodCertificateRequest, clusterFQDN string) map[string]string {
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

// checkUnrecognizedUserAnnotations rejects unverifiedUserAnnotations keys the
// signer does not recognize. Signers should deny such requests, see
// https://pkg.go.dev/k8s.io/api/certificates/v1beta1#PodCertificateRequestSpec
func checkUnrecognizedUserAnnotations(annotations map[string]string, signerName string) error {
	known := map[string]struct{}{
		annotationKey(signerName, AnnotationSuffixCN):            {},
		annotationKey(signerName, AnnotationSuffixSAN):           {},
		annotationKey(signerName, AnnotationSuffixIPSAN):         {},
		annotationKey(signerName, AnnotationSuffixDuration):      {},
		annotationKey(signerName, AnnotationSuffixRefreshBefore): {},
		annotationKey(signerName, AnnotationSuffixURIs):          {},
		annotationKey(signerName, AnnotationSuffixEKU):           {},
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

// keyUsageFor returns the KeyUsage bits appropriate for the subject key type.
// keyEncipherment only has meaning for RSA key transport; for ECDSA and
// Ed25519 keys digitalSignature is the only applicable usage.
func keyUsageFor(alg x509.PublicKeyAlgorithm) x509.KeyUsage {
	if alg == x509.RSA {
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	return x509.KeyUsageDigitalSignature
}

// resolveExtKeyUsage resolves the eku annotation, if present, into ExtKeyUsage
// values, falling back to current when the annotation is absent.
func resolveExtKeyUsage(lookup func(string) (string, bool), expand func(string, string) (string, error), current []x509.ExtKeyUsage, signerName string) ([]x509.ExtKeyUsage, error) {
	eku, ok := lookup(AnnotationSuffixEKU)
	if !ok {
		return current, nil
	}
	eku, err := expand(AnnotationSuffixEKU, eku)
	if err != nil {
		return nil, err
	}
	usages, err := parseEKU(eku)
	if err != nil {
		return nil, fmt.Errorf("annotation %q: %w", annotationKey(signerName, AnnotationSuffixEKU), err)
	}
	return usages, nil
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
