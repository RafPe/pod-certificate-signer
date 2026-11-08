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

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/go-logr/logr"
)

// PodCertificate is a certificate issued for a pod, together with the
// configuration it was issued from and its validity bounds.
type PodCertificate struct {
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
	// Warnings are non-fatal notices about how the configuration was resolved
	// (e.g. default pod DNS SANs omitted for an over-long pod name). The
	// certificate still issues; the reconciler surfaces each as a Warning event
	// and a log line so the operator can see why a default was dropped.
	Warnings []string
}

// CSR holds the values extracted from a kubelet-generated PKCS#10 certificate
// request: the subject public key, and any requested subject alternative
// names.
//
// Today kubelet generates completely empty CSRs, so the SAN slices are always
// empty - the KEP plans for pod authors to request DNS and IP SANs which
// kubelet will embed in the CSR, and carrying them now keeps the signer ready
// for that.
type CSR struct {
	PublicKey          crypto.PublicKey
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	DNSNames           []string
	IPAddresses        []net.IP
}

// Well-known configuration annotation suffixes understood by the signer.
//
// Keys are formed as <signer-name>-<suffix>, e.g. coolcert.example.com/mysigner-cn,
// and are read from the PodCertificateRequest spec.unverifiedUserAnnotations.
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

// annotationSuffixes is every suffix the signer understands, and so the
// closed set of keys it accepts under its own prefix.
var annotationSuffixes = []string{
	AnnotationSuffixCN,
	AnnotationSuffixSAN,
	AnnotationSuffixIPSAN,
	AnnotationSuffixEKU,
	AnnotationSuffixDuration,
	AnnotationSuffixRefreshBefore,
	AnnotationSuffixURIs,
}

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
func NewPodCertificate(certificateChain string, config *PodCertificateConfig, notBefore, notAfter time.Time) *PodCertificate {
	return &PodCertificate{
		certificateChain: certificateChain,
		config:           config,
		notBefore:        notBefore,
		notAfter:         notAfter,
	}
}

// CertificateChain returns the PEM-encoded certificate chain: the issued
// certificate followed by the CA certificate that signed it.
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

// Options is the process-wide policy the certificate configuration is built
// under. It is set once from the command line and is the same for every
// request; the per-request input is the PodCertificateRequest, its pod and
// its [CSR].
type Options struct {
	// ClusterFQDN is used in the default DNS names. Empty means
	// [DefaultClusterFQDN].
	ClusterFQDN string
	// EnableInterpolation allows ${...} placeholders in every configuration
	// value, resolved from the apiserver-verified fields of the
	// PodCertificateRequest (see [interpolationVars]). When disabled, values
	// containing ${ are rejected rather than issued verbatim.
	EnableInterpolation bool
	// HonorCSRSANs uses the DNS and IP SANs embedded in the kubelet-generated
	// PKCS#10 CSR when no san/ip-san annotation overrides them. CSR SANs are
	// still subject to the identity constraints below: unless
	// AllowUnverifiedIdentities is set, CSR DNS SANs must clear the same
	// verified-identity allowlist as annotation values, and CSR IP SANs (which
	// have no verified derivation) are denied. Kubelet generates empty CSRs
	// today, so this is inert until Kubernetes starts embedding requested
	// SANs; when disabled, CSR SANs are ignored, which the API contract
	// explicitly allows for signers.
	HonorCSRSANs bool
	// AllowUnverifiedIdentities lifts the requirement that certificate identities
	// resolve to one derived from the apiserver-verified PodCertificateRequest
	// fields (pod name/namespace/serviceAccountName/uid + cluster FQDN). It
	// governs both annotation-provided cn/san/ip-san/uris values and, when
	// HonorCSRSANs is set, the SANs requested via the CSR. It is off by default:
	// without it, values that do not derive from a verified identity are denied,
	// so a pod cannot request a certificate for an identity it does not own. IP
	// SANs and arbitrary literals have no verified derivation and are always
	// denied when this is false.
	AllowUnverifiedIdentities bool
}

// NewPodCertificateConfig builds the certificate configuration for the given
// PodCertificateRequest, its associated pod and the CSR kubelet generated for
// it. A nil csr means no public key and no requested SANs.
//
// Configuration values are read from the request spec.unverifiedUserAnnotations,
// falling back to the pod's annotations (deprecated, see
// annotationResolver.lookup). Keys follow the <signer-name>-<suffix>
// convention, e.g. coolcert.example.com/mysigner-cn.
//
// Malformed values and any unverifiedUserAnnotations key the signer does not
// recognize result in an error, since signers should deny requests they do not
// fully understand rather than silently fall back to defaults. The same
// denial applies to pod annotations that carry the signer's prefix.
func NewPodCertificateConfig(
	ctx context.Context,
	pcr *certificatesv1.PodCertificateRequest,
	pod *corev1.Pod,
	csr *CSR,
	opts Options,
) (*PodCertificateConfig, error) {
	if csr == nil {
		csr = &CSR{}
	}
	if opts.ClusterFQDN == "" {
		opts.ClusterFQDN = DefaultClusterFQDN
	}
	signerName := pcr.Spec.SignerName

	if err := checkUnrecognizedAnnotations(pcr.Spec.UnverifiedUserAnnotations, signerName, false); err != nil {
		return nil, err
	}
	if pod != nil {
		if err := checkUnrecognizedAnnotations(pod.Annotations, signerName, true); err != nil {
			return nil, err
		}
	}

	resolver := &annotationResolver{
		logger:     log.FromContext(ctx),
		pcr:        pcr,
		pod:        pod,
		csr:        csr,
		signerName: signerName,
		vars:       interpolationVars(pcr, opts.ClusterFQDN),
		opts:       opts,
	}
	// When identity constraints are enforced (the default), annotation-derived
	// cn/san/uris values must resolve to one of the identities the signer would
	// itself derive from the verified request fields; anything else is denied.
	// A nil allowlist means the constraint is off.
	if !opts.AllowUnverifiedIdentities {
		resolver.verified = verifiedIdentities(pcr, opts.ClusterFQDN)
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

	defaultDNSNames, dnsLabelTooLong := defaultPodDNSNames(pod.Name, pod.Namespace, opts.ClusterFQDN)

	config := &PodCertificateConfig{
		CommonName:         defaultCommonName(pod.Name),
		DNSNames:           defaultDNSNames,
		Duration:           duration,
		RefreshBefore:      DefaultRefreshBefore,
		MaxExpiration:      maxExpiration,
		KeyUsage:           keyUsageFor(csr.PublicKeyAlgorithm),
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
	}

	var err error
	if config.CommonName, err = resolver.commonName(config.CommonName); err != nil {
		return nil, err
	}
	if config.DNSNames, err = resolver.dnsNames(config.DNSNames); err != nil {
		return nil, err
	}
	// If the default pod DNS SANs were dropped for an over-long label and no
	// annotation/CSR SAN took their place, the certificate loses its canonical
	// DNS identity. Surface it so the operator can add an explicit SAN; the
	// reconciler turns this into a Warning event and a log line.
	if dnsLabelTooLong && len(config.DNSNames) == 0 {
		config.Warnings = append(config.Warnings, fmt.Sprintf(
			"default pod DNS SANs omitted: pod name %q exceeds the %d-character DNS label limit; request an explicit SAN via the san annotation if one is needed",
			pod.Name, dnsLabelMaxLen))
	}
	if config.IPAddresses, err = resolver.ipAddresses(); err != nil {
		return nil, err
	}
	if config.ExtKeyUsage, err = resolver.extKeyUsage(config.ExtKeyUsage); err != nil {
		return nil, err
	}
	if config.URIs, err = resolver.uris(); err != nil {
		return nil, err
	}
	if config.Duration, err = resolver.duration(AnnotationSuffixDuration, config.Duration); err != nil {
		return nil, err
	}
	if config.RefreshBefore, err = resolver.duration(AnnotationSuffixRefreshBefore, config.RefreshBefore); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks that the configuration can be used to issue a certificate
// which kube-apiserver will accept on the status subresource. Validating up
// front turns misconfigurations into an immediate denial instead of an
// endless requeue loop caused by rejected status updates.
func (pcc *PodCertificateConfig) Validate() error {
	if pcc.CommonName == "" {
		// An empty common name is valid as long as the certificate still
		// carries a subject alternative name to identify by. Go marks the SAN
		// extension critical in that case, which is exactly what we want for a
		// SAN-only certificate (see defaultCommonName for long pod names).
		if len(pcc.DNSNames) == 0 && len(pcc.IPAddresses) == 0 && len(pcc.URIs) == 0 {
			return errors.New("common name or at least one subject alternative name is required")
		}
	} else if len(pcc.CommonName) > 64 {
		// RFC 5280 ub-common-name; easily exceeded by interpolated pod names.
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

// annotationKey builds the full annotation key for a configuration suffix,
// e.g. coolcert.example.com/mysigner-cn.
func annotationKey(signerName, suffix string) string {
	return signerName + "-" + suffix
}

// podAnnotation returns the value of the given pod annotation. It reports false
// when the pod is nil, or the annotation is absent or empty.
func podAnnotation(pod *corev1.Pod, key string) (string, bool) {
	if pod == nil || pod.Annotations == nil {
		return "", false
	}
	value, ok := pod.Annotations[key]
	if !ok || value == "" {
		return "", false
	}

	return value, true
}

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

// checkUnrecognizedAnnotations rejects annotation keys the signer does not
// recognize. Signers should deny such requests rather than silently fall back
// to defaults, see
// https://pkg.go.dev/k8s.io/api/certificates/v1#PodCertificateRequestSpec
//
// On spec.unverifiedUserAnnotations every key is the signer's business, so any
// unknown key is rejected. Pod annotations are shared with every other
// consumer of the pod, so only keys carrying the signer's own prefix are
// examined (signerPrefixedOnly) - the same typo that would be denied on the
// request is then denied on the pod too, rather than silently ignored.
func checkUnrecognizedAnnotations(annotations map[string]string, signerName string, signerPrefixedOnly bool) error {
	known := make(map[string]struct{}, len(annotationSuffixes))
	for _, suffix := range annotationSuffixes {
		known[annotationKey(signerName, suffix)] = struct{}{}
	}

	for key := range annotations {
		if signerPrefixedOnly && !strings.HasPrefix(key, signerName+"-") {
			continue
		}
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

// lookup resolves a configuration value, preferring the request
// spec.unverifiedUserAnnotations over the deprecated pod annotations.
//
// Deprecated: the pod-annotation fallback is removed in 4.0.0; configure the
// signer through spec.unverifiedUserAnnotations. Every value still taken from
// a pod annotation is logged so remaining users can be found before then.
func (r *annotationResolver) lookup(suffix string) (string, bool) {
	key := annotationKey(r.signerName, suffix)
	if value, ok := r.pcr.Spec.UnverifiedUserAnnotations[key]; ok && value != "" {
		return value, true
	}
	value, ok := podAnnotation(r.pod, key)
	if ok {
		r.logger.Info("certificate configuration read from a pod annotation, which is deprecated and will be removed in 4.0.0; "+
			"move it to spec.unverifiedUserAnnotations", "annotation", key)
	}
	return value, ok
}

// value looks up a configuration value and expands ${...} placeholders in it
// from the apiserver-verified fields of the request.
func (r *annotationResolver) value(suffix string) (string, bool, error) {
	raw, ok := r.lookup(suffix)
	if !ok {
		return "", false, nil
	}
	expanded, err := interpolate(raw, r.vars, r.opts.EnableInterpolation)
	if err != nil {
		return "", true, r.annotationError(suffix, err)
	}
	return expanded, true, nil
}

// annotationError names the annotation an error came from.
func (r *annotationResolver) annotationError(suffix string, err error) error {
	return fmt.Errorf("annotation %q: %w", annotationKey(r.signerName, suffix), err)
}

// commonName resolves the cn annotation, falling back to def, and checks it
// against the verified identities.
func (r *annotationResolver) commonName(def string) (string, error) {
	cn, ok, err := r.value(AnnotationSuffixCN)
	if err != nil || !ok {
		return def, err
	}
	if err := assertVerifiedIdentities("common name", []string{cn}, r.verified); err != nil {
		return "", err
	}
	return cn, nil
}

// dnsNames applies the san-annotation > CSR-requested > default precedence for
// DNS SANs, validates the selected names, and, when identity constraints are
// enforced, verifies each name against the pod's identity.
func (r *annotationResolver) dnsNames(defaults []string) ([]string, error) {
	san, ok, err := r.value(AnnotationSuffixSAN)
	if err != nil {
		return nil, err
	}
	if !ok {
		if r.opts.HonorCSRSANs && len(r.csr.DNSNames) > 0 {
			if err := validateDNSNames(r.csr.DNSNames); err != nil {
				return nil, err
			}
			// CSR-requested SANs are attacker-influenced just like annotation
			// values, so they must clear the same verified-identity allowlist.
			if err := assertVerifiedIdentities("CSR DNS name", r.csr.DNSNames, r.verified); err != nil {
				return nil, err
			}
			return r.csr.DNSNames, nil
		}
		if err := validateDNSNames(defaults); err != nil {
			return nil, err
		}
		return defaults, nil
	}
	names := splitAndTrim(san)
	if len(names) == 0 {
		return nil, r.annotationError(AnnotationSuffixSAN, errors.New("contains no DNS names"))
	}
	if err := validateDNSNames(names); err != nil {
		return nil, err
	}
	if err := assertVerifiedIdentities("DNS name", names, r.verified); err != nil {
		return nil, err
	}
	return names, nil
}

// ipAddresses applies the ip-san-annotation > CSR-requested > none precedence
// for IP SANs. An IP has no verified derivation from the request fields, so
// both sources are denied unless unverified identities are allowed.
func (r *annotationResolver) ipAddresses() ([]net.IP, error) {
	ipSAN, ok := r.lookup(AnnotationSuffixIPSAN)
	if !ok {
		if r.opts.HonorCSRSANs && len(r.csr.IPAddresses) > 0 {
			if r.verified != nil {
				return nil, errors.New("CSR IP SANs are not derived from a verified pod identity and are denied; start the controller with --allow-unverified-identities to allow them")
			}
			return r.csr.IPAddresses, nil
		}
		return nil, nil
	}
	if r.verified != nil {
		return nil, r.annotationError(AnnotationSuffixIPSAN, errors.New("IP SANs are not derived from a verified pod identity and are denied; start the controller with --allow-unverified-identities to allow them"))
	}
	ipSAN, err := interpolate(ipSAN, r.vars, r.opts.EnableInterpolation)
	if err != nil {
		return nil, r.annotationError(AnnotationSuffixIPSAN, err)
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
	if err := assertVerifiedIdentities("URI", literals, r.verified); err != nil {
		return nil, err
	}
	return parsed, nil
}

// duration resolves a duration-valued annotation (duration, refresh), falling
// back to def when it is absent.
func (r *annotationResolver) duration(suffix string, def time.Duration) (time.Duration, error) {
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
