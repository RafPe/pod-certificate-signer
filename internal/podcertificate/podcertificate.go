package podcertificate

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

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
