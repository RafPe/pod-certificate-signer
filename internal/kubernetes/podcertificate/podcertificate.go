package podcertificate

import (
	"context"
	"crypto"
	"crypto/x509"
	"net/url"
	"strings"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/api"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type PodCertificate struct {
	certificate      []byte
	certificateChain string
	config           *PodCertificateConfig
	notBefore        time.Time
	notAfter         time.Time
}

type PodCertificateConfig struct {
	CommonName         string
	DNSNames           []string
	URIs               []*url.URL
	Duration           time.Duration
	RefreshBefore      time.Duration
	KeyUsage           x509.KeyUsage      // TODO: Customizable Key Usage via Policies
	ExtKeyUsage        []x509.ExtKeyUsage // TODO: Customizable Ext Key Usage via Policies or other aliases i.e. client-server-auth , ssl ,
	PublicKey          crypto.PublicKey   // Change from PKIXPublicKey []byte
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
}

// Well-known pod annotation suffixes for configuration of the signer
// These are in the format of: <signer-name>-<suffix> i.e. coolcert.example.com/mysigner-cn
const (
	// Common name for the certificate
	PodCertificateConfigAnnotationSuffixCN string = "cn"
	// DNS names for the certificate
	PodCertificateConfigAnnotationSuffixSAN string = "san"
	// Duration for the certificate
	PodCertificateConfigAnnotationSuffixDuration string = "duration"
	// Refresh before for the certificate
	PodCertificateConfigAnnotationSuffixRefreshBefore string = "refresh"
	// URIs for the certificate
	PodCertificateConfigAnnotationSuffixURIs string = "uris"
)

// -- PodCertificate

func NewPodCertificate(certificate []byte, certificateChain string, config *PodCertificateConfig, notBefore, notAfter time.Time) *PodCertificate {
	return &PodCertificate{
		certificate:      certificate,
		certificateChain: certificateChain,
		config:           config,
		notBefore:        notBefore,
		notAfter:         notAfter,
	}
}

// -- getters :)
func (pc *PodCertificate) CertificateChain() string {
	return pc.certificateChain
}

func (pc *PodCertificate) Config() *PodCertificateConfig {
	return pc.config
}

func (pc *PodCertificate) NotBefore() time.Time {
	return pc.notBefore
}

func (pc *PodCertificate) NotAfter() time.Time {
	return pc.notAfter
}

func annotationKey(signerName, suffix string) string {
	return signerName + "-" + suffix
}

// -- Config

func NewPodCertificateConfig(ctx context.Context, pod *corev1.Pod, signerName, clusterFqdn string, publicKey crypto.PublicKey, publicKeyAlgorithm x509.PublicKeyAlgorithm) (*PodCertificateConfig, error) {
	config := &PodCertificateConfig{
		CommonName:         getConfigFromAnnotationsCN(pod, signerName),
		DNSNames:           getConfigFromAnnotationsSAN(pod, signerName, clusterFqdn),
		URIs:               getConfigFromAnnotationsURIs(ctx, pod, signerName),
		Duration:           getConfigFromAnnotationsDuration(ctx, pod, signerName),
		RefreshBefore:      getConfigFromAnnotationsRefreshBefore(ctx, pod, signerName),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		PublicKey:          publicKey,
		PublicKeyAlgorithm: publicKeyAlgorithm,
	}
	return config, nil
}

func (pcc *PodCertificateConfig) LogConfiguration(ctx context.Context) {
	lgr := log.FromContext(ctx)

	lgr.Info("Successfully created PodCertificateConfig",
		"commonName", pcc.CommonName,
		"dnsNames", pcc.DNSNames,
		"uris", pcc.URIs,
		"duration", pcc.Duration.String(),
		"refreshBefore", pcc.RefreshBefore.String())
}

// getConfigFromAnnotationsCN extracts common name from pod annotations or uses default
func getConfigFromAnnotationsCN(pod *corev1.Pod, signerName string) string {
	if cn, exists := api.GetPodAnnotation(pod, annotationKey(signerName, PodCertificateConfigAnnotationSuffixCN)); exists {
		return cn
	}
	return pod.Name
}

// getConfigFromAnnotationsSAN extracts DNS names from pod annotations or uses default
func getConfigFromAnnotationsSAN(pod *corev1.Pod, signerName, clusterFqdn string) []string {
	if san, exists := api.GetPodAnnotation(pod, annotationKey(signerName, PodCertificateConfigAnnotationSuffixSAN)); exists {
		return strings.Split(san, ",")
	}
	return []string{
		pod.Name + "." + pod.Namespace + ".pod." + clusterFqdn,
		pod.Name + "." + pod.Namespace + ".svc." + clusterFqdn,
	}
}

func getConfigFromAnnotationsURIs(ctx context.Context, pod *corev1.Pod, signerName string) []*url.URL {
	if uris, exists := api.GetPodAnnotation(pod, annotationKey(signerName, PodCertificateConfigAnnotationSuffixURIs)); exists {
		uriStrings := strings.Split(uris, ",")
		parsed := make([]*url.URL, 0, len(uriStrings))
		for _, uriStr := range uriStrings {
			uri, err := url.Parse(strings.TrimSpace(uriStr))
			if err != nil {
				log.FromContext(ctx).Info("ignoring invalid URI annotation value", "value", uriStr, "error", err.Error())
				continue
			}
			parsed = append(parsed, uri)
		}
		return parsed
	}
	return []*url.URL{}
}

// getConfigFromAnnotationsDuration extracts duration from pod annotations or uses default
func getConfigFromAnnotationsDuration(ctx context.Context, pod *corev1.Pod, signerName string) time.Duration {
	const def = 24 * time.Hour
	if durationStr, exists := api.GetPodAnnotation(pod, annotationKey(signerName, PodCertificateConfigAnnotationSuffixDuration)); exists {
		if duration, err := time.ParseDuration(durationStr); err == nil {
			return duration
		} else {
			log.FromContext(ctx).Info("ignoring invalid duration annotation; using default", "value", durationStr, "default", def.String(), "error", err.Error())
		}
	}
	return def
}

// getConfigFromAnnotationsRefreshBefore extracts refresh before from pod annotations or uses default
func getConfigFromAnnotationsRefreshBefore(ctx context.Context, pod *corev1.Pod, signerName string) time.Duration {
	const def = 15 * time.Minute
	if refreshStr, exists := api.GetPodAnnotation(pod, annotationKey(signerName, PodCertificateConfigAnnotationSuffixRefreshBefore)); exists {
		if refresh, err := time.ParseDuration(refreshStr); err == nil {
			return refresh
		} else {
			log.FromContext(ctx).Info("ignoring invalid refresh annotation; using default", "value", refreshStr, "default", def.String(), "error", err.Error())
		}
	}
	return def
}
