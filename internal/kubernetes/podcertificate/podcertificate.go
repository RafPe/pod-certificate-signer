package podCertificate

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
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
	KeyUsage           x509.KeyUsage      //TODO: Customizable Key Usage via Policies
	ExtKeyUsage        []x509.ExtKeyUsage //TODO: Customizable Ext Key Usage via Policies or other aliases i.e. client-server-auth , ssl ,
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
func (pc *PodCertificate) Certificate() []byte {
	return pc.certificate
}

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

// -- validators :)
func (pc *PodCertificate) IsValid() bool {
	now := time.Now()
	return now.After(pc.notBefore) && now.Before(pc.notAfter)
}

func (pc *PodCertificate) ExpiresIn() time.Duration {
	return time.Until(pc.notAfter)
}

func (pc *PodCertificate) CertificateChainToPEM() []byte {
	return []byte(pc.certificateChain)
}

func (pc *PodCertificate) CertificateToPEM() []byte {
	return []byte(pc.certificate)
}

// -- Config

func NewPodCertificateConfig(pod *corev1.Pod, signerName string, publicKey crypto.PublicKey, publicKeyAlgorithm x509.PublicKeyAlgorithm) (*PodCertificateConfig, error) {

	config := &PodCertificateConfig{
		CommonName:         getConfigFromAnnotationsCN(pod, signerName),
		DNSNames:           getConfigFromAnnotationsSAN(pod, signerName),
		URIs:               getConfigFromAnnotationsURIs(pod, signerName),
		Duration:           getConfigFromAnnotationsDuration(pod, signerName),
		RefreshBefore:      getConfigFromAnnotationsRefreshBefore(pod, signerName),
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
	if cn, exists := api.GetPodAnnotation(pod, fmt.Sprintf("%s-%s", signerName, PodCertificateConfigAnnotationSuffixCN)); exists {
		return cn
	}
	return pod.Name // Default
}

// getConfigFromAnnotationsSAN extracts DNS names from pod annotations or uses default
func getConfigFromAnnotationsSAN(pod *corev1.Pod, signerName string) []string {
	if san, exists := api.GetPodAnnotation(pod, fmt.Sprintf("%s-%s", signerName, PodCertificateConfigAnnotationSuffixSAN)); exists {
		return strings.Split(san, ",")
	}

	// Default DNS names
	return []string{
		pod.Name + "." + pod.Namespace + ".pod.cluster.local",
		pod.Name + "." + pod.Namespace + ".svc.cluster.local",
	}
}

func getConfigFromAnnotationsURIs(pod *corev1.Pod, signerName string) []*url.URL {
	if uris, exists := api.GetPodAnnotation(pod, fmt.Sprintf("%s-%s", signerName, PodCertificateConfigAnnotationSuffixURIs)); exists {
		uriStrings := strings.Split(uris, ",")
		uris := make([]*url.URL, 0, len(uriStrings))
		for _, uriStr := range uriStrings {
			if uri, err := url.Parse(strings.TrimSpace(uriStr)); err == nil {
				uris = append(uris, uri)
			}
		}
		return uris
	}

	// Default URIs - empty for now
	return []*url.URL{}
}

// getConfigFromAnnotationsDuration extracts duration from pod annotations or uses default
func getConfigFromAnnotationsDuration(pod *corev1.Pod, signerName string) time.Duration {
	if durationStr, exists := api.GetPodAnnotation(pod, fmt.Sprintf("%s-%s", signerName, PodCertificateConfigAnnotationSuffixDuration)); exists {
		if duration, err := time.ParseDuration(durationStr); err == nil {
			return duration
		}
	}
	return 24 * time.Hour // Default
}

// getConfigFromAnnotationsRefreshBefore extracts refresh before from pod annotations or uses default
func getConfigFromAnnotationsRefreshBefore(pod *corev1.Pod, signerName string) time.Duration {
	if refreshStr, exists := api.GetPodAnnotation(pod, fmt.Sprintf("%s-%s", signerName, PodCertificateConfigAnnotationSuffixRefreshBefore)); exists {
		if refresh, err := time.ParseDuration(refreshStr); err == nil {
			return refresh
		}
	}
	//TODO: Default value here
	// As a ref certificate minimum duration is 1 hour - so we can safely say 15 min - the field is only a hint so
	// this is not 100% deterministic value for the kube-api.
	return 15 * time.Minute // Default
}

//TODO: Implement these :)
// Helper Methods:
// PodCertificate.IsValid() bool
// PodCertificate.ExpiresIn() time.Duration
// PodCertificateConfig.Validate() error
// PodCertificate.ToPEM() []byte
