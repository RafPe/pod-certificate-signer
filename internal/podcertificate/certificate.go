package podcertificate

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"
)

// Certificate is a certificate issued for a pod, together with the
// configuration it was issued from and its validity bounds. It is built once
// by the authority and read by the reconciler; nothing mutates it afterwards.
type Certificate struct {
	// CertificateChain is the PEM-encoded chain: the issued certificate
	// followed by the CA certificate that signed it.
	CertificateChain string
	Config           *Config
	NotBefore        time.Time
	NotAfter         time.Time
}

// Config describes the certificate to be issued for a pod.
type Config struct {
	CommonName    string
	DNSNames      []string
	IPAddresses   []net.IP
	URIs          []*url.URL
	Duration      time.Duration
	RefreshBefore time.Duration
	// MaxExpiration is the maximum certificate lifetime permitted by the
	// PodCertificateRequest spec.maxExpirationSeconds. Zero means no limit.
	MaxExpiration time.Duration
	// KeyUsage is derived from the key type (see keyUsageFor) and is not
	// configurable by the requester.
	KeyUsage x509.KeyUsage
	// ExtKeyUsage is server auth by default; the eku annotation overrides it
	// (client, server).
	ExtKeyUsage        []x509.ExtKeyUsage
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

// Validate checks that the configuration can be used to issue a certificate
// which kube-apiserver will accept on the status subresource. Validating up
// front turns misconfigurations into an immediate denial instead of an
// endless requeue loop caused by rejected status updates.
func (pcc *Config) Validate() error {
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

// keyUsageFor returns the KeyUsage bits appropriate for the subject key type.
// keyEncipherment only has meaning for RSA key transport; for ECDSA and
// Ed25519 keys digitalSignature is the only applicable usage.
func keyUsageFor(alg x509.PublicKeyAlgorithm) x509.KeyUsage {
	if alg == x509.RSA {
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	return x509.KeyUsageDigitalSignature
}
