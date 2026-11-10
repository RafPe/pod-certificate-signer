package podcertificate

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
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
	// Notices are non-fatal facts about how the configuration was resolved
	// (e.g. default pod DNS SANs omitted for an over-long pod name). The
	// certificate still issues; the reconciler surfaces each as a Warning event
	// under its reason, so the operator can see why a default was dropped.
	Notices []Notice
}

// Notice is one non-fatal fact about how a configuration was resolved, with
// the reason the reconciler reports it under.
type Notice struct {
	Reason  outcome.NonTerminalReason
	Message string
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

// commonNameMaxLen is the RFC 5280 ub-common-name limit, easily exceeded by
// interpolated pod names.
const commonNameMaxLen = 64

// Validate checks that the configuration can be used to issue a certificate
// which kube-apiserver will accept on the status subresource. Validating up
// front turns misconfigurations into an immediate denial instead of an
// endless requeue loop caused by rejected status updates.
func (c *Config) Validate() error {
	if c.PublicKey == nil {
		return errors.New("a subject public key is required")
	}
	if c.CommonName == "" {
		// An empty common name is valid as long as the certificate still
		// carries a subject alternative name to identify by. Go marks the SAN
		// extension critical in that case, which is exactly what we want for a
		// SAN-only certificate (see defaultCommonName for long pod names).
		if len(c.DNSNames) == 0 && len(c.IPAddresses) == 0 && len(c.URIs) == 0 {
			return errors.New("common name or at least one subject alternative name is required")
		}
	} else if len(c.CommonName) > commonNameMaxLen {
		return fmt.Errorf("common name %q exceeds the %d character limit", c.CommonName, commonNameMaxLen)
	}
	if c.Duration < MinDuration {
		return fmt.Errorf("duration (%s) must be at least %s", c.Duration, MinDuration)
	}
	if c.MaxExpiration > 0 && c.Duration > c.MaxExpiration {
		return fmt.Errorf("duration (%s) exceeds the maxExpirationSeconds of the request (%s)", c.Duration, c.MaxExpiration)
	}
	if c.RefreshBefore < RefreshMargin {
		return fmt.Errorf("refresh before (%s) must be at least %s", c.RefreshBefore, RefreshMargin)
	}
	if c.RefreshBefore > c.Duration-RefreshMargin {
		return fmt.Errorf("refresh before (%s) must not exceed the certificate duration (%s) minus %s", c.RefreshBefore, c.Duration, RefreshMargin)
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
