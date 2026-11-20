package audit

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/outcome"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
)

// tsLayout is RFC 3339 in UTC with exactly three fractional digits.
// time.RFC3339Nano would drop trailing zeros.
const tsLayout = "2006-01-02T15:04:05.000Z07:00"

// Builder builds the records of one signer under one set of [Options]. It is
// safe for concurrent use.
type Builder struct {
	signerName  string
	opts        Options
	labels      matcher
	annotations matcher
}

// NewBuilder returns a [Builder] for signerName. It returns an error when opts
// do not pass [Options.Validate].
func NewBuilder(signerName string, opts Options) (*Builder, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("audit options: %w", err)
	}
	return &Builder{
		signerName:  signerName,
		opts:        opts,
		labels:      newMatcher(opts.PodLabels),
		annotations: newMatcher(opts.PodAnnotations),
	}, nil
}

// Signed builds the full record for a certificate that was signed and not yet
// published. cert.Leaf, cert.Issuer and cert.Config must not be nil. supplied
// is the result of podcertificate.SuppliedAnnotations.
func (b *Builder) Signed(pcr *certificatesv1.PodCertificateRequest, pod *corev1.Pod,
	cert *podcertificate.Certificate, supplied map[string]string) Record {
	rec := b.envelope(EventSigned, string(outcome.CertificateIssued))
	rec.Request = b.request(pcr, supplied)
	rec.Workload = b.workload(pcr, pod)
	rec.Certificate = certificate(cert)
	rec.Issuer = &Issuer{
		Subject:     cert.Issuer.Subject.String(),
		SerialHex:   cert.Issuer.SerialNumber.Text(16),
		Fingerprint: Fingerprint(cert.Issuer),
	}
	return rec
}

// FollowUp builds a published, superseded or unknown record from a signed
// record: the envelope, the request identity (namespace, name, uid) and the
// certificate serials and fingerprint. It has no workload group.
func (b *Builder) FollowUp(event Event, reason string, signed Record) Record {
	rec := b.envelope(event, reason)
	rec.Request = Request{
		Namespace: signed.Request.Namespace,
		Name:      signed.Request.Name,
		UID:       signed.Request.UID,
	}
	if signed.Certificate != nil {
		rec.Certificate = &Certificate{
			SerialHex:     signed.Certificate.SerialHex,
			SerialDecimal: signed.Certificate.SerialDecimal,
			Fingerprint:   signed.Certificate.Fingerprint,
		}
	}
	return rec
}

// Terminal builds a denied or failed record. It has no certificate or issuer
// group. pod is the live pod, or nil when the signer did not read it.
func (b *Builder) Terminal(event Event, reason, message string, pcr *certificatesv1.PodCertificateRequest,
	pod *corev1.Pod, supplied map[string]string) Record {
	rec := b.envelope(event, reason)
	rec.Message = message
	rec.Request = b.request(pcr, supplied)
	rec.Workload = b.workload(pcr, pod)
	return rec
}

// Fingerprint returns the SHA-256 of the DER certificate in the Kubernetes
// credential-id form "X509SHA256=<lowercase hex>".
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "X509SHA256=" + hex.EncodeToString(sum[:])
}

func (b *Builder) envelope(event Event, reason string) Record {
	return Record{
		Kind:          Kind,
		SchemaVersion: SchemaVersion,
		TS:            time.Now().UTC().Format(tsLayout),
		Event:         event,
		Reason:        reason,
		SignerName:    b.signerName,
	}
}

func (b *Builder) request(pcr *certificatesv1.PodCertificateRequest, supplied map[string]string) Request {
	req := Request{
		Namespace:    pcr.Namespace,
		Name:         pcr.Name,
		UID:          string(pcr.UID),
		SuppliedKeys: slices.Sorted(maps.Keys(supplied)),
	}
	if req.SuppliedKeys == nil {
		req.SuppliedKeys = []string{}
	}
	if b.opts.RecordSuppliedValues {
		req.SuppliedValues = maps.Clone(supplied)
		if req.SuppliedValues == nil {
			req.SuppliedValues = map[string]string{}
		}
	}
	return req
}

func (b *Builder) workload(pcr *certificatesv1.PodCertificateRequest, pod *corev1.Pod) *Workload {
	w := &Workload{
		Pod:            ObjectRef{Name: pcr.Spec.PodName, UID: string(pcr.Spec.PodUID)},
		ServiceAccount: ObjectRef{Name: pcr.Spec.ServiceAccountName, UID: string(pcr.Spec.ServiceAccountUID)},
		Node:           ObjectRef{Name: string(pcr.Spec.NodeName), UID: string(pcr.Spec.NodeUID)},
	}
	var labels, annotations map[string]string
	if pod != nil {
		if ref := metav1.GetControllerOf(pod); ref != nil {
			w.Owner = &Owner{APIVersion: ref.APIVersion, Kind: ref.Kind, Name: ref.Name, UID: string(ref.UID)}
		}
		labels, annotations = pod.Labels, pod.Annotations
	}
	w.Labels, w.Omitted.Labels = b.labels.selectKeys(labels, b.opts.MaxCopiedKeys)
	w.Annotations, w.Omitted.Annotations = b.annotations.selectKeys(annotations, b.opts.MaxCopiedKeys)
	return w
}

func certificate(cert *podcertificate.Certificate) *Certificate {
	leaf := cert.Leaf
	c := &Certificate{
		SerialHex:     leaf.SerialNumber.Text(16),
		SerialDecimal: leaf.SerialNumber.String(),
		Fingerprint:   Fingerprint(leaf),
		CertificateDetails: &CertificateDetails{
			CommonName:   leaf.Subject.CommonName,
			DNSNames:     append([]string{}, leaf.DNSNames...),
			IPAddresses:  make([]string, 0, len(leaf.IPAddresses)),
			URIs:         make([]string, 0, len(leaf.URIs)),
			ExtKeyUsage:  make([]string, 0, len(leaf.ExtKeyUsage)),
			KeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
			NotBefore:    leaf.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:     leaf.NotAfter.UTC().Format(time.RFC3339),
			Sources:      sources(cert.Config.Sources),
		},
	}
	for _, ip := range leaf.IPAddresses {
		c.IPAddresses = append(c.IPAddresses, ip.String())
	}
	for _, uri := range leaf.URIs {
		c.URIs = append(c.URIs, uri.String())
	}
	for _, usage := range leaf.ExtKeyUsage {
		c.ExtKeyUsage = append(c.ExtKeyUsage, extKeyUsageName(usage))
	}
	return c
}

func sources(s podcertificate.FieldSources) Sources {
	return Sources{
		CommonName:    s.CommonName,
		DNSNames:      s.DNSNames,
		IPAddresses:   s.IPAddresses,
		URIs:          s.URIs,
		ExtKeyUsage:   s.ExtKeyUsage,
		Duration:      s.Duration,
		RefreshBefore: s.RefreshBefore,
	}
}

// extKeyUsageName returns the RFC 5280 name of usage. The signer issues only
// server and client auth, so any other usage is reported by its number.
func extKeyUsageName(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	default:
		return fmt.Sprintf("extKeyUsage(%d)", usage)
	}
}
