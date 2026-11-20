// Package audit builds the issuance audit record: one JSON line per signing
// attempt and per terminal outcome, which joins a certificate serial or
// fingerprint to the PodCertificateRequest and the pod that requested it.
//
// A record is built by a [Builder] from the request, the live pod and the
// issued certificate.
package audit

import "github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"

// Kind is the value of the kind field of every record. It tells a record apart
// from operational log lines when a collector merges the two streams.
const Kind = "CertificateAuditRecord"

// SchemaVersion is the version of the record shape.
const SchemaVersion = "v1"

// Event is what a record reports about a certificate or a request.
type Event string

// The events a record can report.
const (
	// EventSigned: the signer created a certificate. Nothing is published yet.
	EventSigned Event = "signed"
	// EventPublished: the API server accepted the certificate for the request.
	EventPublished Event = "published"
	// EventSuperseded: another writer won, so the certificate was not
	// published.
	EventSuperseded Event = "superseded"
	// EventUnknown: the status write may have committed. The API server audit
	// log decides.
	EventUnknown Event = "unknown"
	// EventDenied: the request was denied.
	EventDenied Event = "denied"
	// EventFailed: the request failed.
	EventFailed Event = "failed"
)

// Reasons for the three follow-up events. Terminal events reuse
// outcome.ConditionReason.
const (
	ReasonStatusWritten  = "StatusWritten"
	ReasonOtherWriterWon = "OtherWriterWon"
	ReasonRequestGone    = "RequestGone"
	ReasonWriteRejected  = "WriteRejected"
	ReasonWriteAmbiguous = "WriteAmbiguous"
)

// Record is one audit record. Its JSON encoding is the record line. A group
// that does not apply to the event is nil and absent from the line.
type Record struct {
	Kind          string `json:"kind"`
	SchemaVersion string `json:"schemaVersion"`
	// TS is the time the record was built, in RFC 3339 UTC with milliseconds.
	TS     string `json:"ts"`
	Event  Event  `json:"event"`
	Reason string `json:"reason"`
	// Message is the terminal condition message. It can hold requester text.
	Message     string       `json:"message,omitempty"`
	SignerName  string       `json:"signerName"`
	Request     Request      `json:"request"`
	Workload    *Workload    `json:"workload,omitempty"`
	Certificate *Certificate `json:"certificate,omitempty"`
	Issuer      *Issuer      `json:"issuer,omitempty"`
}

// Request identifies the PodCertificateRequest and names the signer
// configuration keys the requester supplied.
type Request struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
	// SuppliedKeys is sorted. It is nil, and absent, in a follow-up record.
	SuppliedKeys []string `json:"suppliedKeys,omitzero"`
	// SuppliedValues is set only when [Options.RecordSuppliedValues] is true.
	SuppliedValues map[string]string `json:"suppliedValues,omitzero"`
}

// Workload identifies the pod the certificate was requested for.
type Workload struct {
	Pod            ObjectRef `json:"pod"`
	ServiceAccount ObjectRef `json:"serviceAccount"`
	Node           ObjectRef `json:"node"`
	// Owner is the controller ownerReference of the live pod, if it has one.
	Owner *Owner `json:"owner,omitempty"`
	// Labels and Annotations are the pod keys the options select. Nil means
	// removed from the record.
	Labels      map[string]string `json:"labels,omitzero"`
	Annotations map[string]string `json:"annotations,omitzero"`
	Omitted     Omitted           `json:"omitted"`
}

// ObjectRef is the name and UID of an object.
type ObjectRef struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// Owner is the controller ownerReference of a pod.
type Owner struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

// Omitted reports what the limits left out of the record. Labels and
// Annotations count the pod keys that matched the options but are not in the
// record, because of [Options.MaxCopiedKeys] or [Options.MaxRecordBytes].
type Omitted struct {
	Labels      int `json:"labels"`
	Annotations int `json:"annotations"`
	// SuppliedValues counts the supplied values that [Options.MaxRecordBytes]
	// removed from request.suppliedValues. The keys stay in
	// request.suppliedKeys.
	SuppliedValues int `json:"suppliedValues,omitzero"`
	// OverBudget is true when the line is longer than [Options.MaxRecordBytes]
	// after every removable group was removed. The line is written whole.
	OverBudget bool `json:"overBudget,omitzero"`
}

// Certificate describes the issued certificate, as parsed from its DER. A
// follow-up record carries only the serial and the fingerprint.
type Certificate struct {
	// SerialHex is lowercase hex with no separators and no leading zeros.
	SerialHex     string `json:"serialHex"`
	SerialDecimal string `json:"serialDecimal"`
	Fingerprint   string `json:"fingerprint"`
	// CertificateDetails is set only in a signed record. encoding/json inlines
	// its fields when it is set and leaves them out when it is nil. It is nil
	// in every follow-up record, so check it before you read a promoted field
	// such as DNSNames: that read panics on a nil pointer.
	*CertificateDetails
}

// CertificateDetails is the content of the issued certificate that only a
// signed record carries.
type CertificateDetails struct {
	CommonName   string   `json:"commonName"`
	DNSNames     []string `json:"dnsNames"`
	IPAddresses  []string `json:"ipAddresses"`
	URIs         []string `json:"uris"`
	ExtKeyUsage  []string `json:"extKeyUsage"`
	KeyAlgorithm string   `json:"keyAlgorithm"`
	NotBefore    string   `json:"notBefore"`
	NotAfter     string   `json:"notAfter"`
	Sources      Sources  `json:"sources"`
}

// Sources records where each requester-configurable field of the certificate
// configuration took its value from. It is podcertificate.FieldSources with
// the record's field names.
type Sources struct {
	CommonName    podcertificate.Source `json:"commonName"`
	DNSNames      podcertificate.Source `json:"dnsNames"`
	IPAddresses   podcertificate.Source `json:"ipAddresses"`
	URIs          podcertificate.Source `json:"uris"`
	ExtKeyUsage   podcertificate.Source `json:"extKeyUsage"`
	Duration      podcertificate.Source `json:"duration"`
	RefreshBefore podcertificate.Source `json:"refreshBefore"`
}

// Issuer identifies the CA certificate that signed the issued certificate. A
// serial is unique only within one issuer, so a query scopes a serial by the
// issuer fingerprint.
type Issuer struct {
	Subject     string `json:"subject"`
	SerialHex   string `json:"serialHex"`
	Fingerprint string `json:"fingerprint"`
}
