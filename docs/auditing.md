# Auditing

The signer writes an **issuance audit record** for each signing attempt and
each terminal outcome. A record joins a certificate serial or fingerprint to
the PodCertificateRequest and the pod that requested it. This guide tells how
to configure, collect and query the record.
[ADR-0007](adr/0007-issuance-audit-record.md) records the decision and the
alternatives that the project refused.

## What the record is and what it does not prove

The record is one JSON line on the stdout of the signer container. The
operational log stays on stderr. Only the leader replica signs, so the
records come from the replica that was the leader at that time.

The record is **best-effort**. The signer gets no acknowledgement that a
collector stored the line. A delivered certificate can have no stored record,
or only its `signed` record, in these cases:

- The stdout write fails, or the sink drops the record. See
  [Dropped records](#dropped-records).
- The signer node is lost before the collector ships the line.
- `audit.enabled` is `false`.
- The process stops between a persisted status write and the follow-up
  record. The certificate then has only its `signed` record.

A Denied or Failed outcome can also have no record:

- The status write result was ambiguous or rejected. The request requeued, and
  the next reconcile found the request already terminal.
- The status write conflicted, and the re-read found a terminal condition. The
  signer does not check whether that condition is its own committed write.

Use the API server audit log as the second trail for these cases. See
[The second trail](#the-second-trail).

The record does not prove these things:

- It does not prove that a pod received or used a certificate. A committed
  status makes the certificate available to kubelet. Receipt is a separate
  fact.
- It does not resolve a pod to its Deployment, CronJob or other ancestor.
  `workload.owner` is the direct controller owner only.
- It is not tamper-evident. Any container can print a line with the same
  `kind`. [Ship the records](#ship-the-records) tells how to filter.

The record adds no API call and no RBAC. It adds no metric, so the metrics
surface of [ADR-0005](adr/0005-bounded-metrics-surface.md) is unchanged.

### Dropped records

The sink waits at most 2 seconds for each write. The signer logs each
problem on stderr, under the logger name `audit`. These are the messages:

| Message | When | Fields |
| --- | --- | --- |
| `audit record dropped` | The record did not encode. Or the writer did not take it within 2 seconds while no write was in progress. Or the sink was closed. | `event`, `namespace`, `name`, `uid`, and `fingerprint` when the record has a certificate |
| `an audit record write was blocked past the write timeout` | A write was blocked for more than 2 seconds and then returned. The sink dropped the records that came during the block. | `dropped`: the count |
| `audit records were dropped before the audit sink closed` | The sink closed while a write was blocked | `dropped`: the count |
| `failed to write an audit record` | The stdout write returned an error | The error only |

A blocked write is not cancelled. The line is written when stdout accepts it.
Only the two count messages tell how many records the sink dropped during a
block. They do not name the records.

## Enable and configure

The record is on by default. The chart sets the `--audit-*` flags from the
`audit` values.

| Chart value | Flag | Default | Description |
| --- | --- | --- | --- |
| `audit.enabled` | `--audit-enabled` | `true` | Write the records. |
| `audit.pod_labels` | `--audit-pod-labels` | `[]` | Pod label keys to copy into each record. |
| `audit.pod_annotations` | `--audit-pod-annotations` | `[]` | Pod annotation keys to copy into each record. |
| `audit.max_copied_keys` | `--audit-max-copied-keys` | `32` | Maximum number of labels that a record copies, and separately of annotations. 1 to 256. |
| `audit.max_value_length` | `--audit-max-value-length` | `256` | Maximum length in bytes of each label value, annotation value, supplied value and message. 1 to 4096. |
| `audit.max_record_bytes` | `--audit-max-record-bytes` | `16384` | Maximum size in bytes of one record line. 4096 to 262144. |
| `audit.record_supplied_values` | `--audit-record-supplied-values` | `false` | Add the raw values of the supplied certificate configuration annotations. |

The signer checks the `audit` values at startup only when `audit.enabled` is
`true`. An invalid value stops the signer before it connects to the API
server.

### Select labels and annotations

Each entry in `pod_labels` and `pod_annotations` is an exact key, or a prefix
that ends in `*`. Example:

```yaml
audit:
  pod_labels:
    - pod-template-hash
    - "app.kubernetes.io/*"
  pod_annotations:
    - example.com/owner
```

The signer applies these rules:

- `*` is allowed only as the last character of an entry.
- A bare `*` copies every label. A bare `*` is not allowed in
  `pod_annotations`.
- An empty entry is not allowed.
- Duplicate and overlapping entries are allowed. A key that matches more than
  one entry is copied one time.
- `max_copied_keys` applies to labels and to annotations separately.
- The signer copies the exact keys first. Wildcard matches fill the remaining
  places in sorted key order.
- The number of different exact entries in `pod_labels`, and separately in
  `pod_annotations`, must not be greater than `max_copied_keys`. Otherwise the
  signer does not start.
- `workload.omitted.labels` and `workload.omitted.annotations` count the
  matched keys that are not in the record.

### Limits

- `max_value_length` counts bytes. The signer cuts a longer value at a UTF-8
  character boundary and appends `...[truncated]`. The limit applies to label
  values, annotation values, supplied values and the denial or failure
  message.
- `max_record_bytes` limits one line, including its newline. When a line is
  longer, the signer removes the copied annotations first. If the line is
  still too long, it removes the labels, then the supplied values. It counts
  what it removed in `workload.omitted.annotations`,
  `workload.omitted.labels` and `workload.omitted.suppliedValues`.
- The signer never removes the identity, certificate and issuer fields. If the
  line is still too long, the signer writes it whole and sets
  `workload.omitted.overBudget` to `true`.
- A limit never denies or delays a request.

### Supplied values

`request.suppliedKeys` names the certificate configuration annotations that
the requester supplied, for example `example.com/pod-signer-san`. By default
the record does not hold their values. Set `audit.record_supplied_values` to
`true` to add them as `request.suppliedValues`. The values come from the
requester. Enable this only when your audit log may keep requester text.

## The record

The signer writes each record as one line. This example is a `signed` record,
shown on several lines. The configuration is the one from
[Select labels and annotations](#select-labels-and-annotations), without
`pod-template-hash`.

```json
{
  "kind": "CertificateAuditRecord",
  "schemaVersion": "v1",
  "ts": "2026-11-20T09:15:02.118Z",
  "event": "signed",
  "reason": "CertificateIssued",
  "signerName": "example.com/pod-signer",
  "request": {
    "namespace": "payments",
    "name": "pcr-7xk2q",
    "uid": "0b6f3c1e-5d2a-4f7b-9c1e-2a3b4c5d6e7f",
    "suppliedKeys": [
      "example.com/pod-signer-san"
    ]
  },
  "workload": {
    "pod": {
      "name": "api-6c9f7d5b8-x2lqp",
      "uid": "d4b0c7a2-8e1f-4a3b-b5c6-7d8e9f0a1b2c"
    },
    "serviceAccount": {
      "name": "api",
      "uid": "5e2a9c10-3b4d-4e5f-8a6b-7c8d9e0f1a2b"
    },
    "node": {
      "name": "ip-10-0-3-17",
      "uid": "a81c5f0d-6e7f-4a8b-9c0d-1e2f3a4b5c6d"
    },
    "owner": {
      "apiVersion": "apps/v1",
      "kind": "ReplicaSet",
      "name": "api-6c9f7d5b8",
      "uid": "c3d9e8f1-2a3b-4c5d-8e6f-7a8b9c0d1e2f"
    },
    "labels": {
      "app.kubernetes.io/name": "api",
      "app.kubernetes.io/version": "1.2.3"
    },
    "annotations": {
      "example.com/owner": "team-payments"
    },
    "omitted": {
      "labels": 0,
      "annotations": 0
    }
  },
  "certificate": {
    "serialHex": "3fa91c0e77b2d4a8056e1f9c2b7d6a40",
    "serialDecimal": "84619430957250172514404220402520648256",
    "fingerprint": "X509SHA256=6b6b594029e086a3f31c51c726ac8b0035b31300730145c85dfd1193d33246c4",
    "commonName": "api-6c9f7d5b8-x2lqp",
    "dnsNames": [
      "api.payments"
    ],
    "ipAddresses": [],
    "uris": [],
    "extKeyUsage": [
      "serverAuth"
    ],
    "keyAlgorithm": "ECDSA",
    "notBefore": "2026-11-20T09:14:02Z",
    "notAfter": "2026-11-21T09:14:02Z",
    "sources": {
      "commonName": "default",
      "dnsNames": "pcr",
      "ipAddresses": "default",
      "uris": "default",
      "extKeyUsage": "default",
      "duration": "default",
      "refreshBefore": "default"
    }
  },
  "issuer": {
    "subject": "CN=pod-signer-ca",
    "serialHex": "ed2962977e51130e1960139ba14da262",
    "fingerprint": "X509SHA256=20a7532700378f1d6cc24ed55e2ce28a18b7803099a8e57b67ab2fa6b5399977"
  }
}
```

The `published` record that follows it is one line:

```json
{"kind":"CertificateAuditRecord","schemaVersion":"v1","ts":"2026-11-20T09:15:02.131Z","event":"published","reason":"StatusWritten","signerName":"example.com/pod-signer","request":{"namespace":"payments","name":"pcr-7xk2q","uid":"0b6f3c1e-5d2a-4f7b-9c1e-2a3b4c5d6e7f"},"certificate":{"serialHex":"3fa91c0e77b2d4a8056e1f9c2b7d6a40","serialDecimal":"84619430957250172514404220402520648256","fingerprint":"X509SHA256=6b6b594029e086a3f31c51c726ac8b0035b31300730145c85dfd1193d33246c4"}}
```

Field details:

- `ts` is the time the signer built the record, in RFC 3339 UTC with
  milliseconds. `notBefore` is 1 minute before the signing time, because the
  authority backdates each certificate.
- `serialHex` is lowercase hex with no separators and no leading zeros.
  `serialDecimal` is the same integer in base 10.
- `fingerprint` is the SHA-256 of the DER certificate, in the Kubernetes
  credential-id form `X509SHA256=<lowercase hex>`.
- A serial is unique only within one issuer. Scope a serial query by
  `issuer.fingerprint`.
- `workload.owner` is absent when the pod has no controller owner. It names
  the direct owner only. After a ReplicaSet or Job is pruned, the owner name no
  longer resolves. For a StatefulSet or DaemonSet pod, it does not name a
  revision. Copy revision labels, such as `pod-template-hash`, as hints.
- `workload.labels: {}` means that no pod key matched. An absent
  `workload.labels` means that `max_record_bytes` removed it. The same applies
  to `workload.annotations`.
- `request.suppliedKeys` is `[]` when the requester supplied no keys. It is
  absent from follow-up records.
- `certificate.sources` tells where each configurable field came from: `pcr`
  (the request `spec.unverifiedUserAnnotations`), `pod` (the deprecated pod
  annotation fallback), `csr` (the kubelet CSR) or `default` (the signer
  default).
- `message` is only in `denied` and `failed` records. It is the condition
  message, cut to `max_value_length`.

### Trust of each field

| Field | Source | Trust |
| --- | --- | --- |
| `request` namespace, name, uid | PodCertificateRequest metadata | Set by the API server |
| `request.suppliedKeys` | Names of the signer configuration annotations that the requester supplied | Requester input. Names only by default. |
| `request.suppliedValues` | Raw values of those annotations, only with `record_supplied_values` | Requester input |
| `workload.pod`, `serviceAccount`, `node` | PodCertificateRequest spec. The signer also checks the live pod UID and deletion state. | Depends on the admission and RBAC rules for request creation in the cluster, including NodeRestriction |
| `workload.owner` | Controller ownerReference of the live pod | Observed metadata. The signer does not check that the owner exists. |
| `workload.labels`, `annotations` | Live pod, by the configured entries | Workload owner input. Not identity. |
| `message` | Terminal condition message | Can hold requester text |
| `certificate` | Parsed from the DER that the authority produced | Signer output |
| `certificate.sources` | The annotation resolver | Signer output |
| `issuer` | The CA certificate that signed this certificate | Signer output |

## Events

| Event | Reason | When the signer writes it | Groups |
| --- | --- | --- | --- |
| `signed` | `CertificateIssued` | After signing, before the Issued status write. Nothing is published yet. | `request`, `workload`, `certificate`, `issuer` |
| `published` | `StatusWritten` | The Issued status write persisted. It also persisted when a conflict re-read found this certificate already in place. | `request` identity, serials, fingerprint |
| `superseded` | `OtherWriterWon` | Another terminal outcome is on the same request UID | Same as `published` |
| `superseded` | `RequestGone` | The request was deleted or replaced before the write | Same as `published` |
| `superseded` | `WriteRejected` | The API server refused the write with a definite 4xx error. The request requeues. | Same as `published` |
| `unknown` | `WriteAmbiguous` | A timeout, a cancelled context, a 5xx or 429 error, a failed re-read, or conflicts that outlast the retries. The write may be committed. The request requeues. | Same as `published` |
| `denied` | The condition reason, `UnsupportedKeyType` or `InvalidUnverifiedUserAnnotations` | The Denied status write persisted | `request`, `workload`, `message`. No `certificate` or `issuer`. |
| `failed` | `SigningFailed` | The Failed status write persisted | Same as `denied` |

A dropped request and a requeue before signing write no record.

### Read a sequence

Group records by `request.uid`. Then match each follow-up record to its
`signed` record by `certificate.fingerprint`.

- `signed`, then `published`: the API server accepted this certificate.
- `signed`, then `superseded`: this certificate was not published.
- `signed`, then `unknown`: the write may be committed. Check the API server
  audit log.
- `signed` with no follow-up: the state is unknown. Treat it as `unknown`. The
  process may have stopped after the write, or the sink dropped the
  follow-up record.
- Several `signed` records for one `request.uid`, each with its own
  fingerprint: a `superseded` (`WriteRejected`) or `unknown` record requeues
  the request. The next reconcile can sign again with a new serial. It does
  not sign when it sees the request already terminal. After a leader change,
  the new leader can also sign a request that the old leader signed. At most
  one of these certificates is published.
- `unknown` for one certificate, then `superseded` (`OtherWriterWon`) for a
  later certificate of the same `request.uid`: the earlier certificate can be
  the one that was published. The ambiguous write committed, and the next
  reconcile read the request from a cache that did not yet show the Issued
  condition. Check the earlier
  fingerprint in the API server audit log.
- A follow-up record with no `signed` record: the sink dropped the `signed`
  record. Look for the drop on the operational log.
- `denied` or `failed`: the request reached that terminal outcome. No
  certificate exists for it.

## Ship the records

Collect stdout of the signer container, `pod-certificate-signer`, from every
replica. The code of the signer writes nothing else to stdout. A repository
test checks this for the code under `cmd/` and `internal/`.

In the log backend:

- Filter records on the fields that the collector adds: the cluster, the
  namespace of the release and the container name. Do not filter on `kind`
  alone. A tenant container can print a line with the same `kind` into a
  shared backend. If the collector keeps the stream name, also filter on
  `stdout`.
- Keep nested JSON fields nested. When a collector flattens the record, a
  label key can produce a field name that looks like a top-level field.
- Not verified: how collectors handle long lines and lines that the container
  runtime splits into partial records. Check that the longest records arrive
  whole. The default `max_record_bytes` is 16384.

For a quick look without a log backend, read the current containers with
`kubectl logs`. It merges stdout and stderr, so select the records with `jq`.
It shows only the logs that the nodes still keep.

```sh
kubectl logs -n pcs-system -l app.kubernetes.io/name=pod-certificate-signer --tail=-1 \
  | jq -R -c 'fromjson? | select(.kind? == "CertificateAuditRecord")'
```

## Find a workload from a serial or fingerprint

These queries read records as one JSON object per line, in a file
`records.jsonl`. Adapt them to the query language of your log backend.

With a fingerprint, find every record of the certificate:

```sh
FP='X509SHA256=6b6b594029e086a3f31c51c726ac8b0035b31300730145c85dfd1193d33246c4'
jq -c --arg fp "$FP" \
  'select(.kind == "CertificateAuditRecord" and .certificate.fingerprint? == $fp)' records.jsonl
```

With a serial, find the `signed` record first. Only `signed` records carry
`issuer`, so the issuer scope works only there. Then use its fingerprint in
the query above.

```sh
SERIAL='3fa91c0e77b2d4a8056e1f9c2b7d6a40'
ISSUER='X509SHA256=20a7532700378f1d6cc24ed55e2ce28a18b7803099a8e57b67ab2fa6b5399977'
jq -c --arg s "$SERIAL" --arg i "$ISSUER" \
  'select(.kind == "CertificateAuditRecord" and .event == "signed"
    and .certificate.serialHex == $s and .issuer.fingerprint == $i)' records.jsonl
```

### Values from other sources

Before you compare a serial, convert it to the record form: lowercase hex,
no colons, no leading zeros. Before you compare a SHA-256 fingerprint, remove
colons, convert it to lowercase and add the prefix `X509SHA256=`.

```sh
serial_hex() { printf '%s' "$1" | tr -d ':' | tr 'A-F' 'a-f' | sed 's/^0*//'; }
serial_hex '3F:A9:1C:0E:77:B2:D4:A8:05:6E:1F:9C:2B:7D:6A:40'
# 3fa91c0e77b2d4a8056e1f9c2b7d6a40
```

| Source | Serial | Fingerprint |
| --- | --- | --- |
| Go `x509.Certificate` | `SerialNumber.String()` prints decimal. Compare it with `serialDecimal`. | Compute SHA-256 over `Raw` and compare the hex with the record. |
| OpenSSL | `openssl x509 -noout -serial` prints uppercase hex after `serial=`, with a leading zero when the digit count is odd. Convert it, then compare it with `serialHex`. | `openssl x509 -noout -fingerprint -sha256` prints uppercase hex with colons after `Fingerprint=`. Convert it. |
| Envoy | `%DOWNSTREAM_PEER_SERIAL%`. Convert it, then compare it with `serialHex`. | `%DOWNSTREAM_PEER_FINGERPRINT_256%`. Not verified against the record. `%DOWNSTREAM_PEER_FINGERPRINT_1%` is SHA-1 and cannot match. |
| NGINX | `$ssl_client_serial`. Convert it, then compare it with `serialHex`. | `$ssl_client_fingerprint` is SHA-1 and cannot match. Use the serial and the issuer. |

The OpenSSL row and the conversion were checked with OpenSSL 4.1.0.

Not verified: the exact serial casing and padding in deployed Envoy and NGINX
versions. The conversion above handles case, colons and leading zeros. Scope
an Envoy or NGINX serial by the issuer. For example, compare the issuer DN
with `issuer.subject`. The DN text format can differ between these sources and
the record.

## The second trail

Use the API server audit log to check the status write behind a `published`
record, an `unknown` record or a missing record. Add this rule to the API server audit policy, before any rule that
matches the same requests at a lower level:

```yaml
- level: RequestResponse
  resources:
    - group: certificates.k8s.io
      resources: ["podcertificaterequests/status"]
```

Join an audit event to a record with these rules:

1. Match on the cluster, and on `responseObject.metadata.uid` equal to
   `request.uid`.
2. Match the first certificate in `responseObject.status.certificateChain`
   to `certificate.fingerprint`. The chain is PEM text. Decode the first PEM
   block to DER, then take the SHA-256 of the DER. For example:
   `openssl x509 -outform der | sha256sum` reads the first certificate of a
   PEM chain on stdin.
3. Accept only an event at stage `ResponseComplete`, with a success status
   code, without dry-run, on the `status` subresource, with the Issued
   condition in the response.
4. Use the namespace and name only as a search index. A 409 also writes an
   audit event, and a new request can reuse a name.
5. A missing or incomplete audit event means unknown, not "not published".
   Audit export can be off, filtered or truncated.

On managed clusters you cannot set the audit policy. According to the policies
that EKS, GKE and AKS publish, they record this write at `RequestResponse`.
EKS export is off by default. AKS needs a diagnostic setting. Not verified: no
live managed cluster was inspected for the audit level or for whether the
event keeps the full response body.

## Volume estimate

Each projected podCertificate volume has its own PodCertificateRequest. Each
issued certificate writes two lines, `signed` and `published`. Kubelet starts
the refresh at `beginRefreshAt`, which is `refresh` before expiry. With the
defaults (`duration` 24h, `refresh` 15m), the refresh interval is about 23h45m.

```text
lines per day ≈ projections × (24h / refresh interval) × 2
              + new projections from pod starts per day × 2
              + denials and failures
              + 2 for each new signing after a WriteRejected or unknown record
```

In a test build, a `signed` record with two labels and one annotation was
1,620 bytes. A follow-up record was 481 bytes. A `denied` record with a
227-byte message was 1,113 bytes. Your sizes depend on the copied keys and
SANs.

Example: 1,000 running pods with one projection each, default lifetimes and
no pod starts. That is about 1,011 issuances and 2,021 lines a day, about
2.1 MB a day. In a cluster with many pod starts, the pod start term is
usually the largest.
