---
status: proposed
date: 2026-11-20
decision-makers: RafPe
---

# Write a best-effort issuance audit record to stdout

## Context and Problem Statement

A relying party logs the serial number or the fingerprint of a peer
certificate. An investigator reads that log hours later. By then the pod can be
deleted, the certificate expired and the Deployment rolled. The investigator
must find the pod that requested the certificate.

Before this decision, the signer gave no way to join a serial to a workload:

- The authority generated the serial and did not return it.
- The `issued certificate` log line has the PodCertificateRequest name and
  namespace, the pod name, the common name, the SANs and `notAfter`. It has no
  serial, fingerprint, pod UID, ServiceAccount, node, owner or issuing CA.
- Kubernetes Events expire after 1 hour by default.
- kube-controller-manager deletes a PodCertificateRequest 15 minutes after its
  creation (checked on Kubernetes v1.37).
- A pod name does not identify a rollout revision.

The join must work on every cluster. This includes managed clusters where the
operator cannot set the API server audit policy. The signer must not add API
calls or RBAC to do it.

## Decision

The signer writes an **issuance audit record**: one JSON line on stdout for
each signing attempt and for each terminal outcome. The operational log stays
on stderr. Each record has `"kind": "CertificateAuditRecord"` and
`"schemaVersion": "v1"`, so a reader can tell it apart when a collector merges
the two streams. The record is on by default (`audit.enabled: true`).

A record joins these facts at the time of the request:

- the PodCertificateRequest namespace, name and UID
- the pod, ServiceAccount and node, each with its name and UID
- the controller owner of the live pod, and pod labels and annotations that the
  operator selects
- the certificate serial in hex and in decimal, its SHA-256 fingerprint, and
  its subject, SANs, extended key usages and validity
- the source of each configurable certificate field (`pcr`, `pod`, `csr` or
  `default`)
- the subject, serial and fingerprint of the issuing CA certificate

[docs/auditing.md](../auditing.md) gives the full field list, the trust of
each field and the limits.

### Events and emit order

| Event | When the signer writes it | Meaning |
| --- | --- | --- |
| `signed` | After `Sign` returns, before the Issued status write | The signer created this certificate. Nothing is published yet. |
| `published` | After the Issued status write persisted | The API server accepted this certificate for this request UID. |
| `superseded` | After the Issued status write ended without this certificate in place | This certificate was not published. The reason tells why. `RequestGone` has one narrow exception, described below. |
| `unknown` | After the Issued status write returned an error that does not prove failure | The write may be committed. The API server audit log decides. |
| `denied` | After the Denied status write persisted | The request was denied. The record has no certificate or issuer. |
| `failed` | After the Failed status write persisted | The request failed. Same shape as `denied`. |

Rules:

- The signer writes the `signed` record before the status write. Thus every
  certificate that the API server can accept already has its full record.
- `published`, `superseded` and `unknown` are follow-up records. They carry
  the request identity, the serials and the fingerprint of a `signed` record.
- `superseded` has three reasons. `OtherWriterWon` means another terminal
  outcome is on the same request UID. `WriteRejected` means the API server
  refused the write with 400, 401, 403 or 422. The next item describes
  `RequestGone`.
- `RequestGone` means the request no longer exists: it was deleted or
  replaced. The certificate is not published to any request that still
  exists. In one narrow case, a write can have committed before the request
  was deleted. The client library retries a write after a lost response. The
  retry then gets a 404, or a 409 and a re-read that finds no request. This
  case was reasoned from the behaviour of the client library and was not
  reproduced. A reader treats `RequestGone` for a pod that existed at that
  time as possibly published. The reader checks the API server audit log, as
  for `unknown`.
- `unknown` has the reason `WriteAmbiguous`. The write returned a timeout, a
  cancelled context, a 5xx error or a 429 error. Or it returned a 4xx error
  that is not 400, 401, 403, 404, 409 or 422. Or the re-read failed, or the
  conflicts outlasted the retries.
- When a conflict re-read of the same request UID shows the Issued condition
  with this reconcile's own certificate chain, the event is `published`. The
  earlier write committed and its response was lost.
- A `signed` record with no later record has an unknown state. A reader treats
  it the same as `unknown`.
- `denied` and `failed` come from the code path that runs only when the
  write persisted. A reconcile that lost the race writes nothing.
- A rejected or ambiguous write requeues the request. The next reconcile can
  sign again with a new serial, and that attempt gets its own `signed` record.
  It does not sign when it sees the request already terminal.
- A request that the signer ignores because its pod is gone or being deleted
  writes no record. A requeue before signing writes no record.
- The signer writes every record with a context that a cancelled reconcile
  does not cancel.

### Stream and sink

- One writer goroutine owns stdout. The sink encodes a record completely and
  then makes one write. Concurrent reconciles never write a partial line.
- A record waits at most 2 seconds for the write. After that the reconcile
  continues. A blocked stdout therefore cannot stall the reconcile workers or
  use up the 30-second shutdown window of
  [ADR-0006](0006-release-leader-lease-on-cancel.md).
- The sink does not follow a context. `main` closes it after the manager
  stopped, so records that reconciles write during shutdown still reach
  stdout.
- The sink reports each dropped record on the operational log, with its event,
  request identity and fingerprint. While a write is blocked past the timeout,
  the sink only counts the records it drops. It logs the count when the write
  returns or when the sink closes.

### Guarantee

The record is **best-effort**. The signer writes it to stdout and gets no
acknowledgement that a collector stored it.

A delivered certificate can have no stored record, or only its `signed`
record, in these four cases:

1. The stdout write fails, or the sink drops the record. The sink drops a
   record in these cases:
   - The record does not encode.
   - The writer does not take it within 2 seconds.
   - An earlier write is blocked past the 2-second timeout.
   - The sink is closed.
2. The signer node is lost before the collector ships the line.
3. `audit.enabled` is `false`.
4. The process stops between a persisted status write and the follow-up
   record. The certificate then has only its `signed` record.

A Denied or Failed outcome can also have no record. This occurs when its write
result was ambiguous or rejected and the next reconcile found the request
already terminal. It also occurs when the write conflicted and the re-read
found a terminal condition, which can be this reconcile's own committed write.

The API server audit log is the second trail for these cases. It is also
best-effort on managed clusters. The Issued condition message in the audited
status write carries the serial and the fingerprint as text, in the form of the
record, so a search needs no PEM parsing. A guarantee that no certificate is
published without a stored record needs a durable sink that acknowledges
before the status write. That is out of scope.

### Non-goals

- No change to certificate contents.
- No per-identity metric labels. The decision adds no metric, so
  [ADR-0005](0005-bounded-metrics-surface.md) is unchanged.
- No new API call and no new RBAC. The record uses the pod that the signer
  already reads for the signing decision.
- No durable sink, no webhook sink and no CRD.
- No reuse of the `k8s.io/apiserver` audit stack.
- No resolution of a pod to its Deployment, CronJob or other ancestor.
- No proof that a pod received or used a certificate. A committed status makes
  the certificate available to kubelet. Receipt is a separate fact.

## Consequences

**Positive.** An investigator can join a serial or a fingerprint to the
request, the pod UID, the ServiceAccount, the node and the pod owner. This
works on every cluster and needs no API server configuration. The record also
names where each certificate field came from. This matters because the
deprecated pod-annotation fallback is on by default.

**Negative.** The record adds two lines of stdout for each issued certificate,
plus lines for denials, failures and retries. The operator must collect stdout
and keep it. The record is not tamper-evident. A tenant container can print a
line with the same `kind`, so a query must filter on the source fields that the
collector adds. Labels, annotations, supplied values and the denial message
are requester or workload-owner input, not identity.

**Neutral.** The decision does not change issuance, the identity model, the
trust boundary, the RBAC or the metrics surface. Two status write behaviours
changed with it, because the record needs to know the result of each write:

- An Issued write whose conflict re-read finds its own committed certificate is
  now reported as issued, with its Kubernetes Event and metric. Before, the
  reconcile reported a lost race.
- A status write that returns 404 because the request was deleted no longer
  requeues.

Two visible outputs also changed:

- The Issued condition message and its Kubernetes Event carry the serial and
  the fingerprint of the certificate.
- The `issued certificate` log line carries `serial` and `fingerprint`.

## Alternatives Considered

| | Approach | Result |
| --- | --- | --- |
| A | Use only the API server audit log, with a `RequestResponse` rule for `podcertificaterequests/status` | Kept as the second trail. Not sufficient alone: export is off by default on EKS, the event has no owner, and the serial and the fingerprint are plain text only in the Issued condition message that this signer version writes. |
| B | The signer writes its own JSON record to stdout | Chosen. |
| C | Embed the `k8s.io/apiserver` audit backends and write `audit.k8s.io/v1` events | Rejected. It is a heavy dependency for the signer. Its policy file has nothing to match on, because a controller has no HTTP request path. |
| D | Create one CRD object for each issuance | Rejected. It adds etcd load for each pod on each rotation, and it needs a retention controller. |

## More Information

- Operator guide: [docs/auditing.md](../auditing.md). It gives the
  configuration, the record and the events. It also tells how to collect the
  records and query them by serial or fingerprint. It gives the API server
  audit policy rule, the join rules and a volume estimate.
- Implementation: the record, the builder and the limits are in
  [`internal/audit/`](../../internal/audit/record.go). The stdout sink is
  [`internal/audit/sink.go`](../../internal/audit/sink.go). The emit points are
  in [`internal/controller/audit.go`](../../internal/controller/audit.go). The
  write results are in
  [`internal/controller/status.go`](../../internal/controller/status.go).
- `test/hygiene/stdout_test.go` fails when other code writes to stdout.
- Not verified: live audit events on EKS, GKE and AKS, and whether they keep
  the full response body for this write. The exact serial format in deployed
  Envoy and NGINX versions. Collector behaviour for long lines and partial
  records.
- Related: [ADR-0005](0005-bounded-metrics-surface.md) and
  [ADR-0006](0006-release-leader-lease-on-cancel.md).
