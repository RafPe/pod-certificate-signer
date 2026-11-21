// Content for the interactive audit page. The wording follows docs/auditing.md;
// keep both in step when either changes.

export type Tone = 'ok' | 'quiet' | 'warn' | 'stop' | 'focus' | 'neutral';

export interface State {
  id: string;
  event: string;
  reason?: string;
  tone: Tone;
  verdict?: string;
  when: string;
  groups?: string;
  read: string;
  anchor: string;
}

export const states: State[] = [
  {
    id: 'reconcile',
    event: 'Reconcile',
    tone: 'neutral',
    when: 'The leader reconciles a PodCertificateRequest for the configured signer name.',
    read: 'A request that the signer ignores because its pod is gone or being deleted writes no record. A requeue before signing writes no record.',
    anchor: 'events',
  },
  {
    id: 'signed',
    event: 'signed',
    reason: 'CertificateIssued',
    tone: 'focus',
    when: 'After signing, before the Issued status write. Nothing is published yet.',
    groups: 'request, workload, certificate, issuer',
    read: 'Match each follow-up record to its signed record by certificate.fingerprint. A signed record with no follow-up means the state is unknown: treat it as unknown. The process may have stopped after the write, or the sink dropped the follow-up record.',
    anchor: 'read-a-sequence',
  },
  {
    id: 'published',
    event: 'published',
    reason: 'StatusWritten',
    tone: 'ok',
    verdict: 'Published',
    when: 'The Issued status write persisted. The signer also writes published when a conflict re-read finds this certificate already in place.',
    groups: 'request identity, serials, fingerprint',
    read: 'signed, then published: the API server accepted this certificate.',
    anchor: 'events',
  },
  {
    id: 'other-writer-won',
    event: 'superseded',
    reason: 'OtherWriterWon',
    tone: 'quiet',
    verdict: 'Not published',
    when: 'Another terminal outcome is on the same request UID.',
    groups: 'request identity, serials, fingerprint',
    read: 'signed, then superseded (OtherWriterWon): this certificate was not published. Exception: after an unknown record for an earlier certificate of the same request.uid, that earlier certificate can be the one that was published.',
    anchor: 'read-a-sequence',
  },
  {
    id: 'request-gone',
    event: 'superseded',
    reason: 'RequestGone',
    tone: 'warn',
    verdict: 'Verify',
    when: 'The request no longer exists. It was deleted or replaced before the write. The certificate is not published to any request that still exists.',
    groups: 'request identity, serials, fingerprint',
    read: 'In one narrow case, a retried write can have committed before the deletion. Kubelet may already have read the committed certificate. This case was reasoned from the behaviour of the client library and was not reproduced. Treat RequestGone for a pod that existed at that time as possibly published, and check the API server audit log.',
    anchor: 'read-a-sequence',
  },
  {
    id: 'write-rejected',
    event: 'superseded',
    reason: 'WriteRejected',
    tone: 'quiet',
    verdict: 'Not published',
    when: 'The API server refused the write with 400, 401, 403 or 422. The request requeues.',
    groups: 'request identity, serials, fingerprint',
    read: 'signed, then superseded (WriteRejected): this certificate was not published. The next reconcile can sign again with a new serial.',
    anchor: 'read-a-sequence',
  },
  {
    id: 'unknown',
    event: 'unknown',
    reason: 'WriteAmbiguous',
    tone: 'warn',
    verdict: 'Verify',
    when: 'A timeout, a cancelled context, a 5xx error or a 429 error. Or a 4xx error that is not 400, 401, 403, 404, 409 or 422. Or a failed re-read, or conflicts that outlast the retries. The request requeues.',
    groups: 'request identity, serials, fingerprint',
    read: 'signed, then unknown: the write may be committed. Check the API server audit log.',
    anchor: 'the-second-trail',
  },
  {
    id: 'denied',
    event: 'denied',
    reason: 'The condition reason: UnsupportedKeyType or InvalidUnverifiedUserAnnotations',
    tone: 'stop',
    verdict: 'No certificate',
    when: 'The Denied status write persisted.',
    groups: 'request, workload, message. No certificate or issuer.',
    read: 'The request reached that terminal outcome. No certificate exists for it. message is the condition message, cut to max_value_length, and can hold requester text.',
    anchor: 'events',
  },
  {
    id: 'failed',
    event: 'failed',
    reason: 'SigningFailed',
    tone: 'stop',
    verdict: 'No certificate',
    when: 'The Failed status write persisted.',
    groups: 'request, workload, message. No certificate or issuer.',
    read: 'The request reached that terminal outcome. No certificate exists for it.',
    anchor: 'events',
  },
];

export interface Sequence {
  id: string;
  label: string;
  steps: { text: string; tone: Tone; note?: string }[];
  tone: Tone;
  verdict: string;
  detail: string;
}

export const sequences: Sequence[] = [
  {
    id: 'published',
    label: 'signed → published',
    steps: [{ text: 'signed', tone: 'focus' }, { text: 'published', tone: 'ok' }],
    tone: 'ok',
    verdict: 'Published',
    detail: 'The API server accepted this certificate.',
  },
  {
    id: 'not-published',
    label: 'signed → superseded',
    steps: [{ text: 'signed', tone: 'focus' }, { text: 'superseded', tone: 'quiet', note: 'OtherWriterWon or WriteRejected' }],
    tone: 'quiet',
    verdict: 'Not published',
    detail: 'This certificate was not published.',
  },
  {
    id: 'request-gone',
    label: 'signed → RequestGone',
    steps: [{ text: 'signed', tone: 'focus' }, { text: 'superseded', tone: 'warn', note: 'RequestGone' }],
    tone: 'warn',
    verdict: 'Possibly published',
    detail: 'The request no longer exists, and the certificate is not published to any request that still exists. In one narrow case a retried write committed before the deletion. For a pod that existed at that time, treat it as possibly published and check the API server audit log.',
  },
  {
    id: 'unknown',
    label: 'signed → unknown',
    steps: [{ text: 'signed', tone: 'focus' }, { text: 'unknown', tone: 'warn', note: 'WriteAmbiguous' }],
    tone: 'warn',
    verdict: 'May be committed',
    detail: 'The write may be committed. Check the API server audit log.',
  },
  {
    id: 'no-follow-up',
    label: 'signed, nothing after',
    steps: [{ text: 'signed', tone: 'focus' }, { text: 'no follow-up', tone: 'neutral' }],
    tone: 'warn',
    verdict: 'Unknown',
    detail: 'Treat it as unknown. The process may have stopped after the write, or the sink dropped the follow-up record.',
  },
  {
    id: 'several-signed',
    label: 'several signed, one uid',
    steps: [{ text: 'signed', tone: 'focus', note: 'fingerprint A' }, { text: 'requeue', tone: 'neutral' }, { text: 'signed', tone: 'focus', note: 'fingerprint B' }],
    tone: 'neutral',
    verdict: 'At most one published',
    detail: 'A superseded (WriteRejected) or unknown record requeues the request, and the next reconcile can sign again with a new serial. It does not sign when it sees the request already terminal. After a leader change, the new leader can also sign a request that the old leader signed.',
  },
  {
    id: 'unknown-then-other',
    label: 'unknown, then OtherWriterWon',
    steps: [{ text: 'unknown', tone: 'warn', note: 'certificate A' }, { text: 'superseded', tone: 'quiet', note: 'OtherWriterWon · certificate B' }],
    tone: 'warn',
    verdict: 'Earlier one may be published',
    detail: 'The earlier certificate can be the one that was published. The ambiguous write committed, and the next reconcile read the request from a cache that did not yet show the Issued condition. Check the earlier fingerprint in the API server audit log.',
  },
  {
    id: 'orphan',
    label: 'follow-up, no signed',
    steps: [{ text: 'missing', tone: 'neutral' }, { text: 'published', tone: 'ok', note: 'or another follow-up' }],
    tone: 'neutral',
    verdict: 'signed record lost',
    detail: 'The sink can have dropped the signed record, or the collector can have lost it. A record that the sink drops while a write is blocked is only counted on the operational log. It does not appear by name.',
  },
  {
    id: 'terminal',
    label: 'denied or failed',
    steps: [{ text: 'denied', tone: 'stop', note: 'or failed' }],
    tone: 'stop',
    verdict: 'No certificate',
    detail: 'The request reached that terminal outcome. No certificate exists for it.',
  },
];

export type Trust = 'api' | 'requester' | 'observed' | 'signer';

export const trustLevels: { id: Trust; label: string; detail: string }[] = [
  { id: 'api', label: 'Set by the API server', detail: 'PodCertificateRequest metadata: namespace, name and uid.' },
  { id: 'observed', label: 'Cluster rules and observed metadata', detail: 'Pod, service account and node come from the request spec. Their trust depends on the admission and RBAC rules for request creation, including NodeRestriction. The owner is the controller ownerReference of the live pod, and the signer does not check that the owner exists.' },
  { id: 'requester', label: 'Requester or workload-owner input', detail: 'Supplied annotation keys and values, copied labels and annotations, and the denial or failure message. Not identity.' },
  { id: 'signer', label: 'Signer output', detail: 'Parsed from the DER that the authority produced, the annotation resolver and the issuing CA certificate.' },
];
