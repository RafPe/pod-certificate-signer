---
status: proposed
date: 2026-08-18
decision-makers: RafPe
---

# Bound and validate the previous-CA history bootstrapped from the ClusterTrustBundle

## Context and Problem Statement

The signer keeps a rolling window of the CAs that were current before the one it
holds now, so workloads still presenting a certificate from a retired CA keep
verifying while their certificates drain. That window is published in the
`ClusterTrustBundle` and — because the controller keeps no other record of it —
is read back out of the same object at startup
(`loadPreviousCAHistory` / `fetchPreviousCAs` in `cmd/podcertificate-signer/main.go`,
seeded through `authority.WithPreviousCABundle`).

The bundle is therefore both the controller's output and its only memory. Three
consequences follow, and none of them were handled.

1. **The bundle is not the controller's private state.** It is a cluster-scoped
   object, and the seed was adopted verbatim: whatever the bundle contained
   became the in-memory history, was published again on the next reconcile, and
   was read back as authoritative on the restart after that. A rewritten bundle
   laundered into controller-endorsed history — an edit that would otherwise be
   repaired by the next drift-repair publish instead became permanent.

2. **The configured bound was not applied to it.** `--max-previous-ca-certs`
   was enforced only in `authority.load`'s rotate branch, so a bundle carrying
   more entries than the bound kept all of them until the next rotation, and
   published a window larger than the operator configured.

3. **Absence was silently equated with "no history".** A `NotFound` read
   returned an empty history with a nil error. Delete the bundle, restart the
   controller, and the retained CAs were gone permanently: the controller
   republishes a bundle holding only the current CA, and every certificate
   issued under a retired CA stops verifying — without an error anywhere,
   because from the controller's point of view this is exactly what a first
   install looks like.

This is not a privilege escalation. Whoever can write the `ClusterTrustBundle`
can already write it, and this controller cannot stop them. The defect is that
the controller *converted a self-correcting edit into permanent state* and gave
it its own endorsement.

## Decision

**Treat the bootstrapped history as untrusted input: normalize it against the
same rules the controller applies to history it built itself, and make the
meaning of an absent bundle an explicit, operator-visible choice.**

1. **Normalize on every load** (`authority.normalizePreviousCertificates`).
   An entry is retained only if it is a usable signing CA — `BasicConstraintsValid`,
   `IsCA`, `KeyUsageCertSign`, not expired — which is the same check the material
   on disk must pass to become the current CA. Entries are then de-duplicated by
   certificate identity, the current CA is removed, and the result is trimmed to
   `--max-previous-ca-certs`. Every drop is logged.

2. **Order the history by identity and recency, not by insertion.** A
   certificate occupies at most one slot, and re-observing it moves that slot
   rather than adding another. Trimming happens *after* the current CA and the
   duplicates have been removed, so a rotation that returns to a known CA cannot
   evict one whose certificates are still in the field.

3. **A missing bundle is reported as absence, not as an empty history**
   (`errCAHistoryBundleAbsent`), and is not retried — retrying cannot make an
   absent object appear. By default startup continues with an empty history and
   says so loudly; `--require-ca-history` (chart: `signer.require_ca_history`)
   turns absence into a startup failure.

### Why the provenance check stops where it does

The controller cannot prove that a certificate offered as history was ever its
own CA. It holds one key pair — the current one — and keeps no signed record of
its predecessors, so any check it applies to a previous CA is structural, not
cryptographic. Anything it *could* write to make the check cryptographic (an
annotation, a signature, a second object) would sit next to the same bundle and
be writable by the same people.

So the boundary is drawn where it is actually enforceable: the controller
refuses to carry certificates that could not verify anything it issued (not a
CA, cannot sign, expired) and refuses to carry more than it was configured to,
and it declines to claim more than that.

### Why `--require-ca-history` defaults to off

A bundle that never existed and one that was deleted are the same observation.
Failing closed by default would crash-loop every first install; starting empty
by default makes a deleted bundle a permanent loss. The default keeps the
install path working and the flag gives the fail-closed behaviour to operators
who know their signer has published before — which is every installation past
its first minute.

## Consequences

- A `ClusterTrustBundle` edited by hand no longer becomes permanent history: the
  entries that survive a restart are the ones that pass validation and fit inside
  the configured bound, and the drift-repair publish rewrites the rest.
- The published bundle can shrink on the first restart after this change, if the
  bundle in the cluster held more (or more unusable) entries than the bound
  allows. That is the bound being enforced; raise `--max-previous-ca-certs`
  before restarting if the extra anchors are genuinely still needed.
- An expired CA is dropped from the history. It could not validate anything, and
  the slot it held is returned to a CA that can.
- Absence of the bundle stays non-fatal by default, so a deleted bundle can still
  lose history on an install that has not enabled `--require-ca-history`. The
  startup log says so explicitly, and `docs/operations.md` tells operators to
  turn the flag on.
- The rolling window remains a time-bounded safety net, not an archive: it is
  still the operator's job to leave at least one certificate lifetime between
  rotations.

## Alternatives Considered

- **Fail closed on absence by default.** Correct for every cluster except a
  brand-new one, and there is no way to tell those apart from inside the
  controller. It would make `helm install` crash-loop until an operator found a
  flag to turn off.
- **Have the chart create an empty `ClusterTrustBundle`,** so absence would
  unambiguously mean "not installed". It would break `helm upgrade` on every
  existing installation: the bundle already exists and is not owned by the
  release, so Helm refuses to adopt it. That is a breaking change to the install
  path, for a diagnostic.
- **Persist the history in a second object the controller owns** (a ConfigMap or
  Secret in the release namespace). It removes the ambiguity, at the cost of new
  RBAC, a new failure mode, and a second copy of the trust state to keep
  consistent with the published one. Rejected as disproportionate to the problem;
  worth revisiting if history loss is observed in practice.
- **Pin history to a lineage** (e.g. require a previous CA to share the current
  CA's subject). It reads like provenance but is not: an operator may legitimately
  rotate to a CA with a different subject, and an attacker writing the bundle can
  copy a subject. It would reject valid rotations while stopping nothing.
- **Keep insertion order and only add the missing trim.** It fixes the bound but
  leaves the eviction defect: a rotation flapping between two known CAs still
  spends retention slots on certificates already in the window and evicts one
  that is still needed.

## More Information

- `internal/kubernetes/authority/authority.go` — `normalizePreviousCertificates`,
  `validateCACertificate`, `WithPreviousCABundle`.
- `cmd/podcertificate-signer/main.go` — `loadPreviousCAHistory`,
  `errCAHistoryBundleAbsent`, `--require-ca-history`.
- `docs/operations.md` — rotation runbook and the operator-facing guidance for
  `signer.require_ca_history`.
- [#30](https://github.com/RafPe/pod-certificate-signer/issues/30) — the earlier
  fix that made a *read error* fail closed, which this record extends to what the
  read returns.
