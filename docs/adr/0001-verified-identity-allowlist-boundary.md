---
status: accepted
date: 2026-08-17
decision-makers: RafPe
---

# Bound the verified-identity allowlist to identities the signer emits, plus the service-account short DNS form and SPIFFE ID

## Context and Problem Statement

Since [#26](https://github.com/RafPe/pod-certificate-signer/issues/26) /
[#38](https://github.com/RafPe/pod-certificate-signer/issues/38) the signer
enforces a default-deny identity model. Every `cn`, `san` and `uris` value —
literal or `${...}`-interpolated — must be an exact string member of the set
returned by `verifiedIdentities`
(`internal/kubernetes/podcertificate/podcertificate.go:505-548`), computed
solely from the apiserver-verified fields of the `PodCertificateRequest`. The
exact-equality check is what closes literal-injection loopholes such as
`${pod.name}.attacker.com`.

That set currently contains:

- for the pod: `<pod>`, `<pod>.<ns>`, `<pod>.<ns>.pod`, `<pod>.<ns>.svc`,
  `<pod>.<ns>.pod.<fqdn>`, `<pod>.<ns>.svc.<fqdn>`, and
  `spiffe://<fqdn>/ns/<ns>/pod/<pod>`;
- for the service account: `<sa>.<ns>` and
  `spiffe://<fqdn>/ns/<ns>/sa/<sa>`.

The asymmetry is visible: the pod gets `.svc` and `.svc.<fqdn>` forms, the
service account does not. Two things forced the question.

1. [#87](https://github.com/RafPe/pod-certificate-signer/issues/87) asks for
   `--enable-annotation-interpolation` to default on, so that per-pod
   SPIFFE-style identity works out of the box.
2. `examples/workload-pod.yaml` — the repository's flagship example, referenced
   from the docs and applied by the e2e suite — requests
   `${pod.serviceAccountName}.${pod.namespace}.svc`, which resolves to
   `<sa>.<ns>.svc` and is **denied** under the default configuration. The e2e
   suite masks this by installing with both `allow_unverified_identities=true`
   and `enable_annotation_interpolation=true`, so the failure has never been
   observed in CI.

So there are two ways to make the example issue: widen the allowlist with the
service-account `.svc` / `.svc.<fqdn>` forms, or keep the allowlist as it is and
fix the example. That choice governs the identity model, and nothing in the repo
records which way it should go.

There is a second problem this decision solves. Nothing in the repository states
what the allowlist's boundary *is* — only what it currently contains. Without a
stated rule, the allowlist grows one plausible-looking entry at a time, each
justified locally, until it no longer denies anything meaningful.

## Decision

**The verified-identity allowlist contains exactly two categories, and nothing
else:**

**(a) The identities the signer itself emits by default.** `defaultPodDNSNames`
(`podcertificate.go:486-496`) emits `<pod>.<ns>.pod.<fqdn>` and
`<pod>.<ns>.svc.<fqdn>`; `defaultCommonName` emits `<pod>`. Whatever the signer
will put into a certificate on its own must be claimable explicitly, or the
annotation path would be stricter than the default path — a contradiction. The
shorter pod forms (`<pod>.<ns>`, `<pod>.<ns>.pod`, `<pod>.<ns>.svc`) and the pod
SPIFFE ID are the search-path and SPIFFE spellings of the same emitted names.

**(b) The service account's short DNS form `<sa>.<ns>` and its SPIFFE ID
`spiffe://<fqdn>/ns/<ns>/sa/<sa>`.** The pod runs as this service account, so it
may identify by it.

**The service-account Service DNS forms `<sa>.<ns>.svc` and
`<sa>.<ns>.svc.<fqdn>` are deliberately excluded**, and so are the corresponding
`.pod` forms. Reasons, strongest first:

1. **They would let a pod claim a real Service's DNS name.**
   `<name>.<ns>.svc.<fqdn>` is exactly the Kubernetes *Service* record shape.
   ServiceAccount names and Service names are independent within a namespace —
   nothing prevents a ServiceAccount `api` in namespace `prod` while a Service
   `api` in `prod` fronts a different team's workload. Granting the form means
   any pod running as that service account can present a valid server
   certificate for `api.prod.svc.cluster.local`, the exact name a strict TLS
   client dials and verifies. This directly contradicts the project's own
   documented threat model: the "Identity constraints" section of
   `docs/configuration.md` names **`kubernetes.default.svc`** as the canonical
   example of what the constraint exists to deny — and a
   ServiceAccount named `kubernetes` in namespace
   `default` would make precisely that claimable. Decisive on its own.
2. **The name resolves to nothing, so it buys the workload nothing.**
   Kubernetes DNS publishes no record for a ServiceAccount. A certificate
   asserting `<sa>.<ns>.svc` can never be validated against a connection a
   client actually opened by that name — pure risk, zero interoperability value.
3. **The service-account identity already has two correct forms.** The SPIFFE
   URI is *exactly* what #87 asks for; the reporter's own example is
   `spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}`.
   Nothing in #87 requires a service-account-derived DNS name.
4. **The asymmetry with the pod forms is principled, not an oversight.** The
   signer never emits any service-account-derived DNS name. Widening the
   allowlist past what the signer will emit on its own is the thing to avoid.

**Non-goals.** This ADR does not change any signer behavior — the allowlist
already matches the rule above. It does not decide the fate of
`examples/workload-pod.yaml`, nor the default of
`--enable-annotation-interpolation`; both are separate changes that this
boundary constrains. It says nothing about `--allow-unverified-identities`,
which lifts the allowlist entirely and is an explicit operator decision.

**Recorded caveat, deliberately not acted on.** The already-allowed `<sa>.<ns>`
carries a weaker version of the same hazard. From inside a pod, `api.prod`
(1 dot, below the default `ndots:5`) resolves through the resolver search path
to `api.prod.svc.cluster.local` — i.e. the Service. So the collision risk is not
*created* by the service-account forms; it is *amplified* by adding the
fully-qualified ones, which turn an ambiguous search-path artifact into an
unambiguous, canonical, SNI-matching claim. This argues for narrowing `<sa>.<ns>`
later, never for widening now. Narrowing it is a breaking change and belongs in
its own issue and ADR.

## Consequences

* Good, because the allowlist now has a stated boundary rather than a list of
  contents. "Does the signer emit this name itself?" is a question a reviewer can
  answer, so a future addition has to argue against a rule instead of merely
  looking plausible.
* Good, because per-pod service-account identity has one blessed spelling — the
  SPIFFE URI — which is also what #87 asked for.
* Good, because the decision is locked by characterization tests
  (`TestServiceAccountServiceDNSFormsDenied`,
  `TestServiceAccountSPIFFEIDAccepted`), so a future "just add `.svc`" patch
  turns red with a pointer here rather than merging quietly.
* Bad, because `examples/workload-pod.yaml` stays broken until it is fixed
  separately: it requests `<sa>.<ns>.svc`, which this decision confirms is
  denied. The example is now provably wrong rather than ambiguously wrong.
* Bad, because an operator who genuinely wants a service-account-derived
  `.svc` name has no path except `--allow-unverified-identities`, which lifts
  every constraint at once rather than just this one. Accepted: the name
  resolves to nothing, so the demand should be rare, and a narrow opt-in for it
  would be a worse trade than the escape hatch.
* Follow-up: open an issue for the `<sa>.<ns>` search-path hazard described in
  the caveat above.
* Follow-up: `examples/workload-pod.yaml` must be changed to request the
  service-account SPIFFE ID instead of `<sa>.<ns>.svc`, and the e2e suite must
  stop masking the denial with `allow_unverified_identities=true`.

## Implementation Plan

* **Affected paths**:
  * `internal/kubernetes/podcertificate/podcertificate.go` —
    `verifiedIdentities` (`:505-548`) is the sole implementation of this
    decision. The "Deliberately excluded" comment on its `if sa != ""` branch
    names the excluded forms and cites this ADR.
  * `internal/kubernetes/podcertificate/identity_constraints_test.go` — the
    characterization tests that lock it.
* **Dependencies**: none.
* **Patterns to follow**: identity checks go through `assertVerifiedIdentity`
  against the map `verifiedIdentities` returns. Comparison is exact string
  equality — never prefix, suffix, or pattern matching, which is what makes
  `${pod.name}.attacker.com` fail.
* **Patterns to avoid**: do not add an entry to `verifiedIdentities` that the
  signer does not itself emit, unless an amendment to this ADR argues the case.
  Do not relax the exact-equality comparison. Do not "fix" a denied example by
  turning on `--allow-unverified-identities`.

### Verification

- [x] `verifiedIdentities` contains no `<sa>.<ns>.svc` or `<sa>.<ns>.pod` entry,
      in either bare or FQDN-suffixed form.
- [x] `go test ./internal/kubernetes/podcertificate/... -run ServiceAccount`
      passes, covering both the denial of the four service-account Service/pod
      DNS forms and the acceptance of the service-account SPIFFE ID.
- [x] The `if sa != ""` branch of `verifiedIdentities` carries a comment naming
      the excluded forms and citing this ADR.
- [ ] A future allowlist addition either satisfies rule (a) or ships with an
      amendment to this ADR.

## Alternatives Considered

* **Add `<sa>.<ns>.svc` and `<sa>.<ns>.svc.<fqdn>` to the allowlist.** Rejected:
  it makes a real Service's canonical DNS name claimable by any pod running as a
  same-named service account, which is the precise attack
  the "Identity constraints" section of `docs/configuration.md` cites as the
  reason the constraint exists.
* **Add the forms but only when no Service of that name exists in the
  namespace.** Rejected: it makes issuance depend on mutable cluster state the
  signer would have to watch, turns a deterministic check into a TOCTOU race
  (create the certificate, then create the Service), and requires the controller
  to gain read access to Services — a trust-boundary expansion out of proportion
  to a name that resolves to nothing anyway.
* **Leave the allowlist undocumented and fix the example quietly.** Rejected:
  the same question would be re-litigated the next time someone reads the
  asymmetry as a bug, which is how #87 surfaced in the first place.

## More Information

* Issue [#87](https://github.com/RafPe/pod-certificate-signer/issues/87) —
  `--enable-annotation-interpolation` on by default; the trigger for this ADR.
* Issues [#26](https://github.com/RafPe/pod-certificate-signer/issues/26),
  [#38](https://github.com/RafPe/pod-certificate-signer/issues/38) — introduced
  the default-deny identity model.
* Issue [#48](https://github.com/RafPe/pod-certificate-signer/issues/48) and PR
  [#80](https://github.com/RafPe/pod-certificate-signer/pull/80) — routed CSR
  DNS SANs through the same allowlist, so this boundary now governs the CSR path
  too.
* `docs/configuration.md` — "Identity constraints" documents the resulting
  user-visible behavior.

**Revisit if**: Kubernetes publishes DNS records for ServiceAccounts (removing
reason 2); or the signer begins emitting a service-account-derived DNS name by
default (making it fall under rule (a)); or the `<sa>.<ns>` search-path hazard
is judged severe enough to narrow the allowlist, which would supersede this ADR
rather than amend it.
