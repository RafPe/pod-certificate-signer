---
status: proposed
date: 2026-08-18
decision-makers: RafPe
---

# Ship `--enable-annotation-interpolation` on by default

## Context and Problem Statement

A `cn`, `san` or `uris` value is authored on a pod template, so it is byte-identical
for every replica the template produces. The signer's `${...}` interpolation
(`internal/kubernetes/podcertificate/podcertificate.go`, `interpolate` /
`interpolationVars`) exists because of that: `${pod.name}` is the only way to write
a per-pod identity into a shared Deployment at all, and `${pod.namespace}` /
`${cluster.fqdn}` are the only way to write a manifest that is correct in more than
one namespace or cluster.

It has shipped **off**. Turning it on is a CLI flag
(`--enable-annotation-interpolation`) or a Helm value
(`signer.enable_annotation_interpolation`), and until an operator finds it, the
signer's headline capability — a certificate carrying the pod's own verified
identity — is only reachable through the controller's *defaults*, never through the
annotation contract. Ask for anything by name and you get the pod name, nothing else.

Two things forced the question.

1. [#87](https://github.com/RafPe/pod-certificate-signer/issues/87) asks for the
   default to flip so that per-pod SPIFFE-style identity works out of the box. The
   reporter's example is
   `spiffe://${cluster.fqdn}/ns/${pod.namespace}/sa/${pod.serviceAccountName}`.
2. `examples/workload-pod.yaml`, the repository's flagship example, is written
   entirely in `${...}`. Copied onto a default install it was denied — for two
   reasons, in fact: the disabled flag, and (until #87's example fix) an identity
   the pod did not own. The example was never runnable as documented.

The flag is also widely mistaken for a security control, which is what makes the
flip look bigger than it is. It is not one. That confusion is what this record has
to settle before the default can move.

## Decision

**`--enable-annotation-interpolation` defaults to `true`, and the chart value
`signer.enable_annotation_interpolation` defaults to `true` with it.** Setting
either to `false` remains fully supported and restores the previous behaviour:
a value containing `${` is denied outright rather than resolved.

**This grants no identity that was not already obtainable.** Two properties, both
pre-existing and neither changed here, make that true:

1. **Placeholders resolve only from verified fields.** `interpolationVars` reads
   `pod.name`, `pod.namespace`, `pod.uid`, `pod.serviceAccountName` and `node.name`
   from the `PodCertificateRequest` spec — fields kubelet populates and
   kube-apiserver verifies — plus `cluster.fqdn` from the operator's own
   `--cluster-fqdn`. No user-controlled input reaches the table, and expansion is a
   single non-recursive pass.
2. **The resolved value faces the same check as a literal one.** Every expanded
   `cn`, `san` and `uris` value must be an exact string member of the set
   `verifiedIdentities` returns, whose boundary is
   [ADR-0001](0001-verified-identity-allowlist-boundary.md). The comparison is
   membership by exact string equality and does not care how the string was
   produced — which is why `${pod.name}.evil.example.com` is denied even with the
   flag on.

So the set of certificates a pod can obtain is identical before and after this
change. What changes is the *syntax* available for naming a member of that set.
**The security gate is `--allow-unverified-identities`**, which lifts the allowlist
entirely and stays off by default. This flag was never that gate, and the flip does
not make it one.

**Release classification: minor, not major.** Nothing that works today stops
working — the flag only ever gated input syntax, and no configuration depends on
`${...}` being *rejected* in a way the flip breaks. Requests previously denied now
succeed, but only for identities the pod provably owns. It is a usability change,
not a security relaxation.

**Non-goals.** This does not touch `verifiedIdentities`, the exact-equality
comparison, the interpolation variable table, or `--allow-unverified-identities`.
It does not deprecate `EnableInterpolation: false`, which stays a supported
configuration with its own tests and its own e2e install profile.

## Consequences

* Good, because the annotation contract is usable as documented on an unmodified
  install: `examples/workload-pod.yaml` and the interpolation examples in
  `docs/configuration.md` now describe what a reader actually gets.
* Good, because the reachable-by-default posture is the *narrow* one. Previously
  the only default-reachable way to put a chosen name into a certificate was
  `--allow-unverified-identities`, which lifts every constraint at once;
  interpolation reaches exactly the pod's own identity and nothing else. Making the
  bounded mechanism the default makes the unbounded one less tempting.
* Neutral, because the identity model is untouched. A denial that fired before the
  flip because the value was not the pod's still fires after it, with the same
  message.
* Bad, because a `${...}` value that is *malformed* (an unknown variable, an
  unterminated placeholder) now denies the request where it used to deny it for a
  different reason. The reason string changes; the outcome does not. An operator
  who relied on the blanket "`${` is denied" behaviour as a crude admission control
  must set `signer.enable_annotation_interpolation: false` explicitly.
* Bad, because the default now lives in two places — the binary constant and the
  chart value — and the chart is the interface almost everyone uses. Mitigated by
  `TestChartInterpolationDefaultMatchesBinary`, which fails if they diverge.
* The default-off behaviour loses its status as the shipped configuration but keeps
  its coverage: `TestInterpolationDisabledRejectsPlaceholders`, the disabled rows of
  `TestInterpolate`, and a dedicated e2e install profile that sets the value to
  `false` explicitly.

## Implementation Plan

* **Affected paths**:
  * `cmd/podcertificate-signer/main.go` — `defaultEnableAnnotationInterpolation`,
    the named constant the flag registration reads. The flag is registered inside
    `main()`, so a constant is what makes the default assertable at all.
  * `charts/pod-certificate-signer/values.yaml` —
    `signer.enable_annotation_interpolation`. `templates/deployment.yaml` renders
    the flag unconditionally, so `false` still reaches the controller as `=false`.
  * `internal/kubernetes/podcertificate/podcertificate.go` — **unchanged**. The
    flip is a default, not a behaviour: `Options.EnableInterpolation` is a struct
    field the controller passes through, and nothing in the package reads a flag
    default.
* **Dependencies**: [ADR-0001](0001-verified-identity-allowlist-boundary.md) — the
  argument that the flip adds no issuable identity rests on the allowlist boundary
  that ADR records. Also `examples/workload-pod.yaml` had to stop requesting a
  denied identity first, or the flip would have surfaced a second, unrelated denial.
* **Patterns to follow**: a default that is stored twice gets a drift-guard test.
  A property that only holds because two tests in different packages compose gets
  the coupling written into both comments.
* **Patterns to avoid**: do not remove the `EnableInterpolation: false` tests or
  the interpolation-disabled e2e profile — the opt-out is supported, not
  deprecated. Do not set `--set signer.enable_annotation_interpolation=true` in the
  e2e install profiles: while it is the chart default, that `--set` would mask a
  regression of the default rather than detect it.

### Verification

- [x] `defaultEnableAnnotationInterpolation` is `true` and is what
      `flag.BoolVar` receives (`TestAnnotationInterpolationEnabledByDefault`).
- [x] The chart value agrees with the binary constant
      (`TestChartInterpolationDefaultMatchesBinary`).
- [x] `helm template` with no overrides renders
      `--enable-annotation-interpolation=true`, and
      `--set signer.enable_annotation_interpolation=false` renders `=false`
      (`TestDeploymentRendersInterpolationEnabledByDefault`).
- [x] `examples/workload-pod.yaml` resolves to a valid configuration with
      `AllowUnverifiedIdentities: false`
      (`hygiene.TestWorkloadPodExampleIssuesUnderIdentityConstraints`).
- [x] The disabled path still denies `${...}`
      (`TestInterpolationDisabledRejectsPlaceholders`, and the e2e
      `interpolation-disabled` install profile).
- [ ] The e2e suite passes with `--set signer.enable_annotation_interpolation`
      appearing in exactly one install profile, `interpolation-disabled`, where
      it is set to `false`. No profile sets it to `true`.

## Alternatives Considered

* **Keep it off and document it harder.** Rejected: the flag has been documented in
  `docs/configuration.md`, `SECURITY.md`, the chart README and the example header
  the whole time, and the flagship example still shipped un-runnable. When the
  documented happy path requires a flag, the flag is the wrong default.
* **Classify the flip as `major`.** Rejected: `major` is for a broken guarantee or
  a removed capability. Nothing that works stops working, no guarantee weakens, and
  the previous behaviour is one value away. Reserving `major` for real breakage is
  what keeps it informative — the last `major` (`allow_unverified_identities`
  defaulting off) genuinely stopped working configurations from issuing.
* **Flip `--enable-annotation-interpolation` and `--allow-unverified-identities`
  together, so literal values work out of the box too.** Rejected outright, and
  worth recording because the two are habitually discussed as a pair. They are
  opposites: interpolation names an identity the pod owns, the escape hatch removes
  the requirement that it own one.
* **Remove the flag entirely and always interpolate.** Rejected for now: the
  disabled path is a real, if crude, admission control for operators who want
  `${` rejected at the signer, it costs one branch to keep, and removing a flag is
  a breaking change that would have to argue its own case. Revisit if the opt-out
  turns out to be unused.

## More Information

* Issue [#87](https://github.com/RafPe/pod-certificate-signer/issues/87) — the
  request this record answers.
* [ADR-0001](0001-verified-identity-allowlist-boundary.md) — the verified-identity
  allowlist boundary the "no new issuable identity" argument rests on. Its
  follow-up list names both the example fix and the removal of the e2e's
  `allow_unverified_identities` masking.
* `docs/configuration.md` — "Interpolating pod identity into values" and
  "What bounds interpolation" document the user-visible behaviour.

**Revisit if**: the interpolation variable table gains an entry that does not come
from an apiserver-verified request field (which would break the argument above at
its root); or `--enable-annotation-interpolation=false` is found to have no users
and the flag becomes a candidate for removal.
