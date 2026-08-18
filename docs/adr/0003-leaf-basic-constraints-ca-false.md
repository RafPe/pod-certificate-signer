---
status: proposed
date: 2026-08-18
decision-makers: RafPe
---

# Assert `basicConstraints` with `cA:FALSE` on issued leaf certificates

## Context and Problem Statement

The signing template in `internal/kubernetes/authority/authority.go` (`Sign`) set
neither `BasicConstraintsValid` nor `IsCA`:

```go
template := &x509.Certificate{
    SerialNumber: serialNumber,
    Subject:      pkix.Name{CommonName: pcConfig.CommonName},
    DNSNames:     pcConfig.DNSNames,
    // ... no BasicConstraintsValid, no IsCA
}
```

`crypto/x509.CreateCertificate` emits the basicConstraints extension only when
`BasicConstraintsValid` is true, so **issued leaves carried no basicConstraints
extension at all**. This surfaced in the Stage 3 e2e work, which set out to
assert `cA:FALSE` on every leaf and found there was nothing to assert; the
assertion it settled on pinned the *absence*
(`test/e2e/key_semantics_test.go`, `expectConformantLeaf`).

**This is not a vulnerability, and this record is not a fix for one.** The
absence is standards-conformant:

- RFC 5280 4.2.1.9 states the extension **MAY** appear in end-entity
  certificates. Only CA certificates **MUST** carry it.
- RFC 5280 6.1.4 path validation refuses to treat a certificate as a CA unless
  basicConstraints is present with `cA:TRUE`. Go's verifier implements exactly
  that, and it is the verifier the signer's own e2e chain checks run through.
  A leaf issued by this signer therefore cannot be used to sign further
  certificates when validated by a conforming implementation.
- Current CA/Browser Forum Baseline Requirements treat basicConstraints as
  **optional** for subscriber certificates rather than mandatory. An earlier
  internal note claimed the BRs require it; that overstated the position and is
  corrected here so the overstatement does not get cited back.

The argument for asserting it anyway is that "conforming implementation" is a
weaker guarantee inside a Kubernetes cluster than it looks on paper. The signer
issues credentials consumed by whatever TLS stack a workload happens to link:
Go, OpenSSL, BoringSSL, Java, Python, Rust, and vendored copies of all of them,
at whatever version the workload image pins. Path-validation leniency around a
missing basicConstraints has a long history of implementation bugs. The signer
cannot enumerate its verifiers, so it should not rely on all of them being
strict.

The certificate profile is also read by people. A leaf that states its
end-entity status is auditable in one `openssl x509 -text`; a leaf that omits
the extension requires the reader to know RFC 5280 6.1.4 before they can
conclude anything from what is not there.

## Decision

**Set `BasicConstraintsValid: true` on the leaf template and leave `IsCA` at its
zero value**, so every issued certificate carries a basicConstraints extension
asserting `cA:FALSE`.

**No `pathLenConstraint`.** It is meaningful only when `cA` is true, and some
verifiers treat the combination with `cA:FALSE` as malformed.

**The extension is emitted critical**, which is what `crypto/x509` does
unconditionally for basicConstraints — the criticality is not a separate
decision the template can express. It is also the right encoding, for reasons
recorded under Alternatives Considered.

Worth knowing before someone "corrects" the test: DER omits a field encoded at
its DEFAULT, and `cA` is `BOOLEAN DEFAULT FALSE` with `pathLenConstraint`
`OPTIONAL`. The emitted extension value is therefore an **empty SEQUENCE**
(`30 00`). There is no explicit `FALSE` byte to find; `openssl x509 -text`
still prints `CA:FALSE`, and that empty SEQUENCE is the strongest single thing
to assert on, because it pins both the value and the absent `pathLenConstraint`
without depending on any parser's sentinel for "unset".

**Non-goals.** Nothing here touches the identity model, the verified-identity
allowlist, key usage, extended key usage, SANs, or lifetimes. This record
governs only how an issued certificate describes its own end-entity status. It
does not supersede [ADR-0001](0001-verified-identity-allowlist-boundary.md).

**Release classification: patch, `Security`.** The classification records
hardening, not a fixed vulnerability. No capability is granted and none is
removed.

## Consequences

* Good, because issued certificates state their end-entity status explicitly
  instead of relying on every verifier to infer it from an absence. A verifier
  with a lenient or buggy path-validation implementation can no longer be
  induced to treat a workload credential as a CA.
* Good, because the profile becomes self-describing and therefore auditable
  without a spec lookup.
* Neutral, because a conforming verifier — Go's included — already refused to
  treat these leaves as CAs. For that population nothing changes at all, which
  is precisely why this is not classified as a fix.
* Bad, because every issued certificate changes shape. The extension is a
  handful of bytes and universally understood, so the compatibility risk is
  low, but it is not zero: a consumer pinning an exact certificate fingerprint
  or DER length sees a change on the next issuance. Certificates are
  short-lived (24h default) and rotate constantly, so such a consumer is
  already broken by rotation; this only makes the breakage arrive sooner.
* Bad, because the e2e assertion that pinned the absence had to be inverted in
  the same change or the suite goes red. That coupling is the point of the
  assertion existing — it is what caught the profile change — but it does mean
  the record and the test must move together.

## Implementation Plan

* **Affected paths**:
  * `internal/kubernetes/authority/authority.go` — `BasicConstraintsValid: true`
    on the `Sign` template. `IsCA` is deliberately *not* written: the pair of a
    present extension and a false `cA` is what produces `cA:FALSE`, and a
    comment at the field says so, with the `ADR-0003` reference.
  * `internal/kubernetes/authority/authority_test.go` —
    `TestSignAssertsBasicConstraintsCAFalse`.
  * `test/e2e/key_semantics_test.go` — `expectConformantLeaf`, the assertion
    that pinned the absence.
* **Dependencies**: none. This does not rest on the allowlist boundary or on
  any flag.
* **Patterns to follow**: assert on the certificate parsed back from DER, never
  on the template. The template is the request; the DER is the artifact the
  workload is handed, and only one of the two is evidence.
* **Patterns to avoid**: do not add `MaxPathLen` / `MaxPathLenZero` to the
  template to "complete" the extension. Do not reach for `ExtraExtensions` to
  hand-encode the extension — the template field is sufficient and the
  hand-rolled DER would have to be maintained against the same spec Go already
  implements.

### Verification

- [x] A freshly issued leaf, parsed from DER, has `BasicConstraintsValid` true
      and `IsCA` false (`TestSignAssertsBasicConstraintsCAFalse`).
- [x] `pathLenConstraint` is absent: `MaxPathLen` is `-1` and `MaxPathLenZero`
      is false (same test). Go's parser reports `-1`, not `0`, for an absent
      constraint — the assertion was written against the observed value.
- [x] The extension with OID 2.5.29.19 is present, critical, and carries an
      empty SEQUENCE (same test, walking `cert.Extensions` — `x509.Certificate`
      exposes no typed field for basicConstraints criticality).
- [ ] The e2e conformance helper requires the extension's presence on every
      issued leaf across the key-type matrix
      (`test/e2e/key_semantics_test.go`, `expectConformantLeaf`).

## Alternatives Considered

* **Leave it absent.** Standards-conformant, zero risk, zero work, and it is
  what shipped until now. Rejected because the cost of the alternative is a
  handful of bytes and one template field, while the benefit is not depending
  on the correctness of TLS stacks the signer does not choose and cannot
  enumerate.
* **Emit it non-critical.** Rejected on two counts. First, it is not
  expressible: `crypto/x509` marks basicConstraints critical unconditionally,
  so non-critical would mean hand-building the DER in `ExtraExtensions` and
  bypassing the template field entirely. Second, and decisively, it would be
  the wrong choice even if it were free — non-critical is exactly the encoding
  a *lenient* verifier is licensed to skip, and lenient verifiers are the entire
  population this change exists for. The usual argument for non-critical, that
  a verifier which cannot process a critical extension rejects the certificate
  outright, does not apply here: RFC 5280 4.2.1.9 already requires
  basicConstraints critical on CA certificates, so any verifier able to
  validate a chain at all must process it.
* **Set `pathLenConstraint: 0`.** Meaningless with `cA:FALSE`, and some
  verifiers treat the combination as malformed. Rejected.
* **Assert it only for some requests, behind a flag.** Rejected. A certificate
  profile that varies per request is harder to reason about than either
  profile on its own, and there is no configuration for which the extension is
  the wrong answer.

## More Information

* RFC 5280 4.2.1.9 (Basic Constraints) and 6.1.4 (path validation).
* Found by the Stage 3 e2e work. `test/e2e/key_semantics_test.go`,
  `expectConformantLeaf`, now requires the extension's presence; before this
  record it pinned the absence, with a comment saying that any extension
  appearing there must be reviewed and must carry `cA:FALSE`. This is that
  review.
* [ADR-0001](0001-verified-identity-allowlist-boundary.md) — the identity
  boundary. Untouched here; listed so the two are not confused, since both
  concern what an issued certificate may say.
* `CONTRIBUTING.md`'s "When an ADR is required" list does not literally name
  an unconditional change to certificate contents — its closest entry is *a
  flag that gates what ends up in a certificate*, and this change is not
  behind a flag. The record exists anyway because it changes what every
  certificate the signer issues contains, and that reasoning should outlive
  the pull request that carried it.

**Revisit if**: a verifier is found that rejects a leaf carrying a critical
basicConstraints (which would reopen the criticality question, and would be
worth reporting upstream); or the CA/Browser Forum Baseline Requirements move
basicConstraints from optional to required for subscriber certificates, which
would turn this from a judgement call into a conformance obligation.
