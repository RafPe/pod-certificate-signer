# Architecture Decision Records (ADR)

An Architecture Decision Record (ADR) records one decision that shapes how this
signer is built or operated. It also records the context that forced the
decision and the consequences that follow from it. With the record, the next
person or agent that reads the code finds the reasoning without a search of the
git history.

[CONTRIBUTING.md](../../CONTRIBUTING.md#architecture-decision-records) tells
when a change needs an ADR and how a maintainer reviews it.

## Conventions

- Directory: `docs/adr/`
- Naming: `NNNN-title-with-dashes.md`, with a zero-padded sequential number and
  a lowercase slug.
- The YAML front matter holds the status: `proposed`, `accepted`, `rejected`,
  `deprecated`, or `superseded by [ADR-NNNN](NNNN-slug.md)`.
- Keep a rejected ADR. Do not delete it. The record of an option that the
  project considered and refused is the point.
- Put a short `ADR-NNNN` comment at the entry point of the code that an ADR
  governs. A reader of the code then finds the reasoning.
- Do not rewrite the history of an accepted ADR. Add a dated status update
  under `## More Information` when the code changes after the decision.

## ADRs

| ADR | Title | Status | Shipped in |
| --- | ----- | ------ | ---------- |
| [0001](0001-verified-identity-allowlist-boundary.md) | Bound the verified-identity allowlist to identities the signer emits, plus the service-account short DNS form and SPIFFE ID | Accepted | 2.3.0 (record only, no behavior change) |
| [0002](0002-annotation-interpolation-on-by-default.md) | Ship `--enable-annotation-interpolation` on by default | Accepted | 2.3.0 |
| [0003](0003-leaf-basic-constraints-ca-false.md) | Assert `basicConstraints` with `cA:FALSE` on issued leaf certificates | Accepted | 2.4.0 |
| [0004](0004-bootstrapped-previous-ca-history.md) | Bound and validate the previous-CA history bootstrapped from the ClusterTrustBundle | Accepted | 2.4.0 |
| [0005](0005-bounded-metrics-surface.md) | Expose a bounded metrics surface, and never label a metric with a per-request identity | Accepted | 2.4.0 |
| [0006](0006-release-leader-lease-on-cancel.md) | Release the leader Lease on a voluntary shutdown | Accepted | 3.0.1 |
| [0007](0007-issuance-audit-record.md) | Write a best-effort issuance audit record to stdout | Proposed | Not released |

Next: read [CONTRIBUTING.md](../../CONTRIBUTING.md#when-an-adr-is-required) to
find out when a change needs a new ADR.
