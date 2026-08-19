# Architecture Decision Records (ADR)

An Architecture Decision Record captures a decision that shapes how this signer
is built or operated, together with the context that forced it and the
consequences it carries. The record exists so that the next person — or the next
agent — reading the code can find the reasoning without reconstructing it from
git history.

See [CONTRIBUTING.md](../../CONTRIBUTING.md#architecture-decision-records) for
when an ADR is required and how one is reviewed.

## Conventions

- Directory: `docs/adr/`
- Naming: `NNNN-title-with-dashes.md`, zero-padded sequential number, lowercase
  slug.
- Status lives in YAML front matter: `proposed`, `accepted`, `rejected`,
  `deprecated`, or `superseded by [ADR-NNNN](NNNN-slug.md)`.
- A rejected ADR is kept, not deleted. The record of what was considered and
  turned down is the point.
- Code governed by an ADR should carry a short `ADR-NNNN` comment at the
  relevant entry point, so the reasoning is discoverable from the code.

## ADRs

| ADR | Title | Status |
| --- | ----- | ------ |
| [0001](0001-verified-identity-allowlist-boundary.md) | Bound the verified-identity allowlist to identities the signer emits, plus the service-account short DNS form and SPIFFE ID | Accepted |
| [0002](0002-annotation-interpolation-on-by-default.md) | Ship `--enable-annotation-interpolation` on by default | Accepted |
| [0005](0005-bounded-metrics-surface.md) | Expose a bounded metrics surface, and never label a metric with a per-request identity | Proposed |
