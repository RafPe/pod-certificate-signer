# Contributing to pod-certificate-signer

Thanks for taking the time to contribute! Bug reports, feature requests and
pull requests are all welcome.

## Prerequisites

- **Go 1.26+** (see `go.mod` for the exact version)
- **Docker** (or another container tool via `CONTAINER_TOOL=podman`)
- **make**

All other tooling — `controller-gen`, `golangci-lint`, `kind`, `helm`,
`setup-envtest` — is pinned in `internal/tools/go.mod` and invoked through
`go tool` by the Makefile. You do not need to install anything else manually.

## Development workflow

1. Create a branch off `main` (fork first if you don't have push access).
2. Make your changes, including tests for new behavior.
3. Run the checks below before opening a pull request.

Useful make targets (`make help` shows the full list):

| Target                 | What it does                                                          |
| ---------------------- | --------------------------------------------------------------------- |
| `make fmt` / `make vet` | Format the code and run `go vet`                                      |
| `make lint`            | Run `golangci-lint` (`make lint-fix` applies fixes)                    |
| `make generate`        | Regenerate DeepCopy code after changing API types                      |
| `make test`            | Run unit tests with envtest (Kubernetes control-plane binaries are downloaded automatically) |
| `make test-e2e`        | Run the e2e suite against a throwaway kind cluster (`pcs-e2e`)         |
| `make build`           | Build the manager binary into `bin/`                                   |
| `make run`             | Run the controller locally against your current kubeconfig             |
| `make docker-build`    | Build the OCI image (`IMAGE=<repo:tag>` to override)                   |

### Local cluster with kind

The repository ships a kind configuration (`kind/kind-config.yaml`) pinning a
Kubernetes 1.37 node image, where the `PodCertificateRequest` and
`ClusterTrustBundle` APIs the controller needs are GA in
`certificates.k8s.io/v1` and served by default:

| Target                 | What it does                                                          |
| ---------------------- | --------------------------------------------------------------------- |
| `make kind-start`      | Create the local dev cluster (`pcs-dev`)                               |
| `make kind-load-image` | Build the image and load it into the dev cluster                       |
| `make helm-deploy`     | Load the image and install the chart with the example CA secret and values |
| `make helm-uninstall`  | Remove the Helm release                                                |
| `make kind-stop`       | Tear the dev cluster down                                              |

## Pull requests

- Target the `main` branch.
- Keep PRs focused; smaller PRs are reviewed faster.
- Make sure `make test` and `make lint` pass.
- Update the README / chart docs when you change user-facing behavior.

### Release labels (required)

Releases are fully label-driven. **Every PR must carry exactly one
`release/*` label** — a required CI check
(`.github/workflows/pr-release-metadata.yml`) fails otherwise:

| Label           | Effect on the next prepared release                              |
| --------------- | ---------------------------------------------------------------- |
| `release/major` | Next release bumps the **major** version (breaking change)       |
| `release/minor` | Next release bumps the **minor** version (feature)               |
| `release/patch` | Next release bumps the **patch** version (fix)                   |
| `release/skip`  | No version or changelog impact                                   |

For every non-skip PR, add one or more `.changes/unreleased/*.yaml` files:

```yaml
kind: Fixed
body: Explain the user-visible change in one sentence.
```

Allowed kinds are `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
`Security`, and `Dependencies`. A `release/skip` PR must not add a fragment.
Ordinary merges never publish; maintainers explicitly prepare and approve a
generated release PR.

## Architecture Decision Records

Decisions that shape how the signer is built or operated are recorded in
[`docs/adr/`](docs/adr/README.md). The record exists so the reasoning survives
the pull request that carried it: a code comment explains what the code does, an
ADR explains why the alternative was turned down.

### When an ADR is required

Open one alongside the PR (or before it) when the change touches:

- **a default that affects issuance or security posture** — flipping
  `enable_annotation_interpolation`, `allow_unverified_identities`,
  `honor_csr_sans`, `metrics_secure`, or the default EKU set;
- **the identity model** — anything that widens or narrows
  `verifiedIdentities`, changes how a resolved value is compared against it, or
  adds an interpolation variable;
- **the trust boundary** — new RBAC, a new API the controller reads or writes,
  new inputs it treats as trusted, or a change to what reaches the CA key;
- **a flag that gates what ends up in a certificate** — subject, SANs, URIs,
  EKU, validity;
- **cluster-wide chart resources** — ClusterRoles, ValidatingAdmissionPolicies,
  ClusterTrustBundles, or anything else installed outside the release namespace;
- **anything carrying `release/major`.** A breaking change always warrants a
  record of what was broken and why.

Routine work inside an established pattern does not need one. Neither do bug
fixes, dependency bumps, or docs. If you find yourself writing a long code
comment that argues rather than describes, that argument belongs in an ADR.

### Lifecycle

An ADR is created as `proposed`, discussed on the PR, and then either `accepted`
or `rejected`. **A rejected ADR is kept, not deleted** — the record that an
option was considered and turned down is exactly what stops it being
re-proposed. A decision that is later replaced becomes
`superseded by [ADR-NNNN](NNNN-slug.md)`, with the new ADR linking back; one
that no longer applies but has no replacement becomes `deprecated` with the
reason stated. Status lives in the YAML front matter. Do not rewrite an accepted
ADR's history — append to `## More Information` instead.

### Review

**An ADR needs at least one approving maintainer review before it is merged as
`accepted`.** This is the one place in the project where a second pair of eyes
is not optional: ordinary PRs merge on green CI, but a decision that governs
future code should not be self-approved. An ADR may merge as `proposed` without
that review — it just does not bind anything until accepted.

Reference the ADR from the code it governs with a short `ADR-NNNN` comment at
the relevant entry point, and from the PR description.

## Reporting issues

Use the issue forms in this repository for bugs and feature requests. For
security vulnerabilities, please **do not** open a public issue — report them
privately via [GitHub security advisories](https://github.com/RafPe/pod-certificate-signer/security/advisories/new).

## Code of conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold it.
