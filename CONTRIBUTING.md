# Contributing to pod-certificate-signer

This project accepts bug reports, feature requests and pull requests.

## Prerequisites

- **Go 1.27+** (see `go.mod` for the exact version)
- **Docker** (or another container tool via `CONTAINER_TOOL=podman`)
- **make**

`internal/tools/go.mod` pins all other tools: `golangci-lint`, `kind`, `helm`
and `setup-envtest`. The Makefile runs them through `go tool`. You do not need
to install them yourself.

## Development workflow

1. Create a branch from `main`. If you do not have push access, fork the
   repository first.
2. Make your changes. Add tests for new behavior. If a test involves time,
   follow [`docs/testing/deterministic-time.md`](docs/testing/deterministic-time.md).
3. Run the checks in [Pull requests](#pull-requests) before you open a pull
   request.

Useful make targets (`make help` shows the full list):

| Target                 | What it does                                                          |
| ---------------------- | --------------------------------------------------------------------- |
| `make fmt` / `make vet` | Format the code and run `go vet`                                      |
| `make lint`            | Run `golangci-lint` (`make lint-fix` applies fixes)                    |
| `make test`            | Run the unit tests and the envtest controller suite. The target downloads the Kubernetes control-plane binaries |
| `make test-e2e`        | Run the per-PR e2e suite against a throwaway kind cluster (`pcs-e2e`)  |
| `make test-e2e-nightly` | Run the full e2e suite, including the specs labelled `nightly`        |
| `make build`           | Build the manager binary into `bin/`                                   |
| `make run`             | Run the controller locally against your current kubeconfig             |
| `make docker-build`    | Build the OCI image (`IMAGE=<repo:tag>` to override)                   |

### Local cluster with kind

The repository has a kind configuration (`kind/kind-config.yaml`). It pins a
Kubernetes 1.37 node image. In Kubernetes 1.37, the `PodCertificateRequest` and
`ClusterTrustBundle` APIs are GA in `certificates.k8s.io/v1`. The API server
serves them by default.

| Target                 | What it does                                                          |
| ---------------------- | --------------------------------------------------------------------- |
| `make kind-start`      | Create the local dev cluster (`pcs-dev`)                               |
| `make kind-load-image` | Build the image and load it into the dev cluster                       |
| `make helm-deploy`     | Load the image, generate an ephemeral dev CA into a Secret, and install the chart with `examples/helm-values.yaml` |
| `make helm-uninstall`  | Remove the Helm release                                                |
| `make kind-stop`       | Delete the dev cluster                                                 |

To verify a local install, follow
[Getting started](docs/getting-started.md#3-request-a-certificate-from-a-workload)
from step 3.

## Pull requests

- Target the `main` branch.
- Keep each PR on one subject. Maintainers review small PRs faster.
- Make sure `make test` and `make lint` pass.
- Update the README and the chart docs when you change user-facing behavior.

### Release labels (required)

Labels control releases. **Every PR must have exactly one `release/*`
label.** A required CI check (`.github/workflows/pr-release-metadata.yml`)
fails otherwise:

| Label           | Effect on the next prepared release                              |
| --------------- | ---------------------------------------------------------------- |
| `release/major` | Next release bumps the **major** version (breaking change)       |
| `release/minor` | Next release bumps the **minor** version (feature)               |
| `release/patch` | Next release bumps the **patch** version (fix)                   |
| `release/skip`  | No version or changelog impact                                   |

For every PR that is not `release/skip`, add one or more
`.changes/unreleased/*.yaml` files:

```yaml
kind: Fixed
body: Explain the user-visible change in one sentence.
```

The allowed kinds are `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`,
`Security`, and `Dependencies`. A `release/skip` PR must not add a fragment. An
ordinary merge does not publish a release. A maintainer prepares a release PR and
merges it to publish. [docs/releasing.md](docs/releasing.md) gives the
procedure.

## Architecture Decision Records

The project records decisions that shape how the signer is built or operated in
[`docs/adr/`](docs/adr/README.md). The record keeps the reasoning after the pull
request that carried it is merged. A code comment explains what the code does.
An ADR explains why the project refused the alternative.

### When an ADR is required

Open an ADR with the PR, or before it, when the change touches one of these:

- **a default that affects issuance or security posture**: a change to
  `enable_annotation_interpolation`, `allow_unverified_identities`,
  `honor_csr_sans`, `metrics.insecure` (`--metrics-secure`), or the default EKU
  set.
- **the identity model**: a change that widens or narrows
  `verifiedIdentities`, that changes how the signer compares a resolved value
  against it, or that adds an interpolation variable.
- **the trust boundary**: new RBAC, a new API that the controller reads or
  writes, new inputs that it treats as trusted, or a change to what reaches the
  CA key.
- **a flag that gates what goes into a certificate**: subject, SANs, URIs,
  EKU, validity.
- **cluster-wide chart resources**: ClusterRoles, ValidatingAdmissionPolicies,
  ClusterTrustBundles, or any other resource outside the release namespace.
- **any PR with the `release/major` label.** A breaking change always needs a
  record of what broke and why.

Routine work inside an established pattern does not need an ADR. Bug fixes,
dependency updates and docs do not need one. If a code comment argues instead of
describes, move that argument into an ADR.

### Lifecycle

A new ADR starts as `proposed`. Reviewers discuss it on the PR. Then it becomes
`accepted` or `rejected`. **Keep a rejected ADR. Do not delete it.** The record
of an option that the project considered and refused stops someone from
proposing it again. When a new ADR replaces a decision, the old ADR becomes
`superseded by [ADR-NNNN](NNNN-slug.md)`, and the new ADR links back to it. When
a decision no longer applies and nothing replaces it, the ADR becomes
`deprecated`, with the reason. The YAML front matter holds the status, and the
[ADR index](docs/adr/README.md#adrs) shows the same status. Do not rewrite the
history of an accepted ADR. Add to `## More Information` instead, as a dated
status update.

### Review

**An ADR needs at least one approving maintainer review before it merges as
`accepted`.** This is the one place in the project where a second review is
mandatory. Ordinary PRs merge on green CI. A decision that governs future code
must not be self-approved. An ADR can merge as `proposed` without that review.
It does not bind anything until a maintainer accepts it.

Put a short `ADR-NNNN` comment at the entry point of the code that the ADR
governs, and refer to the ADR in the PR description.

## Reporting issues

Use the issue forms in this repository for bugs and feature requests. Do **not**
open a public issue for a security vulnerability. Report it privately through
[GitHub security advisories](https://github.com/RafPe/pod-certificate-signer/security/advisories/new).

## Code of conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
All participants must follow it.
