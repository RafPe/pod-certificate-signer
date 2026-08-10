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

The repository ships a kind configuration (`kind/kind-config.yaml`) that
enables the `PodCertificateRequest`, `ClusterTrustBundle` and
`ClusterTrustBundleProjection` feature gates plus the
`certificates.k8s.io/v1beta1` runtime config the controller needs:

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
(`.github/workflows/pr-labels.yml`) fails otherwise:

| Label           | Effect on merge                                                 |
| --------------- | ---------------------------------------------------------------- |
| `release/major` | Next release bumps the **major** version (breaking change)       |
| `release/minor` | Next release bumps the **minor** version (feature)               |
| `release/patch` | Next release bumps the **patch** version (fix)                   |
| `release/skip`  | No release; the change is collected into the next release draft  |

Your PR title ends up in the generated release notes, so make it descriptive.

## Reporting issues

Use the issue forms in this repository for bugs and feature requests. For
security vulnerabilities, please **do not** open a public issue — report them
privately via [GitHub security advisories](https://github.com/RafPe/pod-certificate-signer/security/advisories/new).

## Code of conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating, you are expected to uphold it.
