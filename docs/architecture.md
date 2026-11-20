# Architecture

`pod-certificate-signer` is a Kubernetes controller for the built-in
[`PodCertificateRequest`](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#pod-certificate-requests)
API (`certificates.k8s.io/v1`).

A pod can declare a `podCertificate` projected
volume that names this signer. Kubelet then creates a `PodCertificateRequest`.
The controller validates the request. Then it issues a short-lived X.509
certificate from your CA, or it denies the request.

The controller also
publishes the signer's CA as a
[`ClusterTrustBundle`](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles).
The bundle holds the current CA and the previous CAs that it keeps across
rotations. Workloads can mount these trust anchors next to their certificates.

The controller is **not** a CSR (`CertificateSigningRequest`) signer. It is
**not** an authentication proxy. It acts only on `PodCertificateRequest`
objects. Kubelet creates these objects, and the kube-apiserver verifies their
pod identity fields before it stores them.

## Certificate issuance

```mermaid
sequenceDiagram
    autonumber
    participant Kubelet as kubelet
    participant API as kube-apiserver
    participant Rec as Reconciler (leader)
    participant CA as Certificate authority (in-process)

    Note over Kubelet: A pod with a podCertificate volume starts on the node
    Kubelet->>Kubelet: Generate key pair and PKCS#35;10 CSR
    Kubelet->>API: Create PodCertificateRequest
    API->>API: Verify pod identity fields
    API-->>Rec: Watch event: PodCertificateRequest
    Rec->>Rec: Skip if deleted, other signer or terminal
    Rec->>API: Get pod (live, uncached)
    alt Pod absent, replaced or being deleted
        Rec->>Rec: Drop, no status write
    else Pod matches the request
        Rec->>Rec: Parse CSR, resolve and validate configuration
        alt Unsupported key or invalid configuration
            Rec->>API: Update status: Denied, emit Event
        else Configuration valid
            Rec->>CA: Sign leaf certificate
            alt CA expired, or lifetime ends after the CA
                CA-->>Rec: ErrCASignerUnusable
                Rec->>Rec: Requeue with backoff, Warning Event
            else Other signing error
                CA-->>Rec: Error
                Rec->>API: Update status: Failed, emit Event
            else Signed
                CA-->>Rec: Certificate chain (leaf, then CA)
                Rec->>API: Update status: Issued, emit Event
            end
        end
    end
    Note over API,Rec: A transient API error requeues the request with backoff
    API-->>Kubelet: Issued status (kubelet reads the request)
    Kubelet->>API: Read ClusterTrustBundle (if the pod mounts it)
    Kubelet->>Kubelet: Write credential bundle and ca.crt into the pod
```

## C4 model

The [C4 model](https://c4model.com/) views below zoom in from the signer in its
cluster environment to the components inside the controller. The model is in
[`c4/workspace.dsl`](./c4/workspace.dsl) (Structurizr DSL). The Mermaid
diagrams below are a manual copy of its three views. When you change the model,
change the diagrams to match. GitHub renders the Mermaid blocks natively.

### System context (C4 level 1)

This view shows who the signer serves and what it depends on. A cluster
operator provides the CA and installs the signer. Workload authors create pods
that request certificates. Kubelet creates the `PodCertificateRequest`s. The
signer watches them and publishes the `ClusterTrustBundle`.

```mermaid
flowchart TB
    operator["Cluster operator<br/><i>[Person]</i><br/>Installs the chart, provides the signing CA, sets the signer name and rotates the CA."]
    workload["Workload author<br/><i>[Person]</i><br/>Creates pods that request a certificate through a podCertificate projected volume."]

    signer["pod-certificate-signer<br/><i>[Software System]</i><br/>Watches PodCertificateRequests for its signer name, issues or denies short-lived certificates from the CA, and publishes the signer's ClusterTrustBundle."]

    api["kube-apiserver<br/><i>[External system]</i><br/>Stores PodCertificateRequests after it verifies their pod identity fields. Enforces the status contract. Serves the ClusterTrustBundle."]
    kubelet["kubelet<br/><i>[External system]</i><br/>Generates the key pair and the PKCS#10 CSR. Creates the PodCertificateRequest. Writes the issued credential bundle and the ClusterTrustBundle into the pod and refreshes them."]
    ca["Signing CA source<br/><i>[External system]</i><br/>The CA certificate and private key, mounted read-only from a Kubernetes Secret (recommended) or a bring-your-own volume."]
    scraper["Metrics scraper<br/><i>[External system]</i><br/>Prometheus or another scraper. Sends a ServiceAccount token that the metrics-reader ClusterRole authorizes."]

    workload -->|"Creates pods with podCertificate volumes"| api
    kubelet -->|"Creates requests, reads certificates<br/>[HTTPS]"| api
    kubelet -->|"Probes health<br/>[HTTP :8081]"| signer
    signer -->|"Watches requests, writes status<br/>[HTTPS]"| api
    signer -->|"Publishes ClusterTrustBundle<br/>[HTTPS]"| api
    scraper -->|"Scrapes metrics<br/>[HTTPS :9090]"| signer
    operator -->|"Installs and configures<br/>[Helm]"| signer
    signer -->|"Reads and watches CA files<br/>[read-only volume mount]"| ca
    operator -->|"Provisions and rotates the CA"| ca
```

### Containers (C4 level 2)

The signer is one deployable: a controller Deployment. The chart runs two
replicas with leader election on. The binary flag `--leader-elect` is off by
default. The controller talks to the apiserver and reads the mounted CA.

```mermaid
flowchart TB
    kubelet["kubelet<br/><i>[External system]</i>"]
    scraper["Metrics scraper<br/><i>[External system]</i>"]
    operator["Cluster operator<br/><i>[Person]</i>"]

    subgraph signer["pod-certificate-signer [Software System]"]
        controller["Controller<br/><i>[Container: Go, distroless/static:nonroot]</i><br/>controller-runtime manager. Runs the reconciler and the ClusterTrustBundle publisher on the elected leader, and the CA watcher on every replica."]
    end

    api["kube-apiserver<br/><i>[External system]</i>"]
    ca["Signing CA source<br/><i>[External system]</i>"]

    kubelet -->|"Creates requests, reads certificates<br/>[HTTPS]"| api
    kubelet -->|"Probes health<br/>[HTTP :8081]"| controller
    scraper -->|"Scrapes metrics<br/>[HTTPS :9090]"| controller
    controller -->|"Watches requests, writes status<br/>[HTTPS]"| api
    controller -->|"Publishes ClusterTrustBundle<br/>[HTTPS]"| api
    controller -->|"Renews Lease, reviews scrape tokens<br/>[HTTPS]"| api
    controller -->|"Reads and watches CA files<br/>[read-only volume mount]"| ca
    operator -->|"Installs and configures<br/>[Helm]"| controller
    operator -->|"Provisions and rotates the CA"| ca
```

### Components (C4 level 3)

Six components run in one process inside the controller. The reconciler and
the publisher run only on the elected leader. The certificate authority, the
probes and the metrics run on every replica. The diagram shows one short action per arrow. The
[component overview](#component-overview) below gives the full detail.

```mermaid
flowchart LR
    scraper["Metrics scraper<br/><i>[External system]</i>"]
    kubelet["kubelet<br/><i>[External system]</i>"]
    api["kube-apiserver<br/><i>[External system]</i>"]

    subgraph controller["Controller [Container: Go]"]
        reconciler["PodCertificateRequest reconciler<br/><i>[Component]</i><br/>Leader-gated. Validates each request and records the outcome."]
        config["Certificate configuration<br/><i>[Component]</i><br/>Parses the CSR and resolves the certificate configuration."]
        authority["Certificate authority<br/><i>[Component]</i><br/>Runs on every replica. Holds the CA and signs leaf certificates."]
        ctb["ClusterTrustBundle publisher<br/><i>[Component]</i><br/>Leader-gated. Publishes the CA trust bundle."]
        metrics["Metrics<br/><i>[Component]</i><br/>Serves the bounded Prometheus metrics."]
        probes["Health and readiness<br/><i>[Component]</i><br/>Serves /healthz and /readyz."]
    end

    ca["Signing CA source<br/><i>[External system]</i>"]

    reconciler -->|"Watches requests, gets pod, writes status<br/>[HTTPS]"| api
    reconciler -->|"Resolves configuration"| config
    reconciler -->|"Signs leaf certificate"| authority
    authority -->|"Reads and watches CA files<br/>[read-only volume mount]"| ca
    authority -->|"Signals CA change"| ctb
    ctb -->|"Reads trust bundle"| authority
    ctb -->|"Publishes ClusterTrustBundle<br/>[HTTPS]"| api
    probes -->|"Checks CA health"| authority
    probes -->|"Checks publish result"| ctb
    metrics -->|"Reads CA gauges"| authority
    metrics -->|"Reviews scrape tokens<br/>[TokenReview, SubjectAccessReview]"| api
    kubelet -->|"Probes health<br/>[HTTP :8081]"| probes
    scraper -->|"Scrapes metrics<br/>[HTTPS :9090]"| metrics
    kubelet -->|"Creates requests, reads certificates<br/>[HTTPS]"| api
```

## Component overview

| Component | Responsibility | Leader-gated |
| --- | --- | --- |
| **PodCertificateRequest reconciler** | Watches `PodCertificateRequest`s for the configured signer name. Reads the requesting pod with an uncached `get`. Runs the validation. Records the `Issued`, `Denied` or `Failed` outcome on the request status and emits an Event for it. Otherwise it requeues or drops the request. Writes the issuance audit record to stdout ([Auditing](./auditing.md), [ADR-0007](adr/0007-issuance-audit-record.md)). | **Yes**. controller-runtime gates controllers on leader election by default. See [ADR-0006](adr/0006-release-leader-lease-on-cancel.md). |
| **Certificate configuration** | Parses the kubelet CSR and the annotation contract. Enforces the identity constraints. Resolves `${...}` interpolation. Validates duration, refresh time and EKU against the apiserver status contract. | Not applicable. The reconciler calls this library. |
| **Certificate authority** | Holds the CA in memory. Reads the CA certificate and key from the read-only mount at startup. Reloads them on fsnotify events and every 60 seconds. Refuses a lifetime that ends after the CA expires. Signs the leaf certificate. Keeps up to `--max-previous-ca-certs` previous CAs in the trust bundle PEM. | No. Every replica keeps its CA current. |
| **ClusterTrustBundle publisher** | Names and assembles the signer's `ClusterTrustBundle` from the trust bundle of the certificate authority. Publishes it at start, on each CA change and on a 10-minute drift-repair tick. Each publish gets the bundle, then creates or patches it. Runs one publish at a time and retries with backoff. At startup, every replica reads the existing bundle to load the previous-CA history ([ADR-0004](adr/0004-bootstrapped-previous-ca-history.md)). | **Yes**, for the publish. Only the elected leader writes the shared resource. The startup read runs on every replica. |
| **Health and readiness** | Serves `/healthz` as a ping. Serves `/readyz`, which fails when the CA watcher stops, when CA reloads fail persistently, or when the last publish failed after retries. | No |
| **Metrics** | Serves the bounded `podcertificatesigner_` Prometheus surface on `/metrics`, beside the controller-runtime metrics. Reads the CA gauges from the certificate authority at scrape time. The surface counts request outcomes, requeues, drops, CA reloads and trust bundle publishes, and has CA gauges. By default, each scrape needs HTTPS, a TokenReview and a SubjectAccessReview. [ADR-0005](adr/0005-bounded-metrics-surface.md): no label carries a pod, request or certificate identity. | No |

The CA watcher runs on **every** replica. Thus a standby that becomes the
leader does not sign or publish with stale material. Signing and publishing are
leader-gated. Thus one replica at a time issues certificates and writes the
shared `ClusterTrustBundle`. [Operations](./operations.md) tells how these
components behave during CA rotation, leader changes and restarts.

## Security posture

- **Distroless, non-root image.** The controller runs on
  `gcr.io/distroless/static:nonroot` as a non-root user (UID `65532`). The
  image has no shell, no libc and no package manager. You cannot exec into a
  shell, and the image has almost no OS surface for a CVE.
- **Static, CGO-disabled binary.** The build uses `CGO_ENABLED=0` and makes a
  fully static binary. Thus the image needs no dynamic libraries, and the
  attack surface is only the Go binary.
- **Restricted pod security by default.** The chart defaults comply with the
  `restricted` Pod Security Standard: `runAsNonRoot`, `seccompProfile:
  RuntimeDefault`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`
  and `capabilities: drop: [ALL]`.
- **Least-privilege RBAC.** The controller reads pods with `get` only. It reads
  pods uncached and runs no cluster-wide pod informer. Its other permissions
  cover `PodCertificateRequest`s and their status, `ClusterTrustBundle`s,
  events, the signer name, and its leader-election Lease. With secure metrics
  on, it can also create TokenReviews and SubjectAccessReviews. Because `pods`
  is `get`-only, roll out the chart and the image together. See
  [Operations: upgrades](./operations.md#upgrades).
- **Default-secure identity model.** By default the signer issues certificates
  only for the apiserver-verified identity of the requesting pod. The default
  extended key usage is `serverAuth` only. See
  [Configuration: identity constraints](./configuration.md#identity-constraints).
- **CA private key handling.** The chart mounts the signing key read-only from
  a Secret. The controller holds the key in memory and reloads it on rotation
  without a restart. [SECURITY.md](../SECURITY.md) has the full threat model
  and the reporting policy.

## Next steps

- [Getting started](./getting-started.md): install the signer and issue a first
  certificate.
- [Configuration](./configuration.md): the annotation contract, the identity
  constraints, the CLI flags and the Helm values.
- [Operations](./operations.md): CA rotation, leader election, readiness,
  metrics, upgrades and troubleshooting.
- [Auditing](./auditing.md): the issuance audit record, and how to join a
  certificate serial or fingerprint to the pod that requested it.
- [Architecture decision records](./adr/README.md): the reasons behind the
  design.
