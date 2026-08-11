# Getting started

This guide takes you from an empty cluster to a workload holding a certificate
issued by `pod-certificate-signer`. For the full configuration surface see
[Configuration](./configuration.md); for day-2 tasks see
[Operations](./operations.md).

## Prerequisites

- **Kubernetes 1.35+.** The controller uses the `certificates.k8s.io/v1beta1`
  `PodCertificateRequest` API, available since 1.35. The cluster must have:
  - feature gates `PodCertificateRequest`, `ClusterTrustBundle`,
    `ClusterTrustBundleProjection`;
  - runtime config `certificates.k8s.io/v1beta1=true`.
- **Helm 3+** and **`kubectl`**.
- **A signing CA** (certificate + private key). It can be self-signed. The chart
  does **not** ship a CA — you provide your own.

> [!TIP]
> To try this on a laptop, [`kind/kind-config.yaml`](https://github.com/RafPe/pod-certificate-signer/blob/main/kind/kind-config.yaml)
> enables the required feature gates and runtime config for a local Kind cluster.

## 1. Create the CA Secret

You need a CA the controller will use to sign requests. Generate one with
[cfssl](https://github.com/cloudflare/cfssl), [cert-manager](https://cert-manager.io/),
or `openssl`; if you already have a CA, skip creation and use it as the source.

Create a `kubernetes.io/tls` Secret from the CA in the namespace you deploy into:

```sh
kubectl create namespace pcs-system
kubectl create secret tls podcertificate-signer-ca \
  --namespace pcs-system \
  --cert=ca.pem \
  --key=ca-key.pem
```

> [!WARNING]
> Use a CA you generated yourself. A sample CA (`examples/ca_tls_secret.yaml`)
> once shipped with this repository; it is removed from `HEAD` by
> [#37](https://github.com/rafpe/pod-certificate-signer/pull/37), but its private
> key remains readable in git history and must never be used anywhere real. See
> [Operations: rotating the signing CA](./operations.md#rotating-the-signing-ca).

## 2. Install the chart

The chart is published to GHCR as an OCI artifact on every release, alongside
the controller image. `signer.name` and a CA source are **required**:

```sh
helm install pod-certificate-signer oci://ghcr.io/rafpe/charts/pod-certificate-signer \
  --version <X.Y.Z> \
  --namespace pcs-system \
  --set signer.name=coolcert.example.com/foo \
  --set signer.ca.secretRef.name=podcertificate-signer-ca
```

Replace `<X.Y.Z>` with the [latest release](https://github.com/rafpe/pod-certificate-signer/releases);
omit `--version` for the latest. With `signer.ca.source=secretRef` (the default)
the chart wires a read-only volume for the Secret automatically — there is no
`volumes`/`volumeMounts` to plumb. See
[Configuration: providing the CA](./configuration.md#providing-the-ca) for the
`file` (bring-your-own-mount) alternative and the full values reference.

Confirm the controller is running and has published its trust bundle:

```sh
kubectl -n pcs-system rollout status deploy/pod-certificate-signer
kubectl get clustertrustbundle
```

### Deploying from a local checkout

For development, `make helm-deploy` builds the image, loads it into a local Kind
cluster and installs the chart with the example values. `make helm-uninstall`,
`make helm-status` and `make helm-rollback` manage the release.

## 3. Request a certificate from a workload

A workload opts in by declaring a `podCertificate` projected volume that names
the signer, and (recommended) mounting the signer's `ClusterTrustBundle`
alongside it so it also has the trust anchors to verify peers:

```yaml
      volumeMounts:
        - name: x509-cert
          mountPath: /var/run/x509-cert
      volumes:
        - name: x509-cert
          projected:
            defaultMode: 420
            sources:
              - podCertificate:
                  keyType: RSA4096   # RSA3072, RSA4096, ECDSAP256/384/521, ED25519
                  signerName: coolcert.example.com/foo   # must match the controller
                  credentialBundlePath: credentialbundle.pem
              - clusterTrustBundle:
                  signerName: coolcert.example.com/foo   # the CA bundle the controller publishes
                  labelSelector: {}                      # required with signerName; {} selects all
                  path: ca.crt
```

The container then sees two files:

- `/var/run/x509-cert/credentialbundle.pem` — the private key plus the issued
  certificate chain, kept fresh by kubelet;
- `/var/run/x509-cert/ca.crt` — the signer's CA bundle (including previous CAs
  during rotation), used to verify peer certificates for mTLS.

A complete, runnable manifest — including per-pod identity via annotations — is
in [`examples/workload-pod.yaml`](https://github.com/rafpe/pod-certificate-signer/blob/main/examples/workload-pod.yaml)
(it is also exercised by the e2e suite).

> [!NOTE]
> With controller defaults the certificate is issued for the pod's own verified
> identity. To set a custom common name, SANs, duration, EKU or SPIFFE URIs, use
> the annotation contract in [Configuration](./configuration.md#certificate-configuration-annotations).

## Next steps

- [Configuration](./configuration.md) — the annotation contract, CLI flags, Helm
  values, the identity-constraint model and production-recommended settings.
- [Operations](./operations.md) — CA rotation, leader election, readiness,
  upgrades and troubleshooting.
- [Architecture](./architecture.md) — C4 diagrams, component overview and
  security posture.
