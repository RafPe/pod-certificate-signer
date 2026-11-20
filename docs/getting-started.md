# Getting started

This guide starts with an empty cluster. At the end, a workload holds a
certificate that `pod-certificate-signer` issued. For all configuration options,
see [Configuration](./configuration.md). For day-2 tasks, see
[Operations](./operations.md).

## Prerequisites

- **Kubernetes 1.37+.** The controller uses the `certificates.k8s.io/v1`
  `PodCertificateRequest` API, which became GA in 1.37. You do not need feature
  gates or runtime configuration. The kube-apiserver serves this group version
  by default.
- **Helm 3+** and **`kubectl`**.
- **A signing CA** (certificate and private key). The CA can be self-signed. The
  chart does **not** include a CA. You must supply your own.

> [!TIP]
> To try this on a laptop, use [`kind/kind-config.yaml`](https://github.com/RafPe/pod-certificate-signer/blob/main/kind/kind-config.yaml).
> It pins a Kubernetes 1.37 node image for a local Kind cluster.

## 1. Create the CA Secret

The controller uses a CA to sign requests. To make a CA, use
[cfssl](https://github.com/cloudflare/cfssl), [cert-manager](https://cert-manager.io/)
or `openssl`. If you already have a CA, use it.

Create a `kubernetes.io/tls` Secret from the CA in the namespace that you deploy into:

```sh
kubectl create namespace pcs-system
kubectl create secret tls podcertificate-signer-ca \
  --namespace pcs-system \
  --cert=ca.pem \
  --key=ca-key.pem
```

Make sure that the Secret exists:

```sh
kubectl -n pcs-system get secret podcertificate-signer-ca
```

> [!WARNING]
> Use a CA that you generated yourself. This repository once included a sample
> CA (`examples/ca_tls_secret.yaml`).
> [#37](https://github.com/rafpe/pod-certificate-signer/pull/37) deleted it from
> `HEAD`. Its private key is still readable in the git history. Never use it for
> a real cluster. See
> [Operations: rotating the signing CA](./operations.md#rotating-the-signing-ca).

## 2. Install the chart

Browse chart versions and values on [Artifact Hub](https://artifacthub.io/packages/helm/pod-certificate-signer/pod-certificate-signer).

Each release publishes the chart to GHCR as an OCI artifact, together with the
controller image. The chart requires `signer.name` and a CA source:

```sh
helm install pod-certificate-signer oci://ghcr.io/rafpe/charts/pod-certificate-signer \
  --version <X.Y.Z> \
  --namespace pcs-system \
  --set signer.name=example.org/signer \
  --set signer.ca.secretRef.name=podcertificate-signer-ca
```

Replace `<X.Y.Z>` with the [latest release](https://github.com/rafpe/pod-certificate-signer/releases).
If you omit `--version`, Helm installs the latest release.

The default CA source is `signer.ca.source=secretRef`. With this source, the
chart mounts the Secret as a read-only volume. You do not add `volumes` or
`volumeMounts`. For the `file` source (you supply the mount) and the full values
reference, see [Configuration: providing the CA](./configuration.md#providing-the-ca).

Make sure that the controller runs and published its `ClusterTrustBundle`:

```sh
kubectl -n pcs-system rollout status deploy/pod-certificate-signer
kubectl get clustertrustbundle
```

The bundle name is the signer name with `/` changed to `:`, plus `:bundle`. For
`example.org/signer`, the name is `example.org:signer:bundle`.

### Deploying from a local checkout

For development, `make helm-deploy` does these steps:

1. It builds the image.
2. It loads the image into a local Kind cluster (`make kind-start` creates the cluster).
3. It generates a temporary dev CA and installs the chart from `charts/` with
   [`examples/helm-values.yaml`](../examples/helm-values.yaml) and the signer
   name `example.org/signer`.

To manage the release, use `make helm-status`, `make helm-history`,
`make helm-rollback` and `make helm-uninstall`. To delete the Kind cluster, use
`make kind-stop`.

## 3. Request a certificate from a workload

Use the `podCertificate` source to give a workload its own private key and certificate chain. A pod can request and present its certificate without mounting a `ClusterTrustBundle`.

### Which side needs the trust bundle?

Suppose a client calls an HTTPS server whose certificate comes from this signer. The server presents its certificate. The **client** needs to trust the signer’s CA and check the server’s DNS name.

Mount the `clusterTrustBundle` source in the client if its TLS trust store needs those CA certificates. Configure the client to read `ca.crt` and reload it after rotation. If its trust store already tracks the CA, the extra mount is optional.

With mutual TLS (mTLS), the server also verifies the client certificate. Each side needs trust anchors for the **other side’s issuer**. The server must also check which client identities it allows, for example by SPIFFE ID.

The example below includes both sources. Omit the `clusterTrustBundle` entry if the pod only needs its own credentials.

```yaml
    volumeMounts:
    - name: x509
      mountPath: /var/run/x509
      readOnly: true
  volumes:
  - name: x509
    projected:
      sources:
      - podCertificate:
          keyType: ED25519   # RSA3072, RSA4096, ECDSAP256, ECDSAP384, ECDSAP521, ED25519
          signerName: example.org/signer   # must match the controller
          credentialBundlePath: credentialbundle.pem
      - clusterTrustBundle:
          signerName: example.org/signer   # the CA bundle the controller publishes
          labelSelector: {}                # required with signerName; {} selects all
          path: ca.crt
```

The container then has two files:

- `/var/run/x509/credentialbundle.pem`: the private key and the issued
  certificate chain. The kubelet refreshes this file.
- `/var/run/x509/ca.crt`: the CA bundle of the signer. During a rotation it
  also contains the previous CAs. Use it to verify peer certificates for mTLS.

[`examples/workload-pod.yaml`](https://github.com/rafpe/pod-certificate-signer/blob/main/examples/workload-pod.yaml)
is a complete manifest. It also sets per-pod identity with annotations. The e2e
suite applies the same manifest.

From a checkout of this repository, apply the example:

```sh
kubectl apply -f examples/workload-pod.yaml
```

> [!NOTE]
> With the controller defaults, the certificate is for the verified identity of
> the pod. To set a custom common name, SANs, duration, EKU or SPIFFE URIs, use
> the [annotation contract](./configuration.md#certificate-configuration-annotations).
> Each value in the example resolves to an identity that the pod owns. Thus the
> signer issues it under the default
> [identity constraints](./configuration.md#identity-constraints). You do not
> need `--allow-unverified-identities`.

## 4. Verify the certificate

The kubelet does not start the pod until it writes the credential bundle.
Thus a running pod has a certificate.

1. Wait for the pod:

   ```sh
   kubectl wait --for=condition=Ready pod/pcs-example-workload --timeout=120s
   ```

2. Make sure that the `PodCertificateRequest` has the `Issued` condition:

   ```sh
   kubectl get podcertificaterequests -n default -o yaml
   ```

3. Make sure that the two files are in the container:

   ```sh
   kubectl exec pcs-example-workload -- ls /var/run/x509
   ```

If the pod stays in `ContainerCreating`, read the events and the conditions of
its `PodCertificateRequest`. A `Denied` condition with the reason
`InvalidUnverifiedUserAnnotations` shows a problem in the annotation
configuration. See [Operations: troubleshooting](./operations.md#troubleshooting).

To delete the example:

```sh
kubectl delete -f examples/workload-pod.yaml
```

## Next steps

- [Configuration](./configuration.md): the annotation contract, CLI flags, Helm
  values, the identity constraint model and the settings for production.
- [Operations](./operations.md): CA rotation, leader election, readiness,
  upgrades and troubleshooting.
- [Architecture](./architecture.md): C4 diagrams, component overview and
  security posture.
