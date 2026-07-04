🔐 **PodCertificateSigner**: A Kubernetes controller that issues x509 certificates from a custom provided CA for your pods.

> This controller is not yet ready to deploy to PRODUCTION facing worklads - it is being actively developed and should be considered for TESTING and validating concepts now

- [pod-certificate-signer (PCS): Custom signer for x509 pod certificates](#pod-certificate-signer-pcs-custom-signer-for-x509-pod-certificates)
  - [📋 Overview](#-overview)
    - [What PodCertificateSigner Does](#what-podcertificatesigner-does)
    - [Why Do You Need PodCertificateSigner](#why-do-you-need-podcertificatesigner)
    - [Key Benefits](#key-benefits)
  - [Features](#features)
  - [🔄 How It Works](#-how-it-works)
  - [📋 Prerequisites](#-prerequisites)
  - [📦 Deployment](#-deployment)
    - [1. 🔐 Create the CA secret](#1--create-the-ca-secret)
    - [2. 🚀 Install the chart](#2--install-the-chart)
    - [3. 🧑‍💻 Deploying from a local checkout](#3--deploying-from-a-local-checkout)
  - [📝 Usage](#-usage)
    - [🏷️ Configuration via `unverifiedUserAnnotations`](#️-configuration-via-unverifieduserannotations)
    - [🏷️ Configuration via Pod Annotations (deprecated)](#️-configuration-via-pod-annotations-deprecated)
      - [🔗 Example configuration](#-example-configuration)
    - [Requesting PodCertificates for your workload](#requesting-podcertificates-for-your-workload)
      - [🔗 Example workload manifest](#-example-workload-manifest)
  - [✅ Default PodCertificateSigner validation rules](#-default-podcertificatesigner-validation-rules)
  - [⌘ Controller commandline options](#-controller-commandline-options)
  - [🔧 Troubleshooting](#-troubleshooting)
    - [Common Issues](#common-issues)
    - [📊 Logs](#-logs)
  - [🛡️ Security Considerations](#️-security-considerations)
  - [📦 Release process](#-release-process)
  - [🤝 Contributing](#-contributing)
    - [Unofficial roadmap/work in progress](#unofficial-roadmapwork-in-progress)
# pod-certificate-signer (PCS): Custom signer for x509 pod certificates

## 📋 Overview

PodCertificateSigner is a simple controller operating on **native feature** introduced in Kubernetes v1.34+ that creates [PodCertificateRequest](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#pod-certificate-requests) for your pods that specify a custom x509 signer via projected volume.From your custom configuration the contoller issues(or denies) short lived x509 certificates making sure your workloads can leverage this in their operations ( either for mTLS or just TLS )

Further to that enhancments combining with [Cluster Trust Bundles](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles) / MutatingAdmissionPolicies / ValidatingAdmissionPolicy will provide the cluster operator with extremly strong security framework of operations to secure your cluster and its workloads.



### What PodCertificateSigner Does
- **Handle PodCertificateRequest**: responds and validates all requests for new pod certificates
- **Validates new x509 certificate configuration**: making sure the dynamic configuration is correct
- **Signs pod x509 certificates** or deny issuing a cetrtificate based on the configuration and cluster information.

###  Why Do You Need PodCertificateSigner
- **Secures your workloads east/west traffic** by issuing shortlived x509 certificates to your pods
- **Declarative security** by providing the configuration to your workloads
- **Enabling mTLS** by allowing you to implement strict client/server auth from the x509 certs
- **Enhancing your cluster security** without any external tools - you can use native cluster features to stregthen your security.

### Key Benefits
- **Zero false positives** - only kube-api creates the PodCertificateRequests
- **Easy integration** - works with existing Kubernetes clusters
- **Comprehensive logging** - full audit trail of decisions
- **Flexible configuration** - supports dynamic configuration via annotations

## Features

- **Support for TLS/mTLS certificates**: You can decide how to use the certificates
- **Annotation-Based**: Uses pod annotations to specify certificate configurations



## 🔄 How It Works

1. **Pod Creation**: When a pod is created in Kubernetes with the projected volume , the kube-api server creates `PodCertificateRequest`
2. **Annotation Check**: PodCertificateSigner looks for predefined configuration annotations to customize the certificate
3. **Validation**: It validates the certificate configuration against default checks
4. **Decision**: The certificate for pod is either issued or denied based on validation results.

```mermaid
---
config:
  theme: neo
---
sequenceDiagram
    participant Pod
    participant KubeAPI
    participant Controller
    participant CA
    Pod->>KubeAPI: Create with projected volume
    KubeAPI->>Controller: PodCertificateRequest event
    Controller->>Controller: Validate pod & config
    critical Handle request
    alt Success
        Controller->>CA: Sign certificate
        CA->>Controller: Return certificate
        Controller->>KubeAPI: Update status: Issued
        KubeAPI->>Pod: Pod starts
    else Failure/Deny
        Controller->>KubeAPI: Update status: Failed/Denied
        KubeAPI->>Pod: Pod blocked
    end
    end

```


## 📋 Prerequisites
> To test this setup with kind you can use prepared [kind-config](https://github.com/RafPe/pod-certificate-signer/blob/main/kind/kind-config.yaml)

- Kubernetes cluster version 1.34+ ( requires feature gates )
- CA certificate ( can be self-signed )



## 📦 Deployment

PodCertificateSigner is deployed via its Helm chart. On every release the chart is published to GHCR as an OCI artifact, alongside the controller image.

### 1. 🔐 Create the CA secret

You will need a valid CA which will be used by the controller to sign the pod certificate requests. There are many ways of approaching this - either via a tool like [cfssl](https://github.com/cloudflare/cfssl), leveraging [`cert-manager`](https://cert-manager.io/), or if you live in terminal you can use the `openssl` cli. If you have an existing CA you would like to use, simply skip the creation and use that as the source for the secret.

Create a `kubernetes.io/tls` secret from the CA in the namespace you will deploy into:

```sh
kubectl create namespace pcs-system
kubectl create secret tls podcertificate-signer-ca \
  --namespace pcs-system \
  --cert=ca.pem \
  --key=ca-key.pem
```

### 2. 🚀 Install the chart

Install directly from GHCR (replace the version with the [latest release](https://github.com/rafpe/pod-certificate-signer/releases)):

```sh
helm install podcertificate-signer oci://ghcr.io/rafpe/charts/podcertificate-signer \
  --version <X.Y.Z> \
  --namespace pcs-system \
  --set signer.name=coolcert.example.com/foo \
  --values my-values.yaml
```

Mount the CA secret into the controller via your values file (see [examples/helm-values.yaml](./examples/helm-values.yaml)):

```yaml
volumes:
  - name: podcertificate-signer-ca
    secret:
      secretName: podcertificate-signer-ca
      optional: false

volumeMounts:
  - name: podcertificate-signer-ca
    mountPath: /app/signer/ca
    readOnly: true
```

All configuration options are documented in the chart [values.yaml](./charts/podcertificate-signer/values.yaml).

### 3. 🧑‍💻 Deploying from a local checkout

For development, `make helm-deploy` builds the image, loads it into a local Kind cluster and installs the chart with the example values. `make helm-uninstall`, `make helm-status` and `make helm-rollback` manage the release.

## 📝 Usage

### 🏷️ Configuration via `unverifiedUserAnnotations`
In order to not use controller defaults for certificates being generated - the cluster operator is able to customize them via the `unverifiedUserAnnotations` field of the `podCertificate` projected volume source. This is the standard Kubernetes mechanism for passing additional context to a signer, and the kube-apiserver copies these keys verbatim onto the resulting `PodCertificateRequest`.

The scheme for configuration keys is `signer-domain/name-<configuration-item>: <value>` — the same keys as in the table below:

```yaml
  # ..... content not relevant for the example

      volumes:
      - name: x509-cert
        projected:
          sources:
          - podCertificate:
              signerName: coolcert.example.com/foo
              keyType: ED25519
              credentialBundlePath: credentialbundle.pem
              unverifiedUserAnnotations:
                coolcert.example.com/foo-cn: "some-epic-name.com"
                coolcert.example.com/foo-duration: "2h"

  # ..... rest of the manifest
```

> [!NOTE]
> Keys the signer does not recognize, as well as malformed values (e.g. an invalid duration), result in the request being **Denied** with reason `InvalidUnverifiedUserAnnotations`, as recommended by the Kubernetes API contract for signers.

### 🏷️ Configuration via Pod Annotations (deprecated)

> [!WARNING]
> Configuration via pod annotations is deprecated and will be removed in a future release - use `unverifiedUserAnnotations` instead. When both are set, `unverifiedUserAnnotations` take precedence.

Certificate configuration can also be provided via pod [`annotations`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/).

Below is the table with the annotations and example values:

| Annotation Prefix        | Required | Default Value                                                                       | Example                                                                                              |
| ------------------------ | -------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `{signer-name}-cn`       | No       | `{pod-name}`                                                                        | `mysigner.example.com/foobar-cn: my-pod.default.pod.cluster.local`                                   |
| `{signer-name}-san`      | No       | `{pod-name}.{namespace}.pod.cluster.local,{pod-name}.{namespace}.svc.cluster.local` | `mysigner.example.com/foobar-san: my-pod.default.pod.cluster.local,my-pod.default.svc.cluster.local` |
| `{signer-name}-uris`     | No       | `(empty)`                                                                           | `mysigner.example.com/foobar-uris: spiffe://cluster.local/ns/default/sa/my-service`                  |
| `{signer-name}-duration` | No       | `24h`                                                                               | `mysigner.example.com/foobar-duration: 12h`                                                          |
| `{signer-name}-refresh`  | No       | `15m`                                                                               | `mysigner.example.com/foobar-refresh: 30m`                                                           |


To customize certificates issued by PodCertificateSigner you can add one of the following annotations to your pod. This operation can be automated and delegated to your pipeline(s) or you can leverage native Kubernetes enhancment i.e `MutatingAdmissionPolicy`




#### 🔗 Example configuration
```yaml
  # ..... content not relevant for the example

  template:
    metadata:
      labels:
        app: podcertificate-app
      annotations:
        coolcert.example.com/foo-cn: "some-epic-name.com"
        coolcert.example.com/foo-san: "example.com, www.example.com, anotherexample.com.cy"
        coolcert.example.com/foo-duration: "2h"
        coolcert.example.com/foo-refresh: "30m"
        coolcert.example.com/foo-uris: "https://example.com, https://www.example.com, https://anotherexample.com.cy"
    spec:

  # ..... rest of the manifest
```


### Requesting PodCertificates for your workload
In order for kube-api server to create new PodCertificateRequests your workload needs to use specified projected volume referencing a signer.
Snipper below shows the crucial part of your code configuration required
```yaml
  # ..... content not relevant for the example

        volumeMounts:
        - name: x509-cert
          mountPath: /var/run/x509-cert
      volumes:
      - name: x509-cert
        projected:
          defaultMode: 420
          sources:
          - podCertificate:
              keyType: RSA4096 # "RSA3072", "RSA4096", "ECDSAP256", "ECDSAP384", "ECDSAP521", "ED25519"
              signerName: coolcert.example.com/foo # 👈 IMPORTANT! The signer name must match controller
              credentialBundlePath: credentialbundle.pem

  # ..... rest of the manifest
```

#### 🔗 Example workload manifest
The below provided deployment manifest is using GowebHTTPs server I wrote in Go in order to explore use of certificates in container environment.


```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: goweb
  labels:
    app: goweb-https
spec:
  replicas: 1
  selector:
    matchLabels:
      app: goweb-https
  template:
    metadata:
      labels:
        app: goweb-https
      annotations:
        coolcert.example.com/foo-cn: "some-epic-name.com"
        coolcert.example.com/foo-san: "example.com, www.example.com, anotherexample.com.cy"
        coolcert.example.com/foo-duration: "1h"
        coolcert.example.com/foo-refresh: "45m"
    spec:
      containers:
      - name: server
        image: ghcr.io/rafpe/goweb-https/server:d567d45
        ports:
        - containerPort: 8443
          name: https
          protocol: TCP
        env:
        - name: GOWEB_PORT
          value: "8443"
        - name: GOWEB_CERT_DIRECTORY_PATH
          value: "/var/run/pcr-x509"
        - name: TZ
          value: "Europe/Amsterdam" # 👈 Update to match your timezone
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: CONTAINER_NAME
          value: "server"
        volumeMounts:
        - name: pcr-x509
          mountPath: /var/run/pcr-x509
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 65532
          runAsGroup: 65532
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: pcr-x509
        projected:
          defaultMode: 420
          sources:
          - podCertificate:
              keyType: RSA4096
              signerName: coolcert.example.com/foo
              credentialBundlePath: credentialbundle.pem
      securityContext:
        fsGroup: 65532
      restartPolicy: Always
      terminationGracePeriodSeconds: 5
```


As a bonus point if using this workload demo you can check the certificate status via call to `/status` which provides detailed view of mounted certificate.
```sh
📜 Certificate Status:

Domain: some-epic-name.com
  File: /var/run/pcr-x509/credentialbundle.pem
  CN: some-epic-name.com
  Valid: 2025-09-24 11:33:54 UTC to 2025-09-24 12:33:54 UTC
  Status: ⚠️  EXPIRES SOON (in 57m46s)
```



## ✅ Default PodCertificateSigner validation rules

PodCertificateSigner performs the following `default` validations:

1. **CA files provided**: Verifies the CA provided/mounted files exists and can be loaded
2. **CA valid**: Ensures that the CA used to signing of certificates is a valid CA and not expired
3. **PodCertificateRequest configuration**: Validates the configuration provided via annotation against Kubernetes constraints

The certificate configuration is validated against the constraints kube-apiserver enforces on the `PodCertificateRequest` status, so misconfigurations are denied immediately instead of failing on the API server:

- The certificate duration must be at least `1h` (kube-apiserver minimum) and must not exceed the request's `spec.maxExpirationSeconds` (set by the pod author on the projected volume, defaulted to `24h` by kube-apiserver). The default duration is automatically clamped to `maxExpirationSeconds`.
- The refresh hint must lie within the window kube-apiserver accepts for `beginRefreshAt`: `refresh` must be at least `10m` and at most the certificate duration minus `10m`.

## ⌘ Controller commandline options
Controller is customizable and supports the following arguments along with their default values
```
command line argument:
  -ca-cert-path string
    	CA certificate file. (default "/Users/rafalpieniazek/github.com/rafpe/kubernetes-podcertificate-signer/hack/ca.pem")
  -ca-key-path string
    	CA private key file. (default "/Users/rafalpieniazek/github.com/rafpe/kubernetes-podcertificate-signer/hack/ca-key.pem")
  -cluster-fqdn string
    	The FQDN of the cluster (default "cluster.local")
  -debug-logging
    	Enable debug logging.
  -enable-leader-election
    	Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.
  -health-probe-bind-address string
    	The address the probe endpoint binds to. (default ":8081")
  -kubeconfig string
    	Paths to a kubeconfig. Only required if out-of-cluster.
  -leader-elect
    	Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.
  -leader-election-id string
    	The name of the configmap used to coordinate leader election between controller-managers. (default "pcs-leader-election")
  -signer-name string
    	Only sign CSR with this .spec.signerName. (default "coolcert.example.com/foo")
  -zap-devel
    	Development Mode defaults(encoder=consoleEncoder,logLevel=Debug,stackTraceLevel=Warn). Production Mode defaults(encoder=jsonEncoder,logLevel=Info,stackTraceLevel=Error) (default true)
  -zap-encoder value
    	Zap log encoding (one of 'json' or 'console')
  -zap-log-level value
    	Zap Level to configure the verbosity of logging. Can be one of 'debug', 'info', 'error', 'panic'or any integer value > 0 which corresponds to custom debug levels of increasing verbosity
  -zap-stacktrace-level value
    	Zap Level at and above which stacktraces are captured (one of 'info', 'error', 'panic').
  -zap-time-encoding value
    	Zap time encoding (one of 'epoch', 'millis', 'nano', 'iso8601', 'rfc3339' or 'rfc3339nano'). Defaults to 'epoch'.
```

## 🔧 Troubleshooting
Every system can experience issues. Below you may find the most commonly identified ones.

### Common Issues

1. **Signer name mismatch**
   - Ensure signer name is correct in the controller
   - Ensure signer name is correct in the projected volume of the pod(s)

2. **CA failures**
   - Verify CA is valid ( isCA )
   - Verify private key is valid
   - Ensure the CA is not expiring too soon

3. **Configuration Errors**
   - Verify if your configuration on annotation is not causing errors
   - Troubleshoot by incremently changing the configuration to eliminate the source
   - Keep checking the PodCertificateSigner logs

### 📊 Logs

PodCertificateSigner provides detailed logging for troubleshooting:

```bash
kubectl logs -n system deployment/pcs-controller
```

## 🛡️ Security Considerations

- Use Kubernetes secrets to store certificates/keys
- Monitor controller logs for suspicious activity
- Use RBAC or ValidatingAdmissionPolicy to restrict access
- Bonus: Use MutatingAdmissionPolicies to implement secure usage of the annotation

🔐 Remember: No security mechanism is effective without strong authentication and authorization. In Kubernetes, security begins with controlling who can access what — user identities , RBAC policies and MutatingAdmissionPolicies/ValidatingAdmissionPolicy to form the foundation of your cluster's defense.

## 📦 Release process

Releases are fully label-driven. Every PR targeting `main` must carry exactly one of the following labels (enforced by a required PR check):

| Label           | Effect on merge                                                        |
| --------------- | ---------------------------------------------------------------------- |
| `release/major` | Publishes a release with a **major** version bump (breaking changes)   |
| `release/minor` | Publishes a release with a **minor** version bump (features)           |
| `release/patch` | Publishes a release with a **patch** version bump (fixes)              |
| `release/skip`  | No release; the change is collected into the next release draft        |

Publishing the release creates the `v*` tag, which triggers the release artifacts workflow:

- a multi-arch (`linux/amd64`, `linux/arm64`) image is built and pushed to `ghcr.io/rafpe/pod-certificate-signer` tagged `vX.Y.Z`, `vX.Y`, `vX` and `latest`
- the Helm chart is packaged with `version: X.Y.Z` / `appVersion: vX.Y.Z` and pushed to `oci://ghcr.io/rafpe/charts/podcertificate-signer`

One-time repository setup:

```sh
gh label create release/major --color B60205 --description "Breaking change: next release bumps the major version"
gh label create release/minor --color 0E8A16 --description "Feature: next release bumps the minor version"
gh label create release/patch --color 1D76DB --description "Fix: next release bumps the patch version"
gh label create release/skip  --color C5DEF5 --description "No release: collect into the next release draft"

# Seed the version baseline (the first automated release bumps from here)
git tag v0.1.0 && git push origin v0.1.0
```

## 🤝 Contributing

Contributions are welcome!

For issues and questions:
- 📝 Create an issue in the repository
- 🔍 Check the troubleshooting section
- 📊 Review the logs for error details

### Unofficial roadmap/work in progress
There is work planned in the controller that still needs to happen however this is heavily influenced by the development of this feature in Kubernetes community
- [ ] code::proper validation of certificate constraints ( time based nbf,naf , refresh hint)
- [ ] code::object consistency Camel/Snake casing
- [ ] code::improve debug/standard logging across components
- [ ] feature::implement leader election?
- [ ] feature::metrics/webhooks ?
- [ ] feature::cleanup issued certificates for missing pods ( Karpenter scenarios )
- [ ] feature::generate Cluster Trust Bundles on start ?
- [ ] feature::check pod subdomain/host as fqdn options
- [ ] feature::customizable KeyUsage via policies ? CEL ? Like client auth only or just TLS
- [ ] feature::podidentity ?
- [ ] feature::OIDC ?
- [ ] testing::implement core tests
- [ ] testing::implement e2e testing
- [ ] testing::examples of apps using TLS
- [ ] testing::examples of controller deployment
