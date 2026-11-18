# Visual brief: article 01, per-pod certificates

Source article: `../article.md`. Make each image in this file. Put each image in this directory (`assets/`). Do not change the article text.

## Cover

File: `cover.jpg`.

- Eyebrow line: `pod-certificate-signer 3.1.0 · Kubernetes 1.37`
- Title, line 1 (render this line in blue): `Per-pod`
- Title, line 2: `x509 certificates`
- Title, line 3: `with no sidecar`
- Subtitle: `Install the signer, get a certificate into a pod, and read each field.`
- Pill 1: `PodCertificateRequest`
- Pill 2: `Projected volume`
- Pill 3: `Your own CA`
- Prop: the mascot holds a certificate scroll with a seal.

## Diagrams

### Request flow

File: `flow.png`. Title: `Request flow`. The diagram shows the happy path only. Use 5 boxes.

Boxes (exact labels):

1. `kubelet` (sub-label: `generates the key, creates the request`)
2. `kube-apiserver` (sub-label: `2 verifies the identity fields`)
3. `pod-certificate-signer` (sub-label: `reads the pod, signs`)
4. `CA Secret` (sub-label: `podcertificate-signer-ca`)
5. `Pod volume` (sub-label: `credentialbundle.pem, ca.crt`)

Arrows (exact labels, direction, reading order). The numbers match the five steps in the article. Step 2 has no arrow. It is the sub-label of `kube-apiserver`.

1. From `kubelet` to `kube-apiserver`: `1 create PodCertificateRequest`
2. From `kube-apiserver` to `pod-certificate-signer`: `3 watch: request`
3. From `CA Secret` to `pod-certificate-signer`: `4 sign with current CA`
4. From `pod-certificate-signer` to `kube-apiserver`: `4 status: Issued + chain`
5. From `kube-apiserver` to `kubelet`: `5 read Issued status`
6. From `kubelet` to `Pod volume`: `5 write key and chain`

Reading order: left to right. Put `kubelet` at the left, `kube-apiserver` in the center and `pod-certificate-signer` at the right. Put `CA Secret` below `pod-certificate-signer`. Put `Pod volume` below `kubelet`. Show the arrow labels exactly as above.

## Code cards

Make 9 code cards. Each card text is the fenced block in `article.md`, byte for byte. Do not wrap, cut or change the text. No line is longer than 90 characters. Some lines start at column 0 after a line that ends with `\`. Keep them at column 0. No block has more than 23 lines. Keep the space at the end of the line `kubelet ` in `request.png`.

| File | Header label | Language |
| --- | --- | --- |
| `ca-secret.png` | `Create the CA Secret` | `sh` |
| `install.png` | `Helm install` | `sh` |
| `ctb-list.png` | `ClusterTrustBundle list (excerpt)` | `text` |
| `pod-volume.png` | `Projected volume` | `yaml` |
| `request.png` | `Request status and field managers` | `text` |
| `openssl.png` | `Certificate fields` | `text` |
| `wrong-signer.png` | `wrong-signer-pod.yaml` | `yaml` |
| `stuck-pod.png` | `Pod stays in ContainerCreating (excerpt)` | `text` |
| `verify.png` | `Verify commands` | `sh` |

## Reused images

None. This article uses no repository image.

## Alt text

| File | Alt text |
| --- | --- |
| `cover.jpg` | Cover: per-pod x509 certificates with no sidecar, pod-certificate-signer 3.1.0 on Kubernetes 1.37+. A mascot holds a certificate scroll with a seal. |
| `flow.png` | Request flow: kubelet creates a PodCertificateRequest and kube-apiserver verifies it. The signer signs with the CA and writes Issued. Kubelet writes the files into the pod volume. |
| `ca-secret.png` | Commands that create the pcs-system namespace and the podcertificate-signer-ca TLS Secret. |
| `install.png` | Helm install of the chart 3.1.0 with the signer name example.org/signer, then the rollout status. |
| `ctb-list.png` | Output: the ClusterTrustBundle example.org:signer:bundle and a Kubernetes bundle. |
| `pod-volume.png` | YAML: a projected volume with a podCertificate source and a clusterTrustBundle source. |
| `request.png` | Output: the request has the condition Issued. The field manager kubelet owns the spec and manager owns the status. The pod has two files. |
| `openssl.png` | Output of openssl: subject, issuer, 24-hour validity, server authentication, CA:FALSE and the SANs. |
| `wrong-signer.png` | YAML: a pod with the wrong signer name example.org/other-signer. |
| `stuck-pod.png` | Output: the pod stays in ContainerCreating. The request for the other signer has no condition. The signer log shows both signer names. |
| `verify.png` | Commands that verify the bundle, the request and the certificate chain, then delete both pods. |
