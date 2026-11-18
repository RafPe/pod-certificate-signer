# Facts: article 01, per-pod certificates

Repository state: branch `article-01-per-pod-certificates`, HEAD `5477437` (main). Release 3.1.0.
Test cluster: Kind `pcs-art-01`, node image `kindest/node:v1.37.0`, kind v0.33.0, 2026-11-16.
Evidence files are in `evidence/`. See `evidence/README.md` for the format and the edits after capture.

The article shows the run in `12-cards.txt`, `13-wrong-signer-cards.txt` and `14-verify-final.txt`, unless a row names another file. Files `03` to `11` are earlier runs with longer commands. They show the same results.

## Claim ledger

| # | Claim in the article | Source | Verbatim quote |
| --- | --- | --- | --- |
| 1 | `PodCertificateRequest` is GA in `certificates.k8s.io/v1` since Kubernetes 1.37. | `README.md:24`; `evidence/00-cluster.txt` | "It is GA in `certificates.k8s.io/v1` since Kubernetes 1.37." / `podcertificaterequests  certificates.k8s.io/v1  true  PodCertificateRequest` |
| 2 | Kubelet creates the request. The kube-apiserver verifies its identity fields. | `README.md:26`; `docs/architecture.md:22-24` | "The kubelet creates a `PodCertificateRequest`, and the kube-apiserver verifies its identity fields." / "The kube-apiserver verifies the pod identity fields of the request." |
| 3 | Kubelet created the request (field manager proof). | `evidence/12-cards.txt`; `evidence/04-pcr.txt` (full managedFields) | `kubelet ` (no subresource). In `04-pcr.txt`: `manager: kubelet`, `operation: Update`, owns `f:spec` (`f:signerName`, `f:stubPKCS10Request`, `f:unverifiedUserAnnotations`, ...) and `f:metadata` (`f:generateName`, `f:ownerReferences`) |
| 4 | `manager` owns only the `status` subresource. `manager` is the controller binary name. The signer log shows `issued certificate` at the same second. | `evidence/12-cards.txt`; `evidence/04-pcr.txt`; `Dockerfile:27,38` | `manager status`; log `2026-11-16T13:14:27Z INFO PodCertificateSigner issued certificate {"name": "req-5sksd"`, `creationTimestamp: "2026-11-16T13:14:27Z"`; Dockerfile `-o manager cmd/podcertificate-signer/main.go`, `ENTRYPOINT ["/manager"]` |
| 5 | A signer controller watches requests for its signer name and signs with your CA. It also publishes the CA as a `ClusterTrustBundle`. | `README.md:15-17`; `docs/architecture.md:25-26` | "It issues short-lived x509 certificates to your pods from your own CA. It also publishes that CA as a `ClusterTrustBundle`." / "The reconciler receives the request through a watch. It ignores requests for other signer names." |
| 6 | A `ClusterTrustBundle` is a cluster-scoped object that holds the trust anchors of a signer. | `README.md:28-29`; `evidence/00-cluster.txt` | "publishes its current and previous CAs as a `ClusterTrustBundle`. Workloads mount these trust anchors" / `clustertrustbundles  certificates.k8s.io/v1  false  ClusterTrustBundle` (NAMESPACED false) |
| 7 | Request flow steps 1 to 5. | `docs/architecture.md:21-53` | "Kubelet generates the key pair and a PKCS#10 CSR. Kubelet creates a `PodCertificateRequest`." / "This read is an uncached `get`" / "writes the certificate chain, `notBefore`, `notAfter` and `beginRefreshAt` to the request status with the `Issued` condition" / "Kubelet reads the `Issued` status. It writes the private key and the certificate chain into the pod volume and refreshes them." |
| 8 | Identity constraints permit only names that the pod can prove from the verified fields. | `docs/configuration.md:207-209` | "The signer accepts a `cn`, `san` or `uris` value only when it resolves to an identity from the apiserver-verified `PodCertificateRequest` fields." |
| 9 | The request carries the public key in a stub PKCS#10 request. The private key is not in the request or its status. | `evidence/04-pcr.txt` | spec `stubPKCS10Request: MH8w...`; status fields are only `beginRefreshAt`, `certificateChain`, `conditions`, `notAfter`, `notBefore` |
| 10 | The chart ships no CA. A self-signed CA is permitted. | `docs/getting-started.md:15-16` | "The CA can be self-signed. The chart does **not** include a CA. You must supply your own." |
| 11 | The CA must have `CA:TRUE` and `Certificate Sign`. | `docs/configuration.md:328-329`; `internal/authority/authority.go:255` | "The certificate must be a CA certificate with the `certSign` key usage." / `if !cert.BasicConstraintsValid \|\| !cert.IsCA {` |
| 12 | The test CA had a 30-day lifetime. | `evidence/01-ca-secret.txt` | `notBefore=Nov 16 11:54:14 2026 GMT`, `notAfter=Dec 16 12:54:14 2026 GMT`, `CA:TRUE`, `Digital Signature, Certificate Sign` |
| 13 | The Secret has type `kubernetes.io/tls` and 2 data keys. | `evidence/01-ca-secret.txt` | `podcertificate-signer-ca   kubernetes.io/tls   2      0s` |
| 14 | The chart mounts the CA Secret as a read-only volume. | `docs/getting-started.md:68-69` | "With this source, the chart mounts the Secret as a read-only volume." |
| 15 | The chart requires the signer name and a CA source. | `docs/getting-started.md:55` | "The chart requires `signer.name` and a CA source" |
| 16 | Two replicas. The rollout took about 10 seconds. | `evidence/02-install.txt` | `replicaCount: 2`; rollout started `12:57:26Z`, next command `12:57:36Z`, `deployment "pod-certificate-signer" successfully rolled out` |
| 17 | `kubectl get clustertrustbundle` output. | `evidence/02-install.txt` | `example.org:signer:bundle   example.org/signer` and `kubernetes.io:kube-apiserver-serving:ecb6f5dc135f94dd439d0dd1   kubernetes.io/kube-apiserver-serving`. The article cuts the hash with `...` and says that the block is an excerpt. |
| 18 | Bundle name rule. | `docs/getting-started.md:80-81` | "The bundle name is the signer name with `/` changed to `:`, plus `:bundle`." |
| 19 | The second bundle has a `kubernetes.io/` signer name and is not from this project. | `evidence/02-install.txt`; `docs/getting-started.md:80-81` | `kubernetes.io/kube-apiserver-serving`. The project names its bundle `<signer>:bundle`. |
| 20 | Only the leader publishes the bundle and signs. | `docs/operations.md:153-156` | "**Signing and `ClusterTrustBundle` publication run only on the leader.**" |
| 21 | Field meanings. `labelSelector: {}` is required with `signerName` and selects all. Kubelet copies `userAnnotations` without change. | `docs/getting-started.md:111-120`; `docs/configuration.md:14-18` | `labelSelector: {}                # required with signerName; {} selects all` / "Kubelet copies these keys without change into `spec.unverifiedUserAnnotations`" |
| 22 | `signerName` must match the controller exactly. | `docs/operations.md:369-370` | "Compare each value with `--signer-name` (Helm `signer.name`). They must be exactly the same." |
| 23 | Volume YAML and annotation values are from the example. | `examples/workload-pod.yaml:50-81` | The YAML card leaves out `userAnnotations` and comments. The three annotation values are at lines 62, 68 and 71, unchanged. |
| 24 | The pod was Ready within 2 seconds after the apply. | `evidence/12-cards.txt` | apply `13:14:27Z`; the next command started `13:14:29Z` after `condition met` |
| 25 | Kubelet does not start the container until it writes the credential bundle. | `docs/getting-started.md:151-152`; `evidence/13-wrong-signer-cards.txt` | "The kubelet does not start the pod until it writes the credential bundle. Thus a running pod has a certificate." / `credential bundle is not issued yet` |
| 26 | `Issued` condition, field managers, two files. | `evidence/12-cards.txt` | `Issued CertificateIssued`; `kubelet ` / `manager status`; `ca.crt` / `credentialbundle.pem` |
| 27 | Bundle order: key, leaf, CA. | `evidence/05-files.txt`; `internal/authority/authority.go:395-396` | one private key header, then `-----BEGIN CERTIFICATE-----`, `-----BEGIN CERTIFICATE-----` (the key header line is redacted in the evidence file) / "Issued certificate first, then the CA that signed it." |
| 28 | The busybox image has no `openssl`. | `evidence/10-busybox-openssl.txt` | `exec: "openssl": executable file not found in $PATH` |
| 29 | `-ext` needs OpenSSL 1.1.1 or later. The test used OpenSSL 4.1.0. | `evidence/06-openssl.txt` | `OpenSSL 4.1.0 23 Oct 2026`. The 1.1.1 minimum is not verified. |
| 30 | Certificate fields. | `evidence/12-cards.txt` | the full `openssl x509 ... \| tr ',' '\n'` block in the article |
| 31 | CN, DNS SANs and URI come from the three annotations. | `examples/workload-pod.yaml:62,68,71`; `evidence/04-pcr.txt` (log) | `"commonName": "pcs-example-workload.default.svc.cluster.local", "dnsNames": ["pcs-example-workload.default.svc", "default.default"]` |
| 32 | EKU default is server authentication. | `internal/podcertificate/podcertificate.go:143`; `docs/configuration.md:42` | `ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},` |
| 33 | Key usage follows the key type. | `internal/podcertificate/certificate.go:126-133`; `docs/configuration.md:341-343` | "Certificates for non-RSA keys have only the `digitalSignature` key usage." |
| 34 | `CA:FALSE` is set on every leaf. | `internal/authority/authority.go:377-386` | "IsCA stays at its zero value, so the pair asserts cA:FALSE on every leaf." |
| 35 | Default lifetime 24h. | `internal/podcertificate/certificate.go:62-63`; `docs/configuration.md:44` | `DefaultDuration = 24 * time.Hour` |
| 36 | `${pod.*}` from the verified fields. `${cluster.fqdn}` from `signer.cluster_fqdn`, default `cluster.local`. | `examples/workload-pod.yaml:10-12`; `charts/pod-certificate-signer/values.yaml:98`; `evidence/02-install.txt` | "The signer derives these identities from the verified fields of the PodCertificateRequest." / `cluster_fqdn: cluster.local` / `- --cluster-fqdn=cluster.local` |
| 37 | `default.default` is service account `default`, then namespace `default`. | `examples/workload-pod.yaml:68`; `evidence/06-openssl.txt` | `${pod.serviceAccountName}.${pod.namespace}`; `serviceAccountName` is `default` |
| 38 | An annotation replaces the default. Default SANs are the `.pod` and `.svc` names. Default CN is the pod name. | `internal/podcertificate/annotations.go:203-217`; `internal/podcertificate/identity.go:70-96` | `case fromAnnotation: names = splitAndTrim(san)` ... `default: names = defaults` / `"%s.%s.pod.%s"`, `"%s.%s.svc.%s"` / `return podName` |
| 39 | The example values are identities that the pod owns, so the default constraints permit them. | `examples/workload-pod.yaml:10-14`; `docs/getting-started.md:144-147` | "Thus the signer issues this manifest under the default identity constraints, without --allow-unverified-identities." |
| 40 | `notBefore` is one minute before the signing time. The code states no reason, so the article gives none. | `internal/authority/authority.go:144,345`; `evidence/12-cards.txt` | `backDate: 1 * time.Minute,` / `notBefore := now.Add(-backDate)`; `creationTimestamp: "2026-11-16T13:14:27Z"`, `notBefore: "2026-11-16T13:13:27Z"` |
| 41 | `beginRefreshAt` is 15 minutes before `notAfter`. | `evidence/12-cards.txt`; `internal/podcertificate/certificate.go:67` | `beginRefreshAt: "2026-11-17T12:58:27Z"`, `notAfter: "2026-11-17T13:13:27Z"` / `DefaultRefreshBefore = 15 * time.Minute` |
| 42 | The project docs state that kubelet refreshes the file. | `docs/getting-started.md:126`; `docs/architecture.md:50-51` | "The kubelet refreshes this file." Not observed. |
| 43 | Wrong signer: `ContainerCreating` after 60 s, `FailedMount` event. | `evidence/13-wrong-signer-cards.txt` | `pcs-wrong-signer   0/1     ContainerCreating   0          60s`; `FailedMount   MountVolume.SetUp failed for volume "x509" : credential bundle is not issued yet` (3 lines, cut to 1 in the article). The article cuts `for volume "x509" :` with `...` and keeps `credential bundle is not issued yet`. |
| 44 | The cluster kept events of two earlier test pods with the same name. | `evidence/07-wrong-signer.txt`; `evidence/11-wrong-signer-rerun.txt` | Earlier `pcs-wrong-signer` pods at `12:58:18Z` and `13:12:26Z`. |
| 45 | The signer writes no condition and no event on a request for another signer. | `docs/operations.md:364-365`; `internal/controller/podcertificaterequest_controller.go:210-212`; `evidence/13-wrong-signer-cards.txt` | "The controller ignores requests for other signer names and writes no condition on them." / `Status:` empty, `Events:  <none>` (req-nfmgp) |
| 46 | Signer name mismatch is the most frequent problem. | `docs/operations.md:364` | "**Signer name mismatch.** This is the most frequent problem." |
| 47 | Request list and log output for the wrong signer. | `evidence/13-wrong-signer-cards.txt`; `evidence/07-wrong-signer.txt` | `pcs-wrong-signer       example.org/other-signer   <none>`; `"signerName": "example.org/other-signer", "controllerSignerName": "example.org/signer"}`; full log line: `request is addressed to another signer; ignoring` |
| 48 | `Denied` with `InvalidUnverifiedUserAnnotations` shows an annotation that the signer does not accept. | `docs/architecture.md:42-43`; `docs/configuration.md:48-50` | "An invalid configuration gives `Denied` with the reason `InvalidUnverifiedUserAnnotations`." |
| 49 | The signer does not issue a certificate that would outlive the CA. | `docs/architecture.md:45-47`; `internal/authority/authority.go:351-353` | "The CA cannot sign yet. It is past its expiry date, or the requested lifetime ends after the CA expires." |
| 50 | The example pod runs `sleep 600` with `restartPolicy: Never`. | `examples/workload-pod.yaml:33,37` | `restartPolicy: Never` / `command: ["sleep", "600"]` |
| 51 | Verify results: bundle exists, `Issued`, `stdin: OK`, requests gone after delete. | `evidence/14-verify-final.txt` | `example.org:signer:bundle   example.org/signer`; `req-5sksd ... Issued`; `stdin: OK`; `No resources found` |
| 52 | Kubernetes deletes each request with its pod, because the pod owns it. | `evidence/04-pcr.txt`; `evidence/14-verify-final.txt` | `ownerReferences: - apiVersion: v1 kind: Pod name: pcs-example-workload`; after delete: `No resources found` |
| 53 | An application that loads the certificate only at start keeps the old certificate after a refresh. | Inference from row 42. | No repository doc states this. Not tested. |

## Field manager proof

`kubectl get podcertificaterequests -n default -o yaml --show-managed-fields` (`evidence/04-pcr.txt`, request `req-44ct7`) shows two entries:

- `manager: kubelet`, `operation: Update`, no subresource, `time: "2026-11-16T12:57:44Z"`. It owns `f:metadata.f:generateName`, `f:metadata.f:ownerReferences` and every field of `f:spec`, including `f:signerName`, `f:stubPKCS10Request` and `f:unverifiedUserAnnotations`.
- `manager: manager`, `operation: Update`, `subresource: status`, `time: "2026-11-16T12:57:44Z"`. It owns `f:status` only.

`evidence/12-cards.txt` repeats the result for request `req-5sksd`: `kubelet ` and `manager status`. `manager` is the binary name of the controller (`Dockerfile:27,38`). The code sets no explicit field owner: `grep -rn "FieldOwner\|FieldManager" cmd internal` finds nothing outside tests. The controller log has `issued certificate` for each request at the second of its creation.

## Checks completed

- Each line of each `text` block in `article.md` is a line of an evidence file, with these exceptions:
  - The `...` line in the `stuck-pod` block, and two cut lines with `...` in them: the `kubernetes.io` bundle row (`ctb-list`) and the `FailedMount` row (`stuck-pod`). The sentence before each block says that it is an excerpt.
  - Three commands are split with `\` to keep lines at 90 characters or fewer: the managed-fields jsonpath (`request`), the custom-columns list (`stuck-pod`) and `openssl verify` (`verify`). The jsonpath and custom-columns continuation lines start at column 0, so the shell joins them into the same argument. The arguments are the same as in the evidence.
- Each `sh` command in `article.md` has a `$` line in `evidence/`. Differences in form:
  - `kubectl create secret tls` and `helm install` ran on one line (`01`, `02`). The article splits them with `\`. The arguments are the same.
  - `rollout status` has `--timeout=180s`. `docs/getting-started.md` has no timeout.
  - The verify block ran as a set in `14-verify-final.txt`.
- The custom-columns request list uses `POD`, `SIGNER` and `STATE` columns. `docs/operations.md:368` uses `NS`, `NAME` and `SIGNER`.
- Code cards: 9. Longest line: 90 characters or fewer (contract limit 90). Largest block: 23 lines (`wrong-signer`). Both YAML blocks parse with `yaml.safe_load`.
- No key body is in `evidence/`. The one private key header line in `05-files.txt` is redacted, because the repository hygiene test rejects that header in a tracked file.
- Article: 8 H2 sections, no H3, one table with 3 columns, each fenced block has an image line above it.
- Linter: `ste-lint.py article.md post.md` gives 0 violations (0 hard). `assets/BRIEF.md` also gives 0.
- Word counts: article prose 1,489 (linter count on `article.md` alone, without code blocks). Post 110 words without the two link lines.
- Link: the article links only to `docs/configuration.md` (page, no anchor). The file exists on `main`.
- The cluster `pcs-art-01` was deleted after the evidence was complete.

## Not verified

- **Kubernetes ships no signer for arbitrary signer names.** The article does not state this as a general fact. It states that a signer controller signs requests for its signer name. The evidence shows that no component answered `example.org/other-signer` in 60 seconds.
- **Kubelet refresh of the credential bundle.** The certificate lives 24 hours. The test did not wait for `beginRefreshAt`. The article cites the docs.
- **Application must read the files again.** This is an inference. It was not tested. No repository doc states it.
- **OpenSSL 1.1.1 as the minimum for `-ext`.** Only OpenSSL 4.1.0 ran. LibreSSL was not tested.
- **Client skew.** kubectl was v1.35.0 against server v1.37.0. `kubectl version` printed a skew warning (`evidence/00-cluster.txt`). Other commands printed no warning.
- **Single node.** The cluster had one control-plane node.
- **Field manager name.** The link between `manager` and the binary name comes from the Dockerfile and the absence of an explicit field owner. The client-go default rule was not read.
