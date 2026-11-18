Since Kubernetes 1.37, a pod can ask for its own x509 certificate through a projected volume. No sidecar and no init container are necessary.

Kubelet creates a PodCertificateRequest, and the kube-apiserver verifies its identity fields. A signer for your own CA must answer the request.

The new article installs pod-certificate-signer 3.1.0 on a Kind cluster. In the test run, the pod was ready within seconds.

You read the request and the certificate. Each value has a source: three annotations in the pod, or a default such as the 24-hour lifetime.

The article also shows a pod that stays in ContainerCreating because of a wrong signer name. Two commands show the cause.

Article: <link>
Repo: https://github.com/RafPe/pod-certificate-signer
