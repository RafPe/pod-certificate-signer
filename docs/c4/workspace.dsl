workspace "pod-certificate-signer" "Signer for the built-in PodCertificateRequest API that issues short-lived pod certificates and publishes its CA as a ClusterTrustBundle" {

    model {
        operator = person "Cluster operator" "Installs the chart, provides the signing CA, sets the signer name and rotates the CA."
        workload = person "Workload author" "Ships pods that request a certificate via a podCertificate projected volume."

        apiServer = softwareSystem "kube-apiserver" "Creates PodCertificateRequests from projected volumes, verifies request fields, enforces the status contract and serves the ClusterTrustBundle." {
            tags "External"
        }

        kubelet = softwareSystem "kubelet" "Generates the key pair and PKCS#10 CSR for the projected volume, mounts the issued credential bundle and the ClusterTrustBundle, and refreshes them." {
            tags "External"
        }

        caSource = softwareSystem "Signing CA source" "The CA certificate and private key, mounted read-only from a Kubernetes Secret (recommended) or a bring-your-own volume." {
            tags "External"
        }

        signer = softwareSystem "pod-certificate-signer" "Watches PodCertificateRequests for its signer name, issues or denies short-lived certificates from the CA, and keeps the signer's ClusterTrustBundle in sync." {
            controller = container "Controller" "Kubernetes controller (controller-runtime manager) that runs the reconciler, the CA watcher and the ClusterTrustBundle publisher as a single leader-elected deployment." "Go, distroless/static:nonroot" {
                reconciler = component "PodCertificateRequest reconciler" "Watches PodCertificateRequests for the configured signer name; validates the request and its annotation configuration, then issues or denies." "Go, controller-runtime"
                config = component "Certificate configuration" "Parses the annotation contract (cn/san/ip-san/eku/duration/refresh/uris), enforces identity constraints, resolves ${...} interpolation and validates against the apiserver status contract." "Go"
                authority = component "Certificate authority" "Holds the in-memory CA, hot-reloads the cert/key on disk change via an fsnotify watcher, and retains previous CAs across rotation." "Go, fsnotify + crypto/x509"
                signerCore = component "Signer" "Builds and signs the leaf certificate from the CSR and resolved configuration; assembles the trust bundle for the signer." "Go, crypto/x509"
                ctbPublisher = component "ClusterTrustBundle publisher" "Leader-gated runnable that reconciles the signer's ClusterTrustBundle towards the current CA on reload events and a drift-repair tick." "Go, controller-runtime"
                probes = component "Health & readiness" "Serves healthz/readyz; readiness is gated on CA watcher/reload health and on the ClusterTrustBundle publisher outcome." "Go, healthz"
                metrics = component "Metrics" "Exposes Prometheus metrics, including ClusterTrustBundle publish failures." "Go, Prometheus"
            }
        }

        # People
        operator -> caSource "Provisions the CA (Secret) and rotates it"
        operator -> signer "Installs and configures via the Helm chart"
        workload -> apiServer "Declares a podCertificate projected volume"

        # System context
        signer -> apiServer "Watches and updates PodCertificateRequests; publishes the ClusterTrustBundle" "watch/patch"
        signer -> caSource "Loads and hot-reloads the CA cert/key" "read-only mount"
        apiServer -> kubelet "Delivers the issued credential bundle and ClusterTrustBundle"
        kubelet -> apiServer "Creates the PodCertificateRequest with a PKCS#10 CSR"

        # Container level
        controller -> apiServer "Reconciles PodCertificateRequests and the ClusterTrustBundle" "watch/patch, HTTPS"
        controller -> caSource "Reads and watches the CA files" "read-only mount"

        # Component level
        reconciler -> config "Validates and resolves the requested configuration"
        reconciler -> signerCore "Signs on success / records deny outcome"
        config -> authority "Fits the certificate lifetime inside CA validity"
        signerCore -> authority "Signs the leaf with the current CA key"
        authority -> caSource "Watches and reloads the cert/key" "fsnotify"
        ctbPublisher -> authority "Reads the current trust bundle PEM"
        ctbPublisher -> apiServer "Creates/patches the ClusterTrustBundle" "HTTPS"
        probes -> authority "Polls CA watcher/reload health"
        probes -> ctbPublisher "Polls last publish outcome"
        reconciler -> apiServer "Reads the requesting pod (uncached get) and updates request status" "HTTPS"
    }

    views {
        systemContext signer "SystemContext" "Who the signer serves and what it depends on." {
            include *
            autoLayout
        }

        container signer "Containers" "The signer as a single deployable and the systems it integrates with." {
            include *
            autoLayout
        }

        component controller "Components" "The reconcile, CA and publication components inside the controller." {
            include *
            autoLayout
        }

        styles {
            element "Person" {
                shape Person
                background #08427b
                color #ffffff
            }
            element "Software System" {
                background #1168bd
                color #ffffff
            }
            element "Container" {
                background #438dd5
                color #ffffff
            }
            element "Component" {
                background #85bbf0
                color #000000
            }
            element "External" {
                background #999999
                color #ffffff
            }
        }
    }
}
