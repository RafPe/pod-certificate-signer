workspace "pod-certificate-signer" "Signer for the built-in PodCertificateRequest API. It issues short-lived pod certificates and publishes its CA as a ClusterTrustBundle." {

    model {
        operator = person "Cluster operator" "Installs the chart, provides the signing CA, sets the signer name and rotates the CA."
        workload = person "Workload author" "Creates pods that request a certificate through a podCertificate projected volume."

        apiServer = softwareSystem "kube-apiserver" "Stores PodCertificateRequests after it verifies their pod identity fields. Enforces the status contract. Serves the ClusterTrustBundle." {
            tags "External"
        }

        kubelet = softwareSystem "kubelet" "Generates the key pair and the PKCS#10 CSR. Creates the PodCertificateRequest. Writes the issued credential bundle and the ClusterTrustBundle into the pod and refreshes them." {
            tags "External"
        }

        caSource = softwareSystem "Signing CA source" "The CA certificate and private key, mounted read-only from a Kubernetes Secret (recommended) or a bring-your-own volume." {
            tags "External"
        }

        scraper = softwareSystem "Metrics scraper" "Prometheus or another scraper. Sends a ServiceAccount token that the metrics-reader ClusterRole authorizes." {
            tags "External"
        }

        signer = softwareSystem "pod-certificate-signer" "Watches PodCertificateRequests for its signer name, issues or denies short-lived certificates from the CA, and publishes the signer's ClusterTrustBundle." {
            controller = container "Controller" "controller-runtime manager. Runs the reconciler and the ClusterTrustBundle publisher on the elected leader, and the CA watcher on every replica." "Go, distroless/static:nonroot" {
                reconciler = component "PodCertificateRequest reconciler" "Leader-gated. Validates each request and records the outcome." "Go, controller-runtime"
                config = component "Certificate configuration" "Parses the CSR and resolves the certificate configuration." "Go"
                authority = component "Certificate authority" "Runs on every replica. Holds the CA and signs leaf certificates." "Go, fsnotify, crypto/x509"
                ctbPublisher = component "ClusterTrustBundle publisher" "Leader-gated. Publishes the CA trust bundle." "Go, controller-runtime"
                probes = component "Health and readiness" "Serves /healthz and /readyz." "Go, controller-runtime healthz"
                metrics = component "Metrics" "Serves the bounded Prometheus metrics." "Go, Prometheus"
            }
        }

        # Context level
        operator -> caSource "Provisions and rotates the CA"
        operator -> signer "Installs and configures" "Helm"
        workload -> apiServer "Creates pods with podCertificate volumes"
        kubelet -> apiServer "Creates requests, reads certificates" "HTTPS"
        signer -> apiServer "Watches requests, writes status" "HTTPS"
        signer -> apiServer "Publishes ClusterTrustBundle" "HTTPS"
        signer -> caSource "Reads and watches CA files" "read-only volume mount"
        kubelet -> signer "Probes health" "HTTP :8081"
        scraper -> signer "Scrapes metrics" "HTTPS :9090"

        # Container level
        operator -> controller "Installs and configures" "Helm"
        controller -> apiServer "Watches requests, writes status" "HTTPS"
        controller -> apiServer "Publishes ClusterTrustBundle" "HTTPS"
        controller -> apiServer "Renews Lease, reviews scrape tokens" "HTTPS"
        controller -> caSource "Reads and watches CA files" "read-only volume mount"
        kubelet -> controller "Probes health" "HTTP :8081"
        scraper -> controller "Scrapes metrics" "HTTPS :9090"

        # Component level
        reconciler -> apiServer "Watches requests, gets pod, writes status" "HTTPS"
        reconciler -> config "Resolves configuration"
        reconciler -> authority "Signs leaf certificate"
        authority -> caSource "Reads and watches CA files" "read-only volume mount"
        authority -> ctbPublisher "Signals CA change"
        ctbPublisher -> authority "Reads trust bundle"
        ctbPublisher -> apiServer "Publishes ClusterTrustBundle" "HTTPS"
        probes -> authority "Checks CA health"
        probes -> ctbPublisher "Checks publish result"
        metrics -> authority "Reads CA gauges"
        metrics -> apiServer "Reviews scrape tokens" "TokenReview, SubjectAccessReview"
        kubelet -> probes "Probes health" "HTTP :8081"
        scraper -> metrics "Scrapes metrics" "HTTPS :9090"
    }

    views {
        systemContext signer "SystemContext" "Who the signer serves and what it depends on." {
            include *
            include workload
            autoLayout
        }

        container signer "Containers" "The signer as a single deployable and the systems it integrates with." {
            include *
            autoLayout
        }

        component controller "Components" "The reconcile, CA, publication, health and metrics components inside the controller." {
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
