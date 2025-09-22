# kubernetes-podcertificate-signer

Kubernetes v1.34+ comes with new feature called [PodCertificateRequest](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#pod-certificate-requests) that enables native handling of x509 certificates to pods via projected volumes. 
This in combination with [Cluster Trust Bundles](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles) is going to allow for easy , native and declarative way of securing workloads communication with TLS/mTLS in your cluster(s). 

> This controller is not yet ready to deploy to PRODUCTION facing worklads - it is being actively developed and should be considered for TESTING and validating concepts now

- [kubernetes-podcertificate-signer](#kubernetes-podcertificate-signer)
- [Why this controller](#why-this-controller)
  - [Controller flow](#controller-flow)
- [Running the controller](#running-the-controller)
  - [Prerequisites - valid CA](#prerequisites---valid-ca)
  - [Deploying controller to Kubernetes](#deploying-controller-to-kubernetes)
  - [Controller commandline options](#controller-commandline-options)
    - [New PodCertificateRequest](#new-podcertificaterequest)
  - [Certificate configuration](#certificate-configuration)
  - [Applying configuration for certificates](#applying-configuration-for-certificates)
  - [Requesting PodCertificates](#requesting-podcertificates)
  - [Examples of workload](#examples-of-workload)
- [Development](#development)
  - [Running locally with kind](#running-locally-with-kind)
  - [TODOs](#todos)
  - [TLS / mTLS and client\&server auth](#tls--mtls-and-clientserver-auth)


# Why this controller
The main idea of this controller is leveraging on native functionalities/features of Kubernetes to automate and secure your cluster workloads with short living x509 certificates issued per pod. 

## Controller flow
Below you can see current chart showing how the flow of actions looks from a high level overview.

# Running the controller
Running the controller requires that you have a valid CA certificate and key ( can be of course self signed i.e. with [cfssl](https://github.com/cloudflare/cfssl) ) and determine what will be your designated `signer-name` for the controller. 

As a reminder - `one controller --(runs)--> one signer ( with user provided CA )` 

## Prerequisites - valid CA
As mentioned before running the controller sucessfully - requires a valid CA. There are many ways of approaching this being generating the CA via tool like the [cfssl](https://github.com/cloudflare/cfssl) or leverage [`cert-manager`](https://cert-manager.io/) 


```sh
kubectl create secret tls ca-secret \
  --cert=ca.pem \
  --key=ca-key.pem
```

Once a CA is generated you can easily mount it to the controller container via volume mounts

```yaml
  # ..... content not relevant for the example
        volumes:
        - name: ca-secret
        secret:
            secretName: ca-secret
            items:
            - key: tls.crt
            path: ca.pem
            - key: tls.key
            path: ca-key.pem
    volumeMounts:
    - name: ca-secret
    mountPath: /etc/ssl/ca
    readOnly: true
  # ..... content not relevant for the example
```

## Deploying controller to Kubernetes


## Controller commandline options
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


### New PodCertificateRequest
Is currently the default flow in our controller and is being the heart of its logic.

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

## Certificate configuration
First and foremost the current implementation of the signer is based on the principle that one controller is one signer - and this is done to keep things simple and handle designated areas of responsibilities. 
In order to not use defaults for certificate being generated - operator is able to set customize that via [`annotations`](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/). 

The scheme for configuration is `signer-domain/name-<configuration-item>: <value>`

Below is the table with the annotations and example values: 

| Annotation Prefix        | Required | Default Value                                                                       | Example                                                                                              |
| ------------------------ | -------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `{signer-name}-cn`       | No       | `{pod-name}`                                                                        | `mysigner.example.com/foobar-cn: my-pod.default.pod.cluster.local`                                   |
| `{signer-name}-san`      | No       | `{pod-name}.{namespace}.pod.cluster.local,{pod-name}.{namespace}.svc.cluster.local` | `mysigner.example.com/foobar-san: my-pod.default.pod.cluster.local,my-pod.default.svc.cluster.local` |
| `{signer-name}-uris`     | No       | `(empty)`                                                                           | `mysigner.example.com/foobar-uris: spiffe://cluster.local/ns/default/sa/my-service`                  |
| `{signer-name}-duration` | No       | `24h`                                                                               | `mysigner.example.com/foobar-duration: 12h`                                                          |
| `{signer-name}-refresh`  | No       | `1h`                                                                                | `mysigner.example.com/foobar-refresh: 30m`                                                           |

## Applying configuration for certificates
By adding the annotations specified you are then able to control specifics of certificates being generated.
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

## Requesting PodCertificates
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
              signerName: coolcert.example.com/foo
              credentialBundlePath: credentialbundle.pem

  # ..... rest of the manifest              
```


## Examples of workload
To test your signer you can run the following example below 
> Make sure the `signer` name matches the one you created your controller with

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pcr
spec:
  replicas: 1
  selector:
    matchLabels:
      app: podcertificate-app
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
      serviceAccountName: default
      containers:
      - image: debian
        name: main
        command: ["sleep", "infinity"]
        volumeMounts:
        - name: my-x509-credentials
          mountPath: /var/run/my-x509-credentials
      volumes:
      - name: my-x509-credentials
        projected:
          defaultMode: 420
          sources:
          - podCertificate:
              keyType: RSA
              signerName: coolcert.example.com/foo
              credentialBundlePath: credentialbundle.pem
```

# Development
## Running locally with kind

## TODOs
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

## TLS / mTLS and client&server auth
<!-- TODO: Add here details ... -->

