# kubernetes-podcertificate-signer
Custom signer for PodCertificateRequests




## Development in progress 


```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: podcertificate-deployment
spec:
  replicas: 1
  selector:
    matchLabels:
      app: podcertificate-app
  template:
    metadata:
      labels:
        app: podcertificate-app
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
              keyType: ED25519
              signerName: coolcert.example.com/foo
              credentialBundlePath: credentialbundle.pem
```

```sh
kubebuilder init --domain=operators.raftech.io --repo=github.com/rafpe/kubernetes-podcertificate-signer --project-name podcert
kubebuilder create api --group certificates --version v1alpha1 --kind PodCertificateRequest --controller --resource=false
```