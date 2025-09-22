# development-hints
Some hints to quickly come back to portions of code if needed

## Initializing the project

```sh
kubebuilder init --domain=operators.raftech.io --repo=github.com/rafpe/kubernetes-podcertificate-signer --project-name podcert
kubebuilder create api --group certificates --version v1alpha1 --kind PodCertificateRequest --controller --resource=false
```

## To Requeue or not 

```
			// DON'T REQUEUE - Terminal success
			return ctrl.Result{}, nil
		
			// DON'T REQUEUE - Terminal failure (log error but don't retry)
			if terminalError {
				r.Log.Error(err, "Terminal error - not retrying")
				return ctrl.Result{}, nil // nil error = no requeue
			}
		
			// REQUEUE - Transient error (will retry with exponential backoff)
			return ctrl.Result{}, fmt.Errorf("transient error: %w", err)
		
			// REQUEUE AFTER SPECIFIC TIME - Scheduled retry
			return ctrl.Result{RequeueAfter: 5 * time.Minute}, nil
```

## Logs 

```
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	//r.Log = logf.Log.WithName("PodCertificateRequestReconciler").WithValues("request-name", req.Name)
	// r.Log = logf.FromContext(ctx)
```

## Debugging log 
```
 	r.Log.V(1).Info("Setting the certificate in the PodCertificateRequest",
 		"podName", pcr.Spec.PodName,
 		"commonName", podCertificate.Config.CommonName,
 		"dnsNames", podCertificate.Config.DNSNames,
 		"duration", podCertificate.Config.Duration.String(),
 		"refreshBefore", podCertificate.Config.RefreshBefore.String(),
 		"beginRefreshAt", beginRefreshAt.Format(time.RFC1123Z))
```


## Certificate options/paths

### Add custom OIDs 
Would require a lot of work to get official OIDs registered - but long term run would be amazing to have a dedicatd Kubernetes OIDs registered

### Add to certificate pod/cluster metadata via Enhanced Subject  
This approach would use something like 

```
template := &x509.Certificate{
    // ... existing fields ...
    Subject: pkix.Name{
        // Primary identity
        CommonName: "my-pod.default.svc.cluster.local",
        
        // Organizational structure
        Organization:       []string{"kubernetes.io"},
        OrganizationalUnit: []string{"pods", "default"},
        
        // Geographic information
        Country:      []string{"US"},
        Province:     []string{"Kubernetes"},
        Locality:     []string{"Cluster"},
        StreetAddress: []string{"10.244.0.0/16"}, // Pod network
        PostalCode:   []string{"k8s-001"},
    },
}
```

Could build functions around it like 
```
func buildKubernetesSubject(config *podcertificate.PodCertificateConfig) pkix.Name {
    return pkix.Name{
        // Primary identity - follows Kubernetes naming conventions
        CommonName: fmt.Sprintf("%s.%s.svc.cluster.local", 
            config.PodName, config.Namespace),
        
        // Organizational hierarchy
        Organization: []string{
            "kubernetes.io",
            "cluster.local",
        },
        OrganizationalUnit: []string{
            "pods",
            config.Namespace,
            config.NodeName, // Node affinity
        },
        
        // Geographic/Logical location
        Country:      []string{"K8S"}, // Kubernetes identifier
        Province:     []string{config.Namespace},
        Locality:     []string{config.NodeName},
        StreetAddress: []string{config.PodIP},
        PostalCode:   []string{config.UID},
    }
}

func (ca *CertificateAuthority) buildEnhancedSubject(config *podcertificate.PodCertificateConfig) pkix.Name {
    // Build comprehensive subject information
    subject := pkix.Name{
        CommonName: ca.buildCommonName(config),
        Organization: ca.buildOrganizations(config),
        OrganizationalUnit: ca.buildOrganizationalUnits(config),
        Country: ca.buildCountries(config),
        Province: ca.buildProvinces(config),
        Locality: ca.buildLocalities(config),
        StreetAddress: ca.buildStreetAddresses(config),
        PostalCode: ca.buildPostalCodes(config),
    }
    
    return subject
}

func (ca *CertificateAuthority) buildCommonName(config *podcertificate.PodCertificateConfig) string {
    // Priority order for CommonName
    if config.ServiceName != "" {
        return fmt.Sprintf("%s.%s.svc.cluster.local", 
            config.ServiceName, config.Namespace)
    }
    return fmt.Sprintf("%s.%s.pod.cluster.local", 
        config.PodName, config.Namespace)
}

func (ca *CertificateAuthority) buildOrganizations(config *podcertificate.PodCertificateConfig) []string {
    orgs := []string{"kubernetes.io"}
    
    // Add cluster-specific organization
    if clusterName := config.Annotations["cluster.kubernetes.io/cluster-name"]; clusterName != "" {
        orgs = append(orgs, clusterName)
    }
    
    // Add environment-specific organization
    if env := config.Labels["environment"]; env != "" {
        orgs = append(orgs, fmt.Sprintf("env-%s", env))
    }
    
    return orgs
}

func (ca *CertificateAuthority) buildOrganizationalUnits(config *podcertificate.PodCertificateConfig) []string {
    ous := []string{"pods"}
    
    // Add namespace as OU
    if config.Namespace != "" {
        ous = append(ous, config.Namespace)
    }
    
    // Add node as OU for node affinity
    if config.NodeName != "" {
        ous = append(ous, fmt.Sprintf("node-%s", config.NodeName))
    }
    
    // Add service as OU if available
    if config.ServiceName != "" {
        ous = append(ous, fmt.Sprintf("service-%s", config.ServiceName))
    }
    
    // Add security context as OU
    if config.RunAsUser != nil {
        ous = append(ous, fmt.Sprintf("user-%d", *config.RunAsUser))
    }
    
    return ous
}

func (ca *CertificateAuthority) buildCountries(config *podcertificate.PodCertificateConfig) []string {
    countries := []string{"K8S"} // Kubernetes identifier
    
    // Add environment as country code
    if env := config.Labels["environment"]; env != "" {
        countries = append(countries, strings.ToUpper(env[:2]))
    }
    
    return countries
}

func (ca *CertificateAuthority) buildProvinces(config *podcertificate.PodCertificateConfig) []string {
    provinces := []string{config.Namespace}
    
    // Add zone/region information
    if zone := config.Labels["topology.kubernetes.io/zone"]; zone != "" {
        provinces = append(provinces, zone)
    }
    
    return provinces
}

func (ca *CertificateAuthority) buildLocalities(config *podcertificate.PodCertificateConfig) []string {
    localities := []string{config.NodeName}
    
    // Add node zone information
    if nodeZone := config.Labels["topology.kubernetes.io/zone"]; nodeZone != "" {
        localities = append(localities, nodeZone)
    }
    
    return localities
}

func (ca *CertificateAuthority) buildStreetAddresses(config *podcertificate.PodCertificateConfig) []string {
    addresses := []string{config.PodIP}
    
    // Add service IP if available
    if serviceIP := config.Annotations["service.kubernetes.io/service-ip"]; serviceIP != "" {
        addresses = append(addresses, serviceIP)
    }
    
    return addresses
}

func (ca *CertificateAuthority) buildPostalCodes(config *podcertificate.PodCertificateConfig) []string {
    codes := []string{config.UID}
    
    // Add pod creation timestamp as postal code
    if creationTime := config.Annotations["kubernetes.io/created-at"]; creationTime != "" {
        codes = append(codes, creationTime)
    }
    
    return codes
}

```

```
Subject: CN=my-service.default.svc.cluster.local
         O=kubernetes.io
         O=my-cluster
         O=env-production
         OU=pods
         OU=default
         OU=node-worker-1
         OU=service-my-service
         OU=user-1000
         C=K8S
         C=PR
         ST=default
         ST=us-west-1a
         L=worker-1
         L=us-west-1a
         streetAddress=10.244.1.5
         streetAddress=10.96.0.1
         postalCode=abc123-def456-ghi789
         postalCode=2024-01-15T10:30:00Z
```