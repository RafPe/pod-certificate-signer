# development-hints
Some hints to quickly come back to portions of code if needed

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