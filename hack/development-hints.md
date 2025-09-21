# development-hints
Some hints to quickly come back to portions of code if needed

## Logs 

```
func (r *PodCertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	//r.Log = logf.Log.WithName("PodCertificateRequestReconciler").WithValues("request-name", req.Name)
	// r.Log = logf.FromContext(ctx)
```