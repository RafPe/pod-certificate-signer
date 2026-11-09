/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap/zapcore"
	// The OIDC client auth provider, for out-of-cluster runs (make run)
	// against a kubeconfig that authenticates with OIDC. It is the only
	// provider the client-go auth umbrella package still registers; exec-based
	// credential plugins need no import. In-cluster the ServiceAccount token
	// is used and this is inert.
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/controller"
	signermetrics "github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/podcertificate"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/trustbundle"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

const (
	// controllerName is the controller-runtime controller name, the logger
	// name and the reporter on every event the controller emits.
	controllerName = "PodCertificateSigner"

	// defaultEnableAnnotationInterpolation is the shipped default for
	// --enable-annotation-interpolation. On: a ${...} placeholder resolves
	// only from apiserver-verified PodCertificateRequest fields plus the
	// operator's --cluster-fqdn, and the resolved value must still clear the
	// verified-identity allowlist unless --allow-unverified-identities is set -
	// so turning it on grants no identity the pod does not already own. See
	// docs/adr/0002-annotation-interpolation-on-by-default.md.
	//
	// Keep it in sync with the chart value signer.enable_annotation_interpolation;
	// the two are one decision stored twice and
	// TestChartSecurityDefaultsMatchBinary guards the drift.
	defaultEnableAnnotationInterpolation = true

	// defaultAllowUnverifiedIdentities is the shipped default for
	// --allow-unverified-identities: off, so a pod cannot request a certificate
	// for an identity it does not own. Mirrored by the chart value
	// signer.allow_unverified_identities.
	defaultAllowUnverifiedIdentities = false

	// defaultMetricsSecure is the shipped default for --metrics-secure: the
	// metrics endpoint is served over HTTPS and every scrape is authenticated
	// and authorized. Mirrored, inverted, by the chart value metrics.insecure.
	defaultMetricsSecure = true

	// defaultAllowPodAnnotations keeps the deprecated pod-annotation
	// configuration fallback on until it is removed in 4.0.0. Mirrored by the
	// chart value signer.allow_pod_annotations.
	defaultAllowPodAnnotations = true
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

// flags holds the parsed command-line flags. It is filled by registerFlags so
// the registrations, their defaults and their help text can be exercised by a
// test against a private FlagSet rather than the process-global one. Flags
// that configure a component bind straight into that component's settings
// struct, so nothing is copied field by field afterwards.
type flags struct {
	signerName, caCertPath, caKeyPath string
	maxPreviousCAs                    int
	requireCAHistory                  bool
	manager                           managerConfig
	certOpts                          podcertificate.Options
}

// registerFlags declares every command-line flag on fs and returns the struct
// their parsed values land in.
func registerFlags(fs *flag.FlagSet) *flags {
	f := &flags{}
	fs.StringVar(&f.signerName, "signer-name", "", "Only sign PodCertificateRequests with this .spec.signerName. Required.")
	fs.StringVar(&f.caCertPath, "ca-cert-path", "", "CA certificate file.")
	fs.StringVar(&f.caKeyPath, "ca-key-path", "", "CA private key file.")
	fs.StringVar(&f.certOpts.ClusterFQDN, "cluster-fqdn", podcertificate.DefaultClusterFQDN, "The FQDN of the cluster.")
	fs.StringVar(&f.manager.leaderElectionID, "leader-election-id", "pcs-leader-election",
		"The name of the Lease used to coordinate leader election between replicas.")
	fs.StringVar(&f.manager.leaderElectionNamespace, "leader-election-namespace", "",
		"Namespace for leader election (default: pod's namespace).")
	fs.StringVar(&f.manager.healthProbeBindAddress, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	fs.BoolVar(&f.manager.leaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	fs.StringVar(&f.manager.metricsBindAddress, "metrics-bind-address", ":9090", "The address on which to bind the metrics server.")
	fs.BoolVar(&f.manager.metricsSecure, "metrics-secure", defaultMetricsSecure,
		"Serve the metrics endpoint over HTTPS and require authentication (TokenReview) and authorization "+
			"(SubjectAccessReview) for every scrape. On by default. Set to false to fall back to the legacy "+
			"unauthenticated plaintext endpoint - see the chart's metrics.insecure escape hatch.")
	fs.IntVar(&f.manager.maxConcurrentReconciles, "max-concurrent-reconciles", 5, "Maximum number of concurrent reconciles.")
	fs.IntVar(&f.maxPreviousCAs, "max-previous-ca-certs", 2, "Maximum number of previous CA certificates to retain across CA rotations.")
	fs.BoolVar(&f.requireCAHistory, "require-ca-history", false,
		"Refuse to start when the signer's ClusterTrustBundle does not exist, instead of starting with an empty "+
			"previous-CA history. Off by default, because a first install has no bundle yet and the controller cannot "+
			"tell that apart from one that was deleted. Turn it on once the signer has published its bundle, so a "+
			"deleted bundle cannot silently reset the retained CA history (see docs/operations.md).")
	fs.DurationVar(&f.manager.reconcileTimeout, "reconcile-timeout", 5*time.Minute, "Maximum duration of a reconcile before it times out.")
	fs.BoolVar(&f.certOpts.EnableInterpolation, "enable-annotation-interpolation", defaultEnableAnnotationInterpolation,
		"Allow ${...} placeholders (e.g. ${pod.name}, ${pod.serviceAccountName}) in certificate configuration annotations, "+
			"resolved from the verified fields of the PodCertificateRequest. On by default; resolved values remain subject "+
			"to the identity constraints unless --allow-unverified-identities is set. Set to false to deny any value "+
			"containing ${...} instead of resolving it.")
	fs.BoolVar(&f.certOpts.HonorCSRSANs, "honor-csr-sans", false,
		"Honor DNS and IP SANs embedded in the kubelet-generated PKCS#10 CSR when no SAN annotation overrides them. "+
			"CSR SANs stay subject to the identity constraints unless --allow-unverified-identities is set (CSR DNS SANs "+
			"must be a verified identity; CSR IP SANs are denied). Kubelet generates empty CSRs today; this prepares for "+
			"upcoming Kubernetes support for requesting SANs.")
	fs.BoolVar(&f.certOpts.AllowUnverifiedIdentities, "allow-unverified-identities", defaultAllowUnverifiedIdentities,
		"Allow cn/san/ip-san/uris annotation values that are not derived from the verified PodCertificateRequest fields "+
			"(pod name, namespace and serviceAccountName + cluster FQDN), and, with --honor-csr-sans, CSR SANs. Off by default: "+
			"leaving it off prevents a pod from requesting a certificate for an identity it does not own.")
	fs.BoolVar(&f.certOpts.AllowPodAnnotations, "allow-pod-annotations", defaultAllowPodAnnotations,
		"Fall back to the pod's own annotations for configuration values the PodCertificateRequest does not carry in "+
			"spec.unverifiedUserAnnotations. Deprecated and removed in 4.0.0; on by default until then. Set to false once "+
			"every workload has moved to spec.unverifiedUserAnnotations, so pod annotations stop influencing issuance.")
	return f
}

func main() {
	fs := flag.CommandLine
	f := registerFlags(fs)
	opts := zap.Options{
		Development:     true,
		TimeEncoder:     zapcore.ISO8601TimeEncoder,
		StacktraceLevel: zapcore.DPanicLevel,
	}
	opts.BindFlags(fs)
	// flag.CommandLine exits on a parse error, so there is no error to handle.
	_ = fs.Parse(os.Args[1:])

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// run returns only once the manager has stopped (or failed to start), and
	// the process exits straight after: ADR-0006 relies on that.
	if err := run(ctrl.SetupSignalHandler(), fs, f); err != nil {
		setupLog.Error(err, "controller manager exited with an error")
		os.Exit(1)
	}
}

// run wires the signer and runs the controller manager until ctx is canceled.
// Every setup step that fails returns its error, so main has one exit point.
// mgr.Start is its last statement: see the PRECONDITION in managerOptions.
func run(ctx context.Context, fs *flag.FlagSet, f *flags) error {
	if err := validateFlags(f.signerName, f.certOpts); err != nil {
		return fmt.Errorf("invalid command-line flags: %w", err)
	}

	restCfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	mgr, err := ctrl.NewManager(restCfg, managerOptions(scheme, ctx, f.manager))
	if err != nil {
		return fmt.Errorf("create controller manager: %w", err)
	}

	// Bootstrap previous CA certificates from the existing ClusterTrustBundle
	// so that we retain trust across CA rotations even after a restart. The
	// bundle is a cluster-scoped object this controller does not exclusively
	// own, so what is read from it is bounded and validated rather than
	// adopted: ADR-0004.
	//
	// This needs its own client: the manager is not started yet, and the
	// publisher must not go through the manager cache anyway (see
	// trustbundle.NewPublisher).
	c, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("create API client: %w", err)
	}
	previousCAs, err := trustbundle.LoadPreviousCAHistory(ctx, c, f.signerName, f.requireCAHistory)
	if err != nil {
		return fmt.Errorf("bootstrap the previous-CA history; refusing to start to avoid dropping previously-trusted CAs: %w", err)
	}
	ca, err := authority.New(
		f.caCertPath,
		f.caKeyPath,
		authority.WithPreviousCAs(previousCAs),
		authority.WithMaxPreviousCAs(f.maxPreviousCAs),
		authority.WithLogger(ctrl.Log.WithName("certificate-authority")),
	)
	if err != nil {
		return fmt.Errorf("create certificate authority: %w", err)
	}

	// The signer's custom metric surface is bounded by decision, not by
	// convenience: see ADR-0005 (docs/adr/0005-bounded-metrics-surface.md).
	// Registering into controller-runtime's registry puts it on the manager's
	// existing SecureServing metrics endpoint, so there is no new transport.
	// This runs here rather than in init() because the CA gauges are read from
	// the loaded CA at scrape time, so the collector needs it to exist.
	if err := signermetrics.Register(metrics.Registry, signermetrics.NewCACollector(ca)); err != nil {
		return fmt.Errorf("register the signer metrics: %w", err)
	}

	// Wire the CA file watcher and the ClusterTrustBundle publisher: the
	// watcher signals the publisher whenever a reload changed the CA. The
	// watcher runs on every replica so standby replicas keep their in-memory
	// CA current; the publisher is leader-gated so only the elected leader
	// writes the shared ClusterTrustBundle.
	ctbPublisher := trustbundle.NewPublisher(c, f.signerName, ca)
	if err := mgr.Add(authority.NewWatcher(ca, ctbPublisher.Notify())); err != nil {
		return fmt.Errorf("add CA watcher runnable: %w", err)
	}
	if err := mgr.Add(ctbPublisher); err != nil {
		return fmt.Errorf("add ClusterTrustBundle publisher runnable: %w", err)
	}

	reconciler, err := controller.NewPodCertificateRequestReconciler(mgr, controllerName, f.signerName, ca, f.certOpts)
	if err != nil {
		return fmt.Errorf("create controller %s: %w", controllerName, err)
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("set up controller %s: %w", controllerName, err)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("set up health check: %w", err)
	}
	// Gate readiness on the CA's watcher/reload health: a replica that can no
	// longer observe CA rotations, or whose reloads have been failing
	// persistently, must be pulled from readiness so it is not relied upon to
	// publish or sign with stale material. A transient reload failure keeps the
	// replica ready, since the last-good CA is retained and signing works.
	if err := mgr.AddReadyzCheck("certificate-authority", readyzCheck(ca)); err != nil {
		return fmt.Errorf("set up CA ready check: %w", err)
	}
	// Also gate readiness on the ClusterTrustBundle publisher: a leader whose
	// publishes keep failing must be pulled from readiness so the failure is
	// visible and traffic/leadership can move elsewhere.
	if err := mgr.AddReadyzCheck("clustertrustbundle", readyzCheck(ctbPublisher)); err != nil {
		return fmt.Errorf("set up ClusterTrustBundle ready check: %w", err)
	}

	displayCommandlineFlags(fs)

	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("run controller manager: %w", err)
	}
	return nil
}

// validateFlags checks command-line flags that must fail before the controller
// establishes a Kubernetes API connection.
func validateFlags(signerName string, certOpts podcertificate.Options) error {
	if signerName == "" {
		return errors.New("the --signer-name flag is required")
	}
	// Options treats an empty ClusterFQDN as "use the default", which suits
	// callers that never set it. An operator who passes --cluster-fqdn= (an
	// empty Helm signer.cluster_fqdn renders exactly that) has set it, and
	// silently signing under cluster.local would be wrong in a custom-domain
	// cluster, so the flag must not be empty.
	if certOpts.ClusterFQDN == "" {
		return errors.New("the --cluster-fqdn flag must not be empty")
	}
	if err := certOpts.Validate(); err != nil {
		return fmt.Errorf("invalid --cluster-fqdn: %w", err)
	}
	return nil
}

// managerConfig carries the controller-manager settings. registerFlags binds
// the manager flags straight into it, and tests build it as a literal.
type managerConfig struct {
	healthProbeBindAddress  string
	metricsBindAddress      string
	metricsSecure           bool
	leaderElection          bool
	leaderElectionID        string
	leaderElectionNamespace string
	maxConcurrentReconciles int
	reconcileTimeout        time.Duration
}

// managerOptions builds the controller-manager options from cfg, with
// baseContext as the context every runnable derives from.
func managerOptions(scheme *runtime.Scheme, baseContext context.Context, cfg managerConfig) ctrl.Options {
	return ctrl.Options{
		Scheme:                  scheme,
		HealthProbeBindAddress:  cfg.healthProbeBindAddress,
		LeaderElection:          cfg.leaderElection,
		LeaderElectionID:        cfg.leaderElectionID,
		LeaderElectionNamespace: cfg.leaderElectionNamespace,
		// Release the Lease on a voluntary shutdown instead of leaving a
		// follower to wait out the 15s LeaseDuration. Measured on a
		// two-replica Kind deployment: median pod-delete handover 16.3s ->
		// 1.2s, and a rolling upgrade's leaderless window ~15.2s -> ~1.9s.
		// Both the ClusterTrustBundle publisher and the PodCertificateRequest
		// reconciler are leader-gated, so that window is a signing-latency
		// gap, not only a publishing one. Involuntary loss (node failure,
		// SIGKILL) still falls back to Lease expiry.
		//
		// PRECONDITION: the process must exit as soon as the manager stops, so
		// mgr.Start stays the last statement in run(), and main exits as soon
		// as run returns. The release is
		// deferred until every runnable has returned, but only within
		// GracefulShutdownTimeout (30s default); past that deadline the Lease
		// is released with leader-gated code possibly still live. So every
		// leader-gated runnable's shutdown must be bounded by its context - an
		// unbounded retry would break this silently.
		//
		// ADR-0006 (docs/adr/0006-release-leader-lease-on-cancel.md).
		LeaderElectionReleaseOnCancel: true,
		BaseContext:                   func() context.Context { return baseContext },
		Metrics:                       metricsServerOptions(cfg),
		Controller: config.Controller{
			MaxConcurrentReconciles: cfg.maxConcurrentReconciles,
			RecoverPanic:            new(true),
			ReconciliationTimeout:   cfg.reconcileTimeout,
		},
		// Pods are excluded from the manager cache: the controller only does
		// point Gets by name (and re-reads live via the APIReader for
		// identity), so a cluster-wide pod informer would waste memory and
		// require list/watch RBAC. Pod reads fall through to the API server.
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{&corev1.Pod{}},
			},
		},
	}
}

// metricsServerOptions builds the metrics server options from cfg. By default
// the endpoint is served over HTTPS and every scrape is authenticated (via a
// TokenReview) and authorized (via a SubjectAccessReview) against the
// kube-apiserver, so metrics are not exposed to any pod that can reach the
// service. The insecure escape hatch restores the legacy plaintext,
// unauthenticated endpoint for operators who explicitly opt into it.
//
// The self-signed serving certificate is generated in memory by
// controller-runtime (no on-disk fixture directory is configured), so this is
// compatible with a read-only root filesystem.
func metricsServerOptions(cfg managerConfig) server.Options {
	opts := server.Options{
		BindAddress: cfg.metricsBindAddress,
	}
	if cfg.metricsSecure {
		opts.SecureServing = true
		// FilterProvider authenticates the bearer token and authorizes the
		// "get" verb on the /metrics nonResourceURL. The controller's
		// ServiceAccount therefore needs create on tokenreviews and
		// subjectaccessreviews (wired in the chart ClusterRole), and scrapers
		// need get on the /metrics nonResourceURL (the metrics-reader
		// ClusterRole).
		opts.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	return opts
}

// healthChecker is anything that can report, through HealthCheck, that it is
// no longer doing its job: the CA that lost track of its on-disk material, or
// the publisher whose writes keep failing.
type healthChecker interface {
	HealthCheck() error
}

// readyzCheck adapts a healthChecker into a controller-runtime readiness
// check, so a degraded component removes the replica from readiness.
func readyzCheck(h healthChecker) healthz.Checker {
	return func(_ *http.Request) error {
		return h.HealthCheck()
	}
}

// displayCommandlineFlags logs every flag on fs with its value and default.
func displayCommandlineFlags(fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		setupLog.Info("command-line flag",
			"name", f.Name,
			"value", f.Value.String(),
			"default", f.DefValue)
	})
}
