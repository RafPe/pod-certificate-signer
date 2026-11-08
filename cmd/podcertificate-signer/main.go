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
	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

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
	DefaultControllerName = "PodCertificateSigner"

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
	maxPreviousCACerts                int
	requireCAHistory                  bool
	manager                           managerConfig
	certificate                       podcertificate.Options
}

// registerFlags declares every command-line flag on fs and returns the struct
// their parsed values land in.
func registerFlags(fs *flag.FlagSet) *flags {
	f := &flags{}
	fs.StringVar(&f.signerName, "signer-name", "", "Only sign CSR with this .spec.signerName. Required.")
	fs.StringVar(&f.caCertPath, "ca-cert-path", "", "CA certificate file.")
	fs.StringVar(&f.caKeyPath, "ca-key-path", "", "CA private key file.")
	fs.StringVar(&f.certificate.ClusterFQDN, "cluster-fqdn", podcertificate.DefaultClusterFQDN, "The FQDN of the cluster")
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
	fs.IntVar(&f.manager.maxConcurrentReconciles, "max-concurrent-reconciles", 5, "maximum number of concurrent reconciles which can be run.")
	fs.IntVar(&f.maxPreviousCACerts, "max-previous-ca-certs", 2, "maximum number of previous CA certificates to keep during CA rotation.")
	fs.BoolVar(&f.requireCAHistory, "require-ca-history", false,
		"Refuse to start when the signer's ClusterTrustBundle does not exist, instead of starting with an empty "+
			"previous-CA history. Off by default, because a first install has no bundle yet and the controller cannot "+
			"tell that apart from one that was deleted. Turn it on once the signer has published its bundle, so a "+
			"deleted bundle cannot silently reset the retained CA history (see docs/operations.md).")
	fs.DurationVar(&f.manager.reconcileTimeout, "reconcile-timeout", 5*time.Minute, "maximum duration of a reconcile before it times out.")
	fs.BoolVar(&f.certificate.EnableInterpolation, "enable-annotation-interpolation", defaultEnableAnnotationInterpolation,
		"Allow ${...} placeholders (e.g. ${pod.name}, ${pod.serviceAccountName}) in certificate configuration annotations, "+
			"resolved from the verified fields of the PodCertificateRequest. On by default; resolved values remain subject "+
			"to the identity constraints unless --allow-unverified-identities is set. Set to false to deny any value "+
			"containing ${...} instead of resolving it.")
	fs.BoolVar(&f.certificate.HonorCSRSANs, "honor-csr-sans", false,
		"Honor DNS and IP SANs embedded in the kubelet-generated PKCS#10 CSR when no SAN annotation overrides them. "+
			"CSR SANs stay subject to the identity constraints unless --allow-unverified-identities is set (CSR DNS SANs "+
			"must be a verified identity; CSR IP SANs are denied). Kubelet generates empty CSRs today; this prepares for "+
			"upcoming Kubernetes support for requesting SANs.")
	fs.BoolVar(&f.certificate.AllowUnverifiedIdentities, "allow-unverified-identities", defaultAllowUnverifiedIdentities,
		"Allow cn/san/ip-san/uris annotation values that are not derived from the verified PodCertificateRequest fields "+
			"(pod name/namespace/serviceAccountName/uid + cluster FQDN). Off by default: leaving it off prevents a pod from "+
			"requesting a certificate for an identity it does not own.")
	fs.BoolVar(&f.certificate.AllowPodAnnotations, "allow-pod-annotations", defaultAllowPodAnnotations,
		"Fall back to the pod's own annotations for configuration values the PodCertificateRequest does not carry in "+
			"spec.unverifiedUserAnnotations. Deprecated and removed in 4.0.0; on by default until then. Set to false once "+
			"every workload has moved to spec.unverifiedUserAnnotations, so pod annotations stop influencing issuance.")
	return f
}

func main() {
	f := registerFlags(flag.CommandLine)
	opts := zap.Options{
		Development:     true,
		TimeEncoder:     zapcore.ISO8601TimeEncoder,
		StacktraceLevel: zapcore.DPanicLevel,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if err := validateFlags(f.signerName, f.certificate.ClusterFQDN); err != nil {
		setupLog.Error(err, "invalid command-line flags")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	restCfg := ctrl.GetConfigOrDie()

	mgr, err := ctrl.NewManager(restCfg, managerOptions(scheme, ctx, f.manager))
	if err != nil {
		setupLog.Error(err, "unable to create controller manager")
		os.Exit(1)
	}

	// Bootstrap previous CA certificates from the existing ClusterTrustBundle
	// so that we retain trust across CA rotations even after a restart. The
	// bundle is a cluster-scoped object this controller does not exclusively
	// own, so what is read from it is bounded and validated rather than
	// adopted: ADR-0004.
	//
	// This needs its own client: the manager is not started yet, and the
	// publisher must not go through the manager cache anyway (see
	// trustbundle.Publisher).
	c, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "unable to create API client")
		os.Exit(1)
	}
	previousCAs, err := trustbundle.LoadPreviousCAHistory(ctx, c, f.signerName, f.requireCAHistory)
	if err != nil {
		setupLog.Error(err, "unable to bootstrap the previous-CA history; "+
			"refusing to start to avoid dropping previously-trusted CAs")
		os.Exit(1)
	}
	ca, err := authority.New(
		f.caCertPath,
		f.caKeyPath,
		authority.WithPreviousCABundle(previousCAs),
		authority.WithMaxPreviousCertificates(f.maxPreviousCACerts),
		authority.WithLogger(ctrl.Log.WithName("certificate-authority")),
	)
	if err != nil {
		setupLog.Error(err, "unable to create certificate authority")
		os.Exit(1)
	}

	// The signer's custom metric surface is bounded by decision, not by
	// convenience: see ADR-0005 (docs/adr/0005-bounded-metrics-surface.md).
	// Registering into controller-runtime's registry puts it on the manager's
	// existing SecureServing metrics endpoint, so there is no new transport.
	// This runs here rather than in init() because the CA gauges are read from
	// the loaded CA at scrape time, so the collector needs it to exist.
	if err := signermetrics.Register(metrics.Registry, signermetrics.NewCACollector(ca)); err != nil {
		setupLog.Error(err, "unable to register the signer metrics")
		os.Exit(1)
	}

	// Wire the CA file watcher and the ClusterTrustBundle publisher. The
	// watcher runs on every replica so standby replicas keep their in-memory
	// CA current; the publisher is leader-gated so only the elected leader
	// writes the shared ClusterTrustBundle.
	caWatcher, ctbPublisher := trustbundle.NewRunnables(c, f.signerName, ca)
	if err := mgr.Add(caWatcher); err != nil {
		setupLog.Error(err, "unable to add CA watcher runnable")
		os.Exit(1)
	}
	if err := mgr.Add(ctbPublisher); err != nil {
		setupLog.Error(err, "unable to add ClusterTrustBundle publisher runnable")
		os.Exit(1)
	}

	reconciler, err := controller.NewPodCertificateRequestReconciler(mgr, DefaultControllerName, f.signerName, ca, f.certificate)
	if err != nil {
		setupLog.Error(err, "unable to create controller", "controller", DefaultControllerName)
		os.Exit(1)
	}
	if err := reconciler.SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to set up controller", "controller", DefaultControllerName)
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	// Gate readiness on the CA's watcher/reload health: a replica that can no
	// longer observe CA rotations, or whose reloads have been failing
	// persistently, must be pulled from readiness so it is not relied upon to
	// publish or sign with stale material. A transient reload failure keeps the
	// replica ready, since the last-good CA is retained and signing works.
	if err := mgr.AddReadyzCheck("readyz", readyzCheck(ca)); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}
	// Also gate readiness on the ClusterTrustBundle publisher: a leader whose
	// publishes keep failing must be pulled from readiness so the failure is
	// visible and traffic/leadership can move elsewhere.
	if err := mgr.AddReadyzCheck("clustertrustbundle", readyzCheck(ctbPublisher)); err != nil {
		setupLog.Error(err, "unable to set up ClusterTrustBundle ready check")
		os.Exit(1)
	}

	displayCommandlineFlags()

	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "unable to start controller manager")
		os.Exit(1)
	}
}

// validateFlags checks command-line flags that must fail before the controller
// establishes a Kubernetes API connection.
func validateFlags(signerName, clusterFQDN string) error {
	if signerName == "" {
		return errors.New("the --signer-name flag is required")
	}
	if err := podcertificate.ValidateClusterFQDN(clusterFQDN); err != nil {
		return fmt.Errorf("invalid --cluster-fqdn %q: %w", clusterFQDN, err)
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
		// mgr.Start stays the last statement in main(). The release is
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

// displayCommandlineFlags visits all CLI flags and prints them.
func displayCommandlineFlags() {
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		setupLog.Info("Flag",
			"name", f.Name,
			"value", f.Value.String(),
			"default", f.DefValue)
	})
}
