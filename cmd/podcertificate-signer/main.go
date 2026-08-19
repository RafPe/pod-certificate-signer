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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap/zapcore"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/controller"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	signermetrics "github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("controller.setup")
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
	// This is a named constant rather than a literal in the flag registration
	// below because the flag is registered inside main() and is otherwise
	// unreachable from a test. Keep it in sync with the chart value
	// signer.enable_annotation_interpolation; the two are one decision stored
	// twice and TestChartInterpolationDefaultMatchesBinary guards the drift.
	defaultEnableAnnotationInterpolation = true
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	// The signer's custom metric surface is bounded by decision, not by
	// convenience: see ADR-0005 (docs/adr/0005-bounded-metrics-surface.md).
	// Registering into controller-runtime's registry puts it on the manager's
	// existing SecureServing metrics endpoint, so there is no new transport.
	utilruntime.Must(signermetrics.Register(metrics.Registry))

	// +kubebuilder:scaffold:scheme
}

func main() {
	var signerName, caCertPath, caKeyPath, clusterFqdn string
	var leaderElectionID, leaderElectionNamespace string
	var healthProbeBindAddress, metricsBindAddress string
	var maxConcurrentReconciles, maxPreviousCACerts int
	var enableLeaderElection, enableAnnotationInterpolation, honorCSRSANs bool
	var allowUnverifiedIdentities, metricsSecure bool
	var reconcileTimeout time.Duration

	flag.StringVar(&signerName, "signer-name", "", "Only sign CSR with this .spec.signerName. Required.")
	flag.StringVar(&caCertPath, "ca-cert-path", "", "CA certificate file.")
	flag.StringVar(&caKeyPath, "ca-key-path", "", "CA private key file.")
	flag.StringVar(&clusterFqdn, "cluster-fqdn", "cluster.local", "The FQDN of the cluster")
	flag.StringVar(&leaderElectionID, "leader-election-id", "pcs-leader-election",
		"The name of the configmap used to coordinate leader election between controller-managers.")
	flag.StringVar(&leaderElectionNamespace, "leader-election-namespace", "", "Namespace for leader election (default: pod's namespace).")
	flag.StringVar(&healthProbeBindAddress, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&metricsBindAddress, "metrics-bind-address", ":9090", "The address on which to bind the metrics server.")
	flag.BoolVar(&metricsSecure, "metrics-secure", true,
		"Serve the metrics endpoint over HTTPS and require authentication (TokenReview) and authorization "+
			"(SubjectAccessReview) for every scrape. On by default. Set to false to fall back to the legacy "+
			"unauthenticated plaintext endpoint - see the chart's metrics.insecure escape hatch.")
	flag.IntVar(&maxConcurrentReconciles, "max-concurrent-reconciles", 5, "maximum number of concurrent reconciles which can be run.")
	flag.IntVar(&maxPreviousCACerts, "max-previous-ca-certs", 2, "maximum number of previous CA certificates to keep during CA rotation.")
	flag.DurationVar(&reconcileTimeout, "reconcile-timeout", 5*time.Minute, "maximum duration of a reconcile before it times out.")
	flag.BoolVar(&enableAnnotationInterpolation, "enable-annotation-interpolation", defaultEnableAnnotationInterpolation,
		"Allow ${...} placeholders (e.g. ${pod.name}, ${pod.serviceAccountName}) in certificate configuration annotations, "+
			"resolved from the verified fields of the PodCertificateRequest. On by default; resolved values remain subject "+
			"to the identity constraints unless --allow-unverified-identities is set. Set to false to deny any value "+
			"containing ${...} instead of resolving it.")
	flag.BoolVar(&honorCSRSANs, "honor-csr-sans", false,
		"Honor DNS and IP SANs embedded in the kubelet-generated PKCS#10 CSR when no SAN annotation overrides them. "+
			"CSR SANs stay subject to the identity constraints unless --allow-unverified-identities is set (CSR DNS SANs "+
			"must be a verified identity; CSR IP SANs are denied). Kubelet generates empty CSRs today; this prepares for "+
			"upcoming Kubernetes support for requesting SANs.")
	flag.BoolVar(&allowUnverifiedIdentities, "allow-unverified-identities", false,
		"Allow cn/san/ip-san/uris annotation values that are not derived from the verified PodCertificateRequest fields "+
			"(pod name/namespace/serviceAccountName/uid + cluster FQDN). Off by default: leaving it off prevents a pod from "+
			"requesting a certificate for an identity it does not own.")

	opts := zap.Options{
		Development:     true,
		TimeEncoder:     zapcore.ISO8601TimeEncoder,
		StacktraceLevel: zapcore.DPanicLevel,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	if err := validateFlags(signerName, clusterFqdn); err != nil {
		setupLog.Error(err, "invalid command-line flags")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	restCfg := ctrl.GetConfigOrDie()

	mgr, err := ctrl.NewManager(restCfg, managerOptions(scheme, managerConfig{
		healthProbeBindAddress:  healthProbeBindAddress,
		metricsBindAddress:      metricsBindAddress,
		metricsSecure:           metricsSecure,
		leaderElection:          enableLeaderElection,
		leaderElectionID:        leaderElectionID,
		leaderElectionNamespace: leaderElectionNamespace,
		maxConcurrentReconciles: maxConcurrentReconciles,
		reconcileTimeout:        reconcileTimeout,
		baseContext:             ctx,
	}))

	if err != nil {
		setupLog.Error(err, "unable to create controller manager")
		os.Exit(1)
	}

	// Bootstrap previous CA certificates from the existing ClusterTrustBundle
	// so that we retain trust across CA rotations even after a restart.
	//
	// We need to use a new [client.Client] here, since the controller
	// manager is not started yet, and we must update the ClusterTrustBundle
	// early on.
	c, err := client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		setupLog.Error(err, "unable to create API client")
		os.Exit(1)
	}
	// Read the previous-CA history with bounded retry. A transient read error
	// must not fall through to an empty history: publishing an empty bundle
	// would drop previously-trusted CAs. If the history cannot be read, fail
	// closed rather than risk overwriting the ClusterTrustBundle.
	bootstrapBackoff := wait.Backoff{
		Steps:    5,
		Duration: 500 * time.Millisecond,
		Factor:   2.0,
		Jitter:   0.1,
	}
	var previousCAs []*x509.Certificate
	if err := retry.OnError(bootstrapBackoff, func(error) bool { return true }, func() error {
		var ferr error
		previousCAs, ferr = fetchPreviousCAs(ctx, c, signerName)
		return ferr
	}); err != nil {
		setupLog.Error(err, "unable to read existing CA history from ClusterTrustBundle; "+
			"refusing to start to avoid dropping previously-trusted CAs")
		os.Exit(1)
	}
	ca, err := authority.New(
		caCertPath,
		caKeyPath,
		authority.WithPreviousCABundle(previousCAs),
		authority.WithMaxPreviousCertificates(maxPreviousCACerts),
	)
	if err != nil {
		setupLog.Error(err, "unable to create certificate authority")
		os.Exit(1)
	}

	pcrSigner, err := signer.New(signerName, ca)
	if err != nil {
		setupLog.Error(err, "unable to create signer")
		os.Exit(1)
	}

	// Wire the CA file watcher and the ClusterTrustBundle publisher. The
	// watcher runs on every replica so standby replicas keep their in-memory
	// CA current; the publisher is leader-gated so only the elected leader
	// writes the shared ClusterTrustBundle.
	caWatcher, ctbUpdater := newCARunnables(c, pcrSigner, ca)
	if err := mgr.Add(caWatcher); err != nil {
		setupLog.Error(err, "unable to add CA watcher runnable")
		os.Exit(1)
	}
	if err := mgr.Add(ctbUpdater); err != nil {
		setupLog.Error(err, "unable to add ClusterTrustBundle updater runnable")
		os.Exit(1)
	}

	if err := (&controller.PodCertificateRequestReconciler{
		Client:                        mgr.GetClient(),
		APIReader:                     mgr.GetAPIReader(),
		Log:                           ctrl.Log.WithName(DefaultControllerName),
		Scheme:                        mgr.GetScheme(),
		Signer:                        pcrSigner,
		ClusterFqdn:                   clusterFqdn,
		EventRecorder:                 mgr.GetEventRecorder(DefaultControllerName),
		EnableAnnotationInterpolation: enableAnnotationInterpolation,
		HonorCSRSANs:                  honorCSRSANs,
		AllowUnverifiedIdentities:     allowUnverifiedIdentities,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PodCertificateSignerReconciler")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	// Gate readiness on the CA's watcher/reload health: a replica that can no
	// longer observe CA rotations, or whose reloads have been failing
	// persistently, must be pulled from readiness so it is not relied upon to
	// publish or sign with stale material. A transient reload failure keeps the
	// replica ready, since the last-good CA is retained and signing works.
	if err := mgr.AddReadyzCheck("readyz", caReadyzCheck(ca)); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}
	// Also gate readiness on the ClusterTrustBundle publisher: a leader whose
	// publishes keep failing must be pulled from readiness so the failure is
	// visible and traffic/leadership can move elsewhere.
	if err := mgr.AddReadyzCheck("clustertrustbundle", caReadyzCheck(ctbUpdater)); err != nil {
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

// managerConfig carries the controller-manager settings resolved from CLI
// flags. It exists so the option construction can be unit-tested without
// parsing flags.
type managerConfig struct {
	healthProbeBindAddress  string
	metricsBindAddress      string
	metricsSecure           bool
	leaderElection          bool
	leaderElectionID        string
	leaderElectionNamespace string
	maxConcurrentReconciles int
	reconcileTimeout        time.Duration
	baseContext             context.Context
}

// managerOptions builds the controller-manager options from cfg.
func managerOptions(scheme *runtime.Scheme, cfg managerConfig) ctrl.Options {
	return ctrl.Options{
		Scheme:                  scheme,
		HealthProbeBindAddress:  cfg.healthProbeBindAddress,
		LeaderElection:          cfg.leaderElection,
		LeaderElectionID:        cfg.leaderElectionID,
		LeaderElectionNamespace: cfg.leaderElectionNamespace,
		BaseContext:             func() context.Context { return cfg.baseContext },
		Metrics:                 metricsServerOptions(cfg),
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

// caHealthChecker is the CA health surface consumed by the readiness probe.
type caHealthChecker interface {
	// Healthy returns a non-nil error when the CA can no longer track its
	// on-disk material (watcher dead or reload persistently failing).
	Healthy() error
}

// caReadyzCheck adapts a caHealthChecker into a controller-runtime readiness
// check, so a degraded CA removes the replica from readiness.
func caReadyzCheck(ca caHealthChecker) healthz.Checker {
	return func(_ *http.Request) error {
		return ca.Healthy()
	}
}

// caWatchRunnable reloads the in-memory CA whenever the mounted certificate or
// key files change. It runs on every replica, independent of leader election,
// so that a standby replica keeps its CA current and never signs or publishes
// with stale material immediately after being promoted to leader.
type caWatchRunnable struct {
	ca     *authority.CertificateAuthority
	notify chan<- struct{}
}

// Start blocks watching the CA files until ctx is canceled. A failed watch is
// fatal: without it CA rotations would silently never be observed.
func (r *caWatchRunnable) Start(ctx context.Context) error {
	if err := r.ca.Watch(ctx, r.notify); err != nil {
		return fmt.Errorf("ca-watcher failed: %w", err)
	}
	return nil
}

// NeedLeaderElection reports false so the CA watcher runs on every replica.
func (*caWatchRunnable) NeedLeaderElection() bool { return false }

// ctbDriftRepairInterval is how often the publisher re-publishes the
// ClusterTrustBundle even without a CA reload event, to repair external drift
// (e.g. a manual edit or a lost event).
const ctbDriftRepairInterval = 10 * time.Minute

// ctbPublisher reconciles the signer's ClusterTrustBundle towards the current
// CA. It publishes when it starts, on every CA reload event, and on a periodic
// drift-repair tick. Publishes are retried with exponential backoff and are
// single-flight (a reconcile triggered while one is in flight is coalesced). It
// is leader-gated so only the elected leader writes the shared resource.
type ctbPublisher struct {
	client   client.Client
	signer   *signer.Signer
	ca       *authority.CertificateAuthority
	events   <-chan struct{}
	interval time.Duration
	backoff  wait.Backoff
	// publishes counts every publish attempt by its result, so a leader that
	// stopped publishing is distinguishable from one that is publishing
	// successfully - which a failure-only counter never was.
	publishes *prometheus.CounterVec

	// runMu is a single-flight guard: TryLock lets a reconcile skip when
	// another is already publishing.
	runMu sync.Mutex

	// healthMu guards the most recent publish outcome, polled by readiness.
	healthMu       sync.Mutex
	lastPublishErr error
}

// Start publishes the ClusterTrustBundle on startup, so a newly-elected leader
// publishes from the current in-memory CA, then on every CA reload event and on
// a periodic drift-repair tick, until ctx is canceled.
func (r *ctbPublisher) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("cluster-trust-bundle")
	logger.Info("starting ClusterTrustBundle publisher", "driftRepairInterval", r.interval)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	r.reconcile(ctx, logger)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.events:
			r.reconcile(ctx, logger)
		case <-ticker.C:
			// Periodic drift repair, independent of fsnotify events.
			r.reconcile(ctx, logger)
		}
	}
}

// NeedLeaderElection reports true so only the elected leader writes the
// ClusterTrustBundle.
func (*ctbPublisher) NeedLeaderElection() bool { return true }

// reconcile publishes the current CA trust bundle to the ClusterTrustBundle,
// retrying with exponential backoff. It is single-flight: if a publish is
// already in flight the call is skipped, since the in-flight publish will use
// the latest in-memory CA state anyway. It returns true if a publish ran and
// false if it was skipped.
func (r *ctbPublisher) reconcile(ctx context.Context, logger logr.Logger) bool {
	if !r.runMu.TryLock() {
		logger.V(1).Info("ClusterTrustBundle publish already in progress, skipping")
		return false
	}
	defer r.runMu.Unlock()

	var op controllerutil.OperationResult
	err := retry.OnError(r.backoff, func(error) bool { return true }, func() error {
		var perr error
		op, perr = r.publishOnce(ctx, logger)
		return perr
	})
	r.recordPublishResult(err)
	if err != nil {
		r.publishes.WithLabelValues(signermetrics.ResultFailed).Inc()
		logger.Error(err, "unable to update ClusterTrustBundle after retries")
		return true
	}
	r.publishes.WithLabelValues(publishResult(op)).Inc()
	return true
}

// publishResult maps CreateOrPatch's OperationResult onto the bounded result
// label. OperationResult is a closed set of Go constants, and the mutate
// function touches only .spec, so the status results cannot occur; they are
// folded into "updated" rather than minting a label value the surface does not
// budget for.
func publishResult(op controllerutil.OperationResult) string {
	switch op {
	case controllerutil.OperationResultNone:
		return signermetrics.ResultUnchanged
	case controllerutil.OperationResultCreated:
		return signermetrics.ResultCreated
	default:
		return signermetrics.ResultUpdated
	}
}

// publishOnce performs a single CreateOrPatch of the ClusterTrustBundle to the
// current CA trust bundle. The mutate function overwrites (never merges) the
// trust bundle, so CA pruning in the rolling window is preserved.
func (r *ctbPublisher) publishOnce(ctx context.Context, logger logr.Logger) (controllerutil.OperationResult, error) {
	bundle := r.signer.ClusterTrustBundle()
	// Use the direct API client: reading through the manager's cache-backed
	// client would start an informer for ClusterTrustBundles, which requires
	// list/watch RBAC permissions this controller does not need.
	op, err := controllerutil.CreateOrPatch(ctx, r.client, bundle, func() error {
		bundle.Spec.TrustBundle = string(r.ca.TrustBundlePEM())
		return nil
	})
	if err != nil {
		return op, err
	}
	logger.Info("reconciled ClusterTrustBundle", "name", bundle.Name, "operation", op)
	return op, nil
}

// recordPublishResult stores the outcome of the most recent reconcile.
func (r *ctbPublisher) recordPublishResult(err error) {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	r.lastPublishErr = err
}

// Healthy reports a non-nil error when the most recent ClusterTrustBundle
// publish failed after retries, so a persistently failing publisher fails
// readiness. It is safe for concurrent use.
func (r *ctbPublisher) Healthy() error {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	return r.lastPublishErr
}

// newCARunnables wires the CA file watcher and the ClusterTrustBundle publisher
// so that CA reload events flow from the watcher to the publisher over a shared
// channel. The watcher runs on every replica; the publisher is leader-gated.
func newCARunnables(c client.Client, s *signer.Signer, ca *authority.CertificateAuthority) (*caWatchRunnable, *ctbPublisher) {
	events := make(chan struct{}, 2)
	watcher := &caWatchRunnable{ca: ca, notify: events}
	publisher := &ctbPublisher{
		client:   c,
		signer:   s,
		ca:       ca,
		events:   events,
		interval: ctbDriftRepairInterval,
		backoff: wait.Backoff{
			Steps:    5,
			Duration: 500 * time.Millisecond,
			Factor:   2.0,
			Jitter:   0.1,
		},
		publishes: signermetrics.ClusterTrustBundlePublishAttempts,
	}
	return watcher, publisher
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

// fetchPreviousCAs reads the existing ClusterTrustBundle for the given signer
// and parses its PEM certificates, so previously-trusted CAs are retained
// across a restart.
//
// A missing bundle is the normal first-run state and yields an empty history
// with a nil error. Any other read error is returned so the caller can retry
// or fail closed: silently returning an empty history would overwrite the
// bundle on startup and drop previously-trusted CAs.
func fetchPreviousCAs(ctx context.Context, c client.Client, signerName string) ([]*x509.Certificate, error) {
	bundleName := signer.ClusterTrustBundleName(signerName)

	bundle := &certificatesv1beta1.ClusterTrustBundle{}
	if err := c.Get(ctx, client.ObjectKey{Name: bundleName}, bundle); err != nil {
		if apierrors.IsNotFound(err) {
			setupLog.Info("no existing ClusterTrustBundle found, starting with empty CA history", "name", bundleName)
			return nil, nil
		}
		return nil, fmt.Errorf("read existing ClusterTrustBundle %q: %w", bundleName, err)
	}

	certs := parsePEMCertificates([]byte(bundle.Spec.TrustBundle))
	setupLog.Info("bootstrapped previous CA certificates from ClusterTrustBundle", "name", bundleName, "count", len(certs))

	return certs, nil
}

// parsePEMCertificates extracts x509 certificates from a PEM-encoded bundle.
func parsePEMCertificates(data []byte) []*x509.Certificate {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			setupLog.Error(err, "failed to parse certificate from trust bundle, skipping")
			continue
		}
		certs = append(certs, cert)
	}

	return certs
}
