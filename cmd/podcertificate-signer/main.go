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
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"github.com/go-logr/logr"
	"go.uber.org/zap/zapcore"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/controller"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("controller.setup")
)

const (
	DefaultControllerName = "PodCertificateSigner"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
}

func main() {
	var signerName, caCertPath, caKeyPath, clusterFqdn string
	var leaderElectionID, leaderElectionNamespace string
	var healthProbeBindAddress, metricsBindAddress string
	var maxConcurrentReconciles, maxPreviousCACerts int
	var enableLeaderElection, enableAnnotationInterpolation, honorCSRSANs bool
	var allowUnverifiedIdentities bool
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
	flag.IntVar(&maxConcurrentReconciles, "max-concurrent-reconciles", 5, "maximum number of concurrent reconciles which can be run.")
	flag.IntVar(&maxPreviousCACerts, "max-previous-ca-certs", 2, "maximum number of previous CA certificates to keep during CA rotation.")
	flag.DurationVar(&reconcileTimeout, "reconcile-timeout", 5*time.Minute, "maximum duration of a reconcile before it times out.")
	flag.BoolVar(&enableAnnotationInterpolation, "enable-annotation-interpolation", false,
		"Allow ${...} placeholders (e.g. ${pod.name}, ${pod.serviceAccountName}) in certificate configuration annotations, "+
			"resolved from the verified fields of the PodCertificateRequest.")
	flag.BoolVar(&honorCSRSANs, "honor-csr-sans", false,
		"Honor DNS and IP SANs embedded in the kubelet-generated PKCS#10 CSR when no SAN annotation overrides them. "+
			"Kubelet generates empty CSRs today; this prepares for upcoming Kubernetes support for requesting SANs.")
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

	if err := validateFlags(signerName); err != nil {
		setupLog.Error(err, "invalid command-line flags")
		os.Exit(1)
	}

	ctx := ctrl.SetupSignalHandler()
	restCfg := ctrl.GetConfigOrDie()

	mgr, err := ctrl.NewManager(restCfg, managerOptions(scheme, managerConfig{
		healthProbeBindAddress:  healthProbeBindAddress,
		metricsBindAddress:      metricsBindAddress,
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
	previousCAs := fetchPreviousCAs(ctx, c, signerName)
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
	// longer observe CA rotations (or whose most recent reload failed) must be
	// pulled from readiness so it is not relied upon to publish or sign with
	// stale material.
	if err := mgr.AddReadyzCheck("readyz", caReadyzCheck(ca)); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	displayCommandlineFlags()

	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "unable to start controller manager")
		os.Exit(1)
	}
}

// validateFlags checks required command-line flags. An empty --signer-name is
// rejected here so the controller fails fast at startup - mirroring the
// required --ca-cert-path - instead of only surfacing the problem later, after
// a Kubernetes API connection has been established.
func validateFlags(signerName string) error {
	if signerName == "" {
		return errors.New("the --signer-name flag is required")
	}
	return nil
}

// managerConfig carries the controller-manager settings resolved from CLI
// flags. It exists so the option construction can be unit-tested without
// parsing flags.
type managerConfig struct {
	healthProbeBindAddress  string
	metricsBindAddress      string
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
		Metrics: server.Options{
			BindAddress: cfg.metricsBindAddress,
		},
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

// ctbPublisher keeps the signer's ClusterTrustBundle in sync with the current
// CA. It publishes once when it starts and again on every CA reload event. It
// is leader-gated so only the elected leader writes the shared resource.
type ctbPublisher struct {
	client client.Client
	signer *signer.Signer
	ca     *authority.CertificateAuthority
	events <-chan struct{}
}

// Start publishes the ClusterTrustBundle on startup, so a newly-elected leader
// publishes from the current in-memory CA, and then again on every CA reload
// event, until ctx is canceled.
func (r *ctbPublisher) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("cluster-trust-bundle")
	logger.Info("starting ClusterTrustBundle updater")

	r.publish(ctx, logger)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.events:
			r.publish(ctx, logger)
		}
	}
}

// NeedLeaderElection reports true so only the elected leader writes the
// ClusterTrustBundle.
func (*ctbPublisher) NeedLeaderElection() bool { return true }

// publish reconciles the ClusterTrustBundle to the current CA trust bundle,
// retrying on optimistic-concurrency conflicts.
func (r *ctbPublisher) publish(ctx context.Context, logger logr.Logger) {
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		logger.Info("updating ClusterTrustBundle with new CA certificate")
		bundle := r.signer.ClusterTrustBundle()
		// Use the direct API client: reading through the manager's
		// cache-backed client would start an informer for ClusterTrustBundles,
		// which requires list/watch RBAC permissions this controller does not
		// need.
		_, err := controllerutil.CreateOrPatch(ctx, r.client, bundle, func() error {
			bundle.Spec.TrustBundle = string(r.ca.TrustBundlePEM())
			return nil
		})
		return err
	})
	if err != nil {
		logger.Error(err, "unable to update ClusterTrustBundle")
	}
}

// newCARunnables wires the CA file watcher and the ClusterTrustBundle publisher
// so that CA reload events flow from the watcher to the publisher over a shared
// channel. The watcher runs on every replica; the publisher is leader-gated.
func newCARunnables(c client.Client, s *signer.Signer, ca *authority.CertificateAuthority) (*caWatchRunnable, *ctbPublisher) {
	events := make(chan struct{}, 2)
	watcher := &caWatchRunnable{ca: ca, notify: events}
	publisher := &ctbPublisher{client: c, signer: s, ca: ca, events: events}
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

// fetchPreviousCAs attempts to read the existing ClusterTrustBundle for the
// given signer and parse its PEM certificates. Returns nil if the bundle does
// not exist or cannot be read.
func fetchPreviousCAs(ctx context.Context, c client.Client, signerName string) []*x509.Certificate {
	bundleName := signer.ClusterTrustBundleName(signerName)

	bundle := &certificatesv1beta1.ClusterTrustBundle{}
	if err := c.Get(ctx, client.ObjectKey{Name: bundleName}, bundle); err != nil {
		if apierrors.IsNotFound(err) {
			setupLog.Info("no existing ClusterTrustBundle found, starting with empty CA history", "name", bundleName)
		} else {
			setupLog.Error(err, "unable to read existing ClusterTrustBundle, starting with empty CA history", "name", bundleName)
		}
		return nil
	}

	certs := parsePEMCertificates([]byte(bundle.Spec.TrustBundle))
	setupLog.Info("bootstrapped previous CA certificates from ClusterTrustBundle", "name", bundleName, "count", len(certs))

	return certs
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
