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
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"go.uber.org/zap/zapcore"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
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
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/controller"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	pcsmetrics "github.com/rafpe/kubernetes-podcertificate-signer/internal/metrics"
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
	var enableLeaderElection bool
	var reconcileTimeout time.Duration

	flag.StringVar(&signerName, "signer-name", "example.org/signer", "Only sign CSR with this .spec.signerName.")
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

	opts := zap.Options{
		Development:     true,
		TimeEncoder:     zapcore.ISO8601TimeEncoder,
		StacktraceLevel: zapcore.DPanicLevel,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	ctx := ctrl.SetupSignalHandler()
	restCfg := ctrl.GetConfigOrDie()

	mgr, err := ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                  scheme,
		HealthProbeBindAddress:  healthProbeBindAddress,
		LeaderElection:          enableLeaderElection,
		LeaderElectionID:        leaderElectionID,
		LeaderElectionNamespace: leaderElectionNamespace,
		BaseContext:             func() context.Context { return ctx },
		Metrics: server.Options{
			BindAddress: metricsBindAddress,
		},
		Controller: config.Controller{
			MaxConcurrentReconciles: maxConcurrentReconciles,
			RecoverPanic:            new(true),
			ReconciliationTimeout:   reconcileTimeout,
		},
	})

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

	// caTrustBundleUpdater is a [manager.Runnable] which will update the
	// ClusterTrustBundle of our signer whenever the CA has been reloaded.
	caTrustBundleUpdater := func(ctx context.Context) error {
		logger := log.FromContext(ctx).WithName("cluster-trust-bundle")
		logger.Info("starting ClusterTrustBundle updater")
		events := make(chan struct{}, 2)

		// Start the CA watcher and listen for any CA reload events
		go func() {
			if err := ca.Watch(ctx, events); err != nil {
				logger.Error(err, "failed to start ca-watcher")
			}
		}()

		// We want the trust bundle updated on startup, so emit an event
		// here.
		events <- struct{}{}
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-events:
				err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
					logger.Info("updating ClusterTrustBundle with new CA certificate")
					bundle := pcrSigner.ClusterTrustBundle()
					_, err := controllerutil.CreateOrPatch(ctx, mgr.GetClient(), bundle, func() error {
						bundle.Spec.TrustBundle = string(ca.TrustBundlePEM())
						return nil
					})
					return err
				})
				if err != nil {
					logger.Error(err, "unable to update ClusterTrustBundle")
				}
			}
		}
	}
	if err := mgr.Add(manager.RunnableFunc(caTrustBundleUpdater)); err != nil {
		setupLog.Error(err, "unable to add ClusterTrustBundle updater runnable")
		os.Exit(1)
	}

	// caExpiryMonitor periodically updates the CA-expiry gauge and warns when
	// the active CA is close to expiring.
	caExpiryMonitor := func(ctx context.Context) error {
		const (
			interval         = time.Hour
			warningThreshold = 7 * 24 * time.Hour
		)
		logger := log.FromContext(ctx).WithName("ca-expiry-monitor")
		check := func() {
			remaining := time.Until(pcrSigner.CANotAfter())
			pcsmetrics.CAExpirySeconds.Set(remaining.Seconds())
			if remaining < warningThreshold {
				logger.Info("CA certificate is approaching expiry", "expiresIn", remaining.String())
			}
		}
		check() // emit immediately on startup
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				check()
			}
		}
	}
	if err := mgr.Add(manager.RunnableFunc(caExpiryMonitor)); err != nil {
		setupLog.Error(err, "unable to add CA expiry monitor runnable")
		os.Exit(1)
	}

	if err := (&controller.PodCertificateRequestReconciler{
		Client:        mgr.GetClient(),
		Scheme:        mgr.GetScheme(),
		Signer:        pcrSigner,
		ClusterFqdn:   clusterFqdn,
		EventRecorder: mgr.GetEventRecorder(DefaultControllerName),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PodCertificateSignerReconciler")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	displayCommandlineFlags()

	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "unable to start controller manager")
		os.Exit(1)
	}
}

// displayCommandLineFlags visits all CLI flags and prints them.
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
	// Name of the resource should follow the
	// <domain>:<signerName>:<arbitrary-name> convention.
	//
	// https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles
	normalizedName := strings.ReplaceAll(signerName, "/", ":")
	bundleName := fmt.Sprintf("%s:bundle", normalizedName)

	bundle := &certificatesv1beta1.ClusterTrustBundle{}
	err := c.Get(ctx, client.ObjectKey{Name: bundleName}, bundle)
	if err != nil {
		setupLog.Info("no existing ClusterTrustBundle found, starting with empty CA history", "name", bundleName)
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
