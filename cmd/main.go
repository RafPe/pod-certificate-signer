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
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	"go.uber.org/zap/zapcore"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/controller"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

const (
	defaultFlagMaxConcurrentReconciles = 5
	defaultFlagMaxCertificateNbfSkew   = 5

	defaultFlagHealthProbeBindAddress = ":8081"
	defaultFlagClusterFqdn            = "cluster.local"
	defaultFlagEnableLeaderElection   = false
	defaultFlagLeaderElectionID       = "pcs-leader"
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	// +kubebuilder:scaffold:scheme
}

// nolint:gocyclo
func main() {
	var signerName string
	var caCertPath string
	var caKeyPath string
	var maxConcurrentReconciles int

	var clusterFqdn string
	var enableLeaderElection bool
	var leaderElectionID string
	var healthProbeBindAddress string
	var debugLogging bool

	flag.StringVar(&signerName, "signer-name", "", "Only sign CSR with this .spec.signerName.")
	flag.StringVar(&caCertPath, "ca-cert-path", "", "CA certificate file.")
	flag.StringVar(&caKeyPath, "ca-key-path", "", "CA private key file.")
	flag.IntVar(&maxConcurrentReconciles, "max-concurrent-reconciles", defaultFlagMaxConcurrentReconciles, "The maximum number of concurrent reconciles.")

	flag.StringVar(&clusterFqdn, "cluster-fqdn", defaultFlagClusterFqdn, "The FQDN of the cluster")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", defaultFlagEnableLeaderElection,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.StringVar(&leaderElectionID, "leader-election-id", defaultFlagLeaderElectionID,
		"The name of the configmap used to coordinate leader election between controller-managers.")
	flag.StringVar(&healthProbeBindAddress, "health-probe-bind-address", defaultFlagHealthProbeBindAddress, "The address the probe endpoint binds to.")

	// flag.BoolVar(&secureMetrics, "metrics-secure", true,
	// 	"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	// flag.StringVar(&webhookCertPath, "webhook-cert-path", "", "The directory that contains the webhook certificate.")
	// flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "The name of the webhook certificate file.")
	// flag.StringVar(&webhookCertKey, "webhook-cert-key", "tls.key", "The name of the webhook key file.")
	// flag.StringVar(&metricsCertPath, "metrics-cert-path", "",
	// 	"The directory that contains the metrics server certificate.")
	// flag.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "The name of the metrics server certificate file.")
	// flag.StringVar(&metricsCertKey, "metrics-cert-key", "tls.key", "The name of the metrics server key file.")
	// flag.BoolVar(&enableHTTP2, "enable-http2", false,
	// 	"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.BoolVar(&debugLogging, "debug-logging", false, "Enable debug logging.")

	opts := zap.Options{
		Development:     true,
		TimeEncoder:     zapcore.ISO8601TimeEncoder,
		StacktraceLevel: zapcore.DPanicLevel,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// Validate required flags as they are critical for starting our controller
	if err := validateRequiredFlags(signerName, caCertPath, caKeyPath); err != nil {
		setupLog.Error(err, "Missing required flags")
		os.Exit(1)
	}

	// If we have choosen to use leader election but not provided a leader election ID, use the signer name to create a unique ID with a hash
	if enableLeaderElection && leaderElectionID == defaultFlagLeaderElectionID {
		leaderElectionID = fmt.Sprintf("%s-%s", defaultFlagLeaderElectionID, createStringHash(signerName))
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		HealthProbeBindAddress: healthProbeBindAddress,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       leaderElectionID,
	})

	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	signer, err := signer.NewSigner(caCertPath, caKeyPath, signerName)
	if err != nil {
		setupLog.Error(err, "failed to create signer")
		os.Exit(1)
	}

	if err := (&controller.PodCertificateRequestReconciler{
		Client:        mgr.GetClient(),
		Log:           ctrl.Log.WithName("controllers").WithName("PodCertificateSignerReconciler"),
		Scheme:        mgr.GetScheme(),
		Signer:        signer,
		ClusterFqdn:   clusterFqdn,
		EventRecorder: mgr.GetEventRecorderFor("PodCertificateSignerReconciler"),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "PodCertificateRequest")
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

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func validateRequiredFlags(signerName, caCertPath, caKeyPath string) error {
	var missing []string

	if signerName == "" {
		missing = append(missing, "--signer-name")
	}
	if caCertPath == "" {
		missing = append(missing, "--ca-cert-path")
	}
	if caKeyPath == "" {
		missing = append(missing, "--ca-key-path")
	}

	if len(missing) > 0 {
		return fmt.Errorf("required flags missing: %v", missing)
	}

	return nil
}

func createStringHash(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])[:8]
}
