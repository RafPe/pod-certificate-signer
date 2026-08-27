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

package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/authority"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/signer"
	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
	// +kubebuilder:scaffold:imports
)

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.
//
// Unlike the unit tests in this package, which drive the reconciler against a
// fake client, this suite runs it against a real kube-apiserver. That is the
// only place where the status writes the controller performs are actually
// validated: kube-apiserver enforces a set of rules on PodCertificateRequest
// status (certificate chain parses, lifetime bounds, refresh window, cleared
// fields on terminal outcomes) which no fake client checks.

const (
	// testSignerName is the signer this suite's reconciler is responsible for.
	testSignerName = "example.com/envtest-signer"

	// testNamespace is where the suite creates its pods and requests.
	testNamespace = "default"

	// testMaxExpirationSeconds bounds the certificate lifetime. It is set
	// comfortably above the signer's 24h default duration so the issued
	// certificate sits strictly inside the bound rather than on it.
	testMaxExpirationSeconds = int32(48 * 60 * 60)
)

var (
	ctx       context.Context
	cancel    context.CancelFunc
	testEnv   *envtest.Environment
	cfg       *rest.Config
	k8sClient client.Client
)

func TestControllers(t *testing.T) {
	RegisterFailHandler(Fail)

	RunSpecs(t, "Controller Suite")
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	ctx, cancel = context.WithCancel(context.TODO())

	Expect(certificatesv1.AddToScheme(scheme.Scheme)).To(Succeed())

	// +kubebuilder:scaffold:scheme

	By("bootstrapping test environment")
	// PodCertificateRequest is a built-in API, not a CRD, so there is nothing
	// to install from disk. Since Kubernetes 1.37 it is GA in
	// certificates.k8s.io/v1, which the apiserver enables and serves by
	// default - no feature-gate or runtime-config override needed.
	testEnv = &envtest.Environment{}

	// Retrieve the first found binary directory to allow running tests from IDEs
	if getFirstFoundEnvTestBinaryDir() != "" {
		testEnv.BinaryAssetsDirectory = getFirstFoundEnvTestBinaryDir()
	}

	// cfg is defined in this file globally.
	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())

	By("starting the PodCertificateRequest controller")
	startTestManager()
})

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	cancel()
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

// startTestManager wires the real reconciler - a real CA, a real signer, and
// the manager's own client, API reader and event recorder - into a manager
// running against the envtest apiserver, mirroring how cmd/podcertificate-signer
// assembles it in production.
func startTestManager() {
	GinkgoHelper()

	// The CA must outlive the certificates it issues: authority.Sign refuses
	// to issue past its own NotAfter, and that refusal is classified as
	// transient, so a short-lived CA would make specs requeue until they time
	// out instead of failing usefully.
	ca, err := testutil.NewCA("envtest-ca", 90*24*time.Hour)
	Expect(err).NotTo(HaveOccurred())

	// authority.New loads the CA through tls.LoadX509KeyPair, so the key pair
	// has to reach it as files.
	dir, err := os.MkdirTemp("", "envtest-ca")
	Expect(err).NotTo(HaveOccurred())
	DeferCleanup(func() {
		Expect(os.RemoveAll(dir)).To(Succeed())
	})
	certPath, keyPath, err := ca.WriteFiles(dir)
	Expect(err).NotTo(HaveOccurred())

	certificateAuthority, err := authority.New(certPath, keyPath)
	Expect(err).NotTo(HaveOccurred())

	pcrSigner, err := signer.New(testSignerName, certificateAuthority)
	Expect(err).NotTo(HaveOccurred())

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme.Scheme,
		Metrics:                server.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
		// Pods are excluded from the cache in production; keep the same
		// wiring here so the suite exercises the live-read path.
		Client: client.Options{
			Cache: &client.CacheOptions{DisableFor: []client.Object{&corev1.Pod{}}},
		},
	})
	Expect(err).NotTo(HaveOccurred())

	err = (&PodCertificateRequestReconciler{
		Client:        mgr.GetClient(),
		APIReader:     mgr.GetAPIReader(),
		Log:           ctrl.Log.WithName("envtest"),
		Scheme:        mgr.GetScheme(),
		Signer:        pcrSigner,
		ClusterFqdn:   "cluster.local",
		EventRecorder: mgr.GetEventRecorder("podcertificate-signer"),
	}).SetupWithManager(mgr)
	Expect(err).NotTo(HaveOccurred())

	go func() {
		defer GinkgoRecover()
		Expect(mgr.Start(ctx)).To(Succeed())
	}()
	Expect(mgr.GetCache().WaitForCacheSync(ctx)).To(BeTrue())
}

// getFirstFoundEnvTestBinaryDir locates the first binary in the specified path.
// ENVTEST-based tests depend on specific binaries, usually located in paths set by
// controller-runtime. When running tests directly (e.g., via an IDE) without using
// Makefile targets, the 'BinaryAssetsDirectory' must be explicitly configured.
//
// This function streamlines the process by finding the required binaries, similar to
// setting the 'KUBEBUILDER_ASSETS' environment variable. To ensure the binaries are
// properly set up, run 'make setup-envtest' beforehand.
func getFirstFoundEnvTestBinaryDir() string {
	basePath := filepath.Join("..", "..", "bin", "k8s")
	entries, err := os.ReadDir(basePath)
	if err != nil {
		logf.Log.Error(err, "Failed to read directory", "path", basePath)
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return filepath.Join(basePath, entry.Name())
		}
	}
	return ""
}
