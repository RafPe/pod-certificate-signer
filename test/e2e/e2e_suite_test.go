//go:build e2e
// +build e2e

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

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

var (
	// Optional Environment Variables:
	// - CERT_MANAGER_INSTALL_SKIP=true: Skips CertManager installation during test setup.
	// These variables are useful if CertManager is already installed, avoiding
	// re-installation and conflicts.
	skipCertManagerInstall = os.Getenv("CERT_MANAGER_INSTALL_SKIP") == "true"
	// isCertManagerAlreadyInstalled will be set true when CertManager CRDs be found on the cluster
	isCertManagerAlreadyInstalled = false

	// projectImage is the name of the image which will be build and loaded
	// with the code source changes to be tested.
	projectImage = "example.com/pcs:v0.0.1"

	// workloadProbeImage is the in-cluster credential probe the
	// credential-conformance specs run as their workload (test/credprobe).
	//
	// It is built from this repository and loaded into Kind for the same reason
	// the manager image is: a third-party workload image would have to exist,
	// and be reachable, on whatever runner executes `make test-e2e`. The value
	// must match the Makefile's E2E_WORKLOAD_IMAGE default.
	workloadProbeImage = "example.com/pcs-credprobe:v0.0.1"
)

// TestE2E runs the end-to-end (e2e) test suite for the project. These tests execute in an isolated,
// temporary environment to validate project changes with the purpose of being used in CI jobs.
// The default setup requires Kind, builds/loads the Manager Docker image locally, and installs
// CertManager.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting pcs integration test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	By("verifying the suite is running in a single process")
	// The suite mutates cluster-wide state mid-run: installProfile re-installs
	// the Helm release in place with different signer flags, and the
	// ClusterTrustBundle context rotates the CA secret. Neither is scoped to a
	// spec, so a second process would silently run its specs against another
	// process's install and produce results that describe a configuration that
	// was never under test.
	//
	// The top-level container is decorated Serial, which is the correct
	// declaration but not a sufficient guarantee - it orders specs, it does not
	// stop the suite being launched with `--procs`. This guard does, and it runs
	// in every process so a parallel invocation fails immediately and loudly
	// rather than after the first profile switch corrupts the run.
	suiteConfig, _ := GinkgoConfiguration()
	Expect(suiteConfig.ParallelTotal).To(Equal(1),
		"the e2e suite mutates cluster-wide state (Helm install profiles, CA rotation) and must run "+
			"in a single process; it was started with %d. Run it via `make test-e2e`.", suiteConfig.ParallelTotal)
	Expect(GinkgoParallelProcess()).To(Equal(1),
		"the e2e suite must run as parallel process 1, got %d", GinkgoParallelProcess())

	By("building the manager(Operator) image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMAGE=%s", projectImage))
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")

	// TODO(user): If you want to change the e2e test vendor from Kind, ensure the image is
	// built and available before running the tests. Also, remove the following block.
	By("loading the manager(Operator) image on Kind")
	err = utils.LoadImageToKindClusterWithName(projectImage)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager(Operator) image into Kind")

	By("building the credential probe workload image")
	cmd = exec.Command("make", "e2e-workload-image", fmt.Sprintf("E2E_WORKLOAD_IMAGE=%s", workloadProbeImage))
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the credential probe image")

	By("loading the credential probe workload image on Kind")
	err = utils.LoadImageToKindClusterWithName(workloadProbeImage)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the credential probe image into Kind")

	// The tests-e2e are intended to run on a temporary cluster that is created and destroyed for testing.
	// To prevent errors when tests run in environments with CertManager already installed,
	// we check for its presence before execution.
	// Setup CertManager before the suite if not skipped and if not already installed
	if !skipCertManagerInstall {
		By("checking if cert manager is installed already")
		isCertManagerAlreadyInstalled = utils.IsCertManagerCRDsInstalled()
		if !isCertManagerAlreadyInstalled {
			_, _ = fmt.Fprintf(GinkgoWriter, "Installing CertManager...\n")
			Expect(utils.InstallCertManager()).To(Succeed(), "Failed to install CertManager")
		} else {
			_, _ = fmt.Fprintf(GinkgoWriter, "WARNING: CertManager is already installed. Skipping installation...\n")
		}
	}
})

var _ = AfterSuite(func() {
	// Teardown CertManager after the suite if not skipped and if it was not already installed
	if !skipCertManagerInstall && !isCertManagerAlreadyInstalled {
		_, _ = fmt.Fprintf(GinkgoWriter, "Uninstalling CertManager...\n")
		utils.UninstallCertManager()
	}
})
