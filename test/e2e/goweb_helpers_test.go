//go:build e2e
// +build e2e

package e2e

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
	"github.com/rafpe/kubernetes-podcertificate-signer/test/utils"
)

// The two HTTP outcomes these specs expect from /whoami.json. Named so a call
// site states which one it is asserting rather than passing a bare integer.
const (
	http200 = 200
	http403 = 403
)

// gowebStatusDocument is the part of goweb's /status.json this suite reads.
//
// It is a local, partial mirror of goweb's own type rather than an import: the
// image is pinned by digest and its JSON is a wire contract, so decoding only
// the fields asserted on keeps a field added upstream from being a compile
// error here. Refresh it alongside gowebImage.
type gowebStatusDocument struct {
	Server struct {
		StartedAt time.Time `json:"started_at"`
	} `json:"server"`

	Certificate *struct {
		FingerprintSHA256 string   `json:"fingerprint_sha256"`
		Subject           string   `json:"subject"`
		Issuer            string   `json:"issuer"`
		DNSNames          []string `json:"dns_names"`
		URIs              []string `json:"uris"`
		Validity          string   `json:"validity"`
	} `json:"certificate"`

	TrustBundle *struct {
		Anchors []struct {
			Subject           string `json:"subject"`
			FingerprintSHA256 string `json:"fingerprint_sha256"`
		} `json:"anchors"`
		LoadedAt     time.Time `json:"loaded_at"`
		LastSuccess  time.Time `json:"last_success"`
		StaleSeconds int64     `json:"stale_seconds"`
		LastError    string    `json:"last_error"`
	} `json:"trust_bundle"`
}

// gowebWhoamiDocument is the part of goweb's /whoami.json this suite reads.
type gowebWhoamiDocument struct {
	Authenticated bool   `json:"authenticated"`
	Reason        string `json:"reason"`

	Client *struct {
		Subject           string   `json:"subject"`
		Issuer            string   `json:"issuer"`
		FingerprintSHA256 string   `json:"fingerprint_sha256"`
		DNSNames          []string `json:"dns_names"`
		URIs              []string `json:"uris"`
		Chain             []string `json:"chain"`
	} `json:"client"`
}

// anchorFingerprints returns the SHA-256 fingerprints of the trust anchors the
// server reports enforcing, in the same encoding certificateFingerprints
// produces so the two can be compared directly.
func anchorFingerprints(status gowebStatusDocument) []string {
	if status.TrustBundle == nil {
		return nil
	}
	fingerprints := make([]string, 0, len(status.TrustBundle.Anchors))
	for _, anchor := range status.TrustBundle.Anchors {
		fingerprints = append(fingerprints, anchor.FingerprintSHA256)
	}
	return fingerprints
}

// certificateURIs renders a certificate's URI SANs as strings, the form goweb
// reports them in.
func certificateURIs(cert *x509.Certificate) []string {
	uris := make([]string, 0, len(cert.URIs))
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}
	return uris
}

// gowebServerDNSName is the name clients dial the server by: the Service DNS
// form, which is one of the two SANs the signer issues by default and the only
// one the cluster resolves.
func gowebServerDNSName() string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", gowebServerPodName, workloadNamespace)
}

func gowebStatusURL() string {
	return fmt.Sprintf("https://%s:%d/status.json", gowebServerDNSName(), gowebPort)
}

func gowebWhoamiURL() string {
	return fmt.Sprintf("https://%s:%d/whoami.json", gowebServerDNSName(), gowebPort)
}

// gowebStatus fetches and decodes the server's status document, presenting the
// caller pod's projected credential.
func gowebStatus(g Gomega, from podRef) gowebStatusDocument {
	facts := gowebPeerRequest(g, from, report.PeerModeProjected, gowebStatusURL())
	g.Expect(facts.HTTPStatus).To(Equal(http200),
		"the server must serve its status document; error was %q", facts.Error)

	var status gowebStatusDocument
	g.Expect(json.Unmarshal([]byte(facts.Body), &status)).To(Succeed(),
		"decoding the server's status document: %s", facts.Body)
	return status
}

// gowebWhoami fetches and decodes the server's account of the caller's identity,
// requiring the given HTTP status.
//
// The status is a parameter rather than always 200 because the refusal is as
// much a result as the acceptance: /whoami.json answers 403 with a populated
// document when no certificate was presented, and a helper that insisted on 200
// could not express the negative at all.
func gowebWhoami(g Gomega, from podRef, mode string, wantStatus int) gowebWhoamiDocument {
	facts := gowebPeerRequest(g, from, mode, gowebWhoamiURL())
	g.Expect(facts.HTTPStatus).To(Equal(wantStatus),
		"the server must answer HTTP %d to a %s credential; error was %q", wantStatus, mode, facts.Error)

	var whoami gowebWhoamiDocument
	g.Expect(json.Unmarshal([]byte(facts.Body), &whoami)).To(Succeed(),
		"decoding the server's whoami document: %s", facts.Body)
	return whoami
}

// gowebPeerRequest runs one credential-probe request from a client pod and
// returns what it observed.
//
// It goes through `kubectl exec` rather than reading the pod's log, and that is
// what the rotation spec needs: the pod's startup report describes the world as
// it was when the container began, and the question here is what a pod that has
// been running for ten minutes can do *now*. Exec'ing also makes each request
// retryable, so a transient failure is retried by the caller's Eventually
// instead of requiring a new pod.
func gowebPeerRequest(g Gomega, from podRef, mode, url string) report.PeerFacts {
	cmd := exec.Command("kubectl", "exec", from.name, "-n", from.namespace,
		"-c", workloadContainerName, "--",
		"/credprobe",
		"-role="+report.RolePeer,
		"-peer-mode="+mode,
		"-peer-url="+url,
		// Report and exit: this is a one-shot run inside a pod that is already
		// held open by its own long-lived process.
		"-hold=0",
		fmt.Sprintf("-expect-chain-len=%d", defaultChainLength),
		fmt.Sprintf("-bundle=%s/%s", certTestPodMountPath, defaultCredentialBundlePath),
		fmt.Sprintf("-trust=%s/ca.crt", certTestPodMountPath))
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(),
		"running the peer probe in pod %s failed; %s; output was: %s", from, podStatusSummary(from), output)

	parsed, err := report.Parse(output)
	g.Expect(err).NotTo(HaveOccurred(),
		"the peer probe in pod %s did not report: %v; output was: %s", from, err, output)

	g.Expect(parsed.CheckNames()).To(Equal(report.ExpectedChecks(report.RolePeer)),
		"the peer probe must run every check; a short report means it stopped early\n%s", parsed)
	g.Expect(parsed.Failures()).To(BeEmpty(),
		"the peer probe reached no definite outcome\n%s", parsed)
	g.Expect(parsed.Facts.Peer).NotTo(BeNil(), "the peer role must record peer facts\n%s", parsed)

	return *parsed.Facts.Peer
}

// observerTrustAnchors reads the projected trust anchors out of a pod's observer
// sidecar.
//
// It is mountedTrustAnchors for a pod whose workload container cannot be exec'd
// into: goweb is distroless and has neither a shell nor cat. The volume is the
// pod's, so the sidecar sees the identical projection at the identical moment -
// this is not a proxy for what the server can read, it is the same file.
func observerTrustAnchors(g Gomega, ref podRef) []*x509.Certificate {
	cmd := exec.Command("kubectl", "exec", ref.name, "-n", ref.namespace,
		"-c", observerContainerName, "--",
		"cat", certTestPodMountPath+"/ca.crt")
	output, err := utils.Run(cmd)
	g.Expect(err).NotTo(HaveOccurred(),
		"Failed to read the projected trust anchors from pod %s; %s", ref, podStatusSummary(ref))
	return parseCertificateChain(g, output)
}

// expectAnchorsUsableAsClientCAs asserts every published anchor satisfies what
// goweb requires of a client CA.
//
// The conditions are goweb's, restated here because it enforces them at startup
// and fails the whole load on one bad anchor: basic constraints present and
// asserting CA, the certSign key usage explicitly set, and the certificate
// currently within its validity window. RFC 5280 permits a CA to omit the key
// usage extension; goweb does not, and that is the condition most likely to be
// surprising.
func expectAnchorsUsableAsClientCAs(anchors []*x509.Certificate) {
	GinkgoHelper()

	now := time.Now()
	for _, anchor := range anchors {
		subject := anchor.Subject.CommonName
		Expect(anchor.BasicConstraintsValid).To(BeTrue(),
			"anchor %q has no valid basic constraints; the TLS workload refuses to start on it", subject)
		Expect(anchor.IsCA).To(BeTrue(),
			"anchor %q is not a CA; the TLS workload refuses to start on it", subject)
		Expect(anchor.KeyUsage&x509.KeyUsageCertSign).NotTo(BeZero(),
			"anchor %q does not assert the certSign key usage; the TLS workload requires it explicitly", subject)
		Expect(now).To(BeTemporally(">=", anchor.NotBefore),
			"anchor %q is not yet valid; the TLS workload refuses to start on it", subject)
		Expect(now).To(BeTemporally("<", anchor.NotAfter),
			"anchor %q has expired; the TLS workload refuses to start on it. A preceding container "+
				"rotates through a deliberately short-lived CA - if that one is still in the published "+
				"window, this is why", subject)
	}
}

// expectNoRestarts asserts every container in the pod is still on its first run.
//
// A restart would give a container a fresh process with a freshly loaded trust
// bundle, which is precisely the thing the rotation spec claims did not have to
// happen. The container statuses are decoded rather than string-matched so an
// empty list - a pod whose statuses have not been published yet - fails instead
// of passing vacuously.
func expectNoRestarts(ref podRef) {
	GinkgoHelper()

	cmd := exec.Command("kubectl", "get", "pod", ref.name, "-n", ref.namespace, "-o", "json")
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to read pod %s", ref)

	var pod corev1.Pod
	Expect(json.Unmarshal([]byte(trimToJSON(output)), &pod)).To(Succeed(),
		"Failed to decode pod %s", ref)

	Expect(pod.Status.ContainerStatuses).NotTo(BeEmpty(),
		"pod %s reported no container statuses, so 'no restarts' would prove nothing", ref)
	for _, status := range pod.Status.ContainerStatuses {
		Expect(status.RestartCount).To(BeZero(),
			"container %s of pod %s restarted %d time(s); the hot-reload claim requires the "+
				"original process to still be running", status.Name, ref, status.RestartCount)
	}
}

// createGowebServer creates the TLS workload.
//
// Everything it needs is configuration: the credential bundle it serves and the
// client CA file it verifies against are the two files kubelet already projects,
// named through goweb's own environment variables. Nothing about the image knows
// this signer exists, which is what makes its verdict worth having.
func createGowebServer() podRef {
	GinkgoHelper()

	bundlePath := fmt.Sprintf("%s/%s", certTestPodMountPath, defaultCredentialBundlePath)
	trustPath := certTestPodMountPath + "/ca.crt"

	return createCertTestPod(certTestPod{
		name:                   gowebServerPodName,
		image:                  gowebImage,
		clusterTrustBundleName: trustBundleName,
		labels:                 map[string]string{gowebSelectorLabel: gowebServerPodName},
		observerSidecar:        true,
		holdSeconds:            gowebObserverHold,
		userAnnotations: map[string]string{
			signerName + "-uris": gowebSpiffeURI,
		},
		env: []corev1.EnvVar{
			// One file holding the key and the chain: exactly the layout kubelet
			// writes, which is why no adaptation is needed between the signer's
			// output and this server's input.
			{Name: "GOWEB_X509_BUNDLE", Value: bundlePath},
			// Setting this is what turns client-certificate verification on;
			// there is no separate boolean.
			{Name: "GOWEB_MTLS_CLIENT_CA", Value: trustPath},
			{Name: "GOWEB_PORT", Value: fmt.Sprintf("%d", gowebPort)},
			{Name: "GOWEB_RELOAD_DEBOUNCE", Value: gowebReloadDebounce},
			{Name: "GOWEB_RELOAD_INTERVAL", Value: gowebReloadInterval},
		},
	})
}

// createGowebClient creates a credential-probe pod that can authenticate to the
// server.
//
// It runs in the client role at startup, which proves its own credential before
// any peer is involved, and then holds so the specs can exec peer requests
// through it for as long as the container lives.
func createGowebClient(podName string) podRef {
	GinkgoHelper()

	return createCertTestPod(certTestPod{
		name:                   podName,
		image:                  workloadProbeImage,
		serviceAccountName:     gowebClientServiceAccount,
		clusterTrustBundleName: trustBundleName,
		userAnnotations: map[string]string{
			// clientAuth is required, not cosmetic: Go's TLS server rejects a
			// client certificate without it for incompatible key usage, and the
			// spec would then be asserting an EKU boundary rather than trust.
			signerName + "-eku":  "client",
			signerName + "-uris": gowebSpiffeURI,
		},
		args: []string{
			"-role=" + report.RoleClient,
			fmt.Sprintf("-expect-chain-len=%d", defaultChainLength),
			fmt.Sprintf("-allowed-dns=%s.%s.pod.cluster.local", podName, workloadNamespace),
			fmt.Sprintf("-unrelated-dns=%s.%s.pod.attacker.example", podName, workloadNamespace),
			fmt.Sprintf("-bundle=%s/%s", certTestPodMountPath, defaultCredentialBundlePath),
			fmt.Sprintf("-trust=%s/ca.crt", certTestPodMountPath),
			// Long enough to outlive the whole container; see gowebObserverHold.
			fmt.Sprintf("-hold=%ds", gowebObserverHold),
		},
	})
}

// createGowebClientServiceAccount creates the identity the client pods run as,
// so their SPIFFE ID differs from the server's.
func createGowebClientServiceAccount() {
	GinkgoHelper()

	account := &corev1.ServiceAccount{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "ServiceAccount"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      gowebClientServiceAccount,
			Namespace: workloadNamespace,
		},
	}
	applyObject(account, "service account "+gowebClientServiceAccount)

	DeferCleanup(func() {
		cmd := exec.Command("kubectl", "delete", "serviceaccount", gowebClientServiceAccount,
			"-n", workloadNamespace, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	})
}

// createGowebService publishes the server under a name its certificate carries.
//
// It is headless on purpose. A ClusterIP would put kube-proxy between the two
// pods and the handshake would terminate against a virtual address; with no
// cluster IP, the name resolves straight to the pod and the TLS session is
// genuinely pod to pod, which is the claim these specs are making.
func createGowebService() {
	GinkgoHelper()

	service := &corev1.Service{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Service"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      gowebServerPodName,
			Namespace: workloadNamespace,
			Labels:    map[string]string{e2eWorkloadLabel: "true"},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: corev1.ClusterIPNone,
			Selector:  map[string]string{gowebSelectorLabel: gowebServerPodName},
			Ports: []corev1.ServicePort{{
				Name:       "https",
				Port:       gowebPort,
				TargetPort: intstr.FromInt32(gowebPort),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
	applyObject(service, "service "+gowebServerPodName)

	DeferCleanup(func() {
		cmd := exec.Command("kubectl", "delete", "service", gowebServerPodName,
			"-n", workloadNamespace, "--ignore-not-found=true")
		_, _ = utils.Run(cmd)
	})
}

// applyObject creates a typed object through kubectl, over stdin.
//
// Typed rather than a YAML string for the same reason createCertTestPod builds a
// typed Pod: a field the API renames becomes a compile error here instead of a
// setting the apiserver silently ignores.
func applyObject(object any, description string) {
	GinkgoHelper()

	manifest, err := json.Marshal(object)
	Expect(err).NotTo(HaveOccurred(), "Failed to marshal %s", description)

	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = bytes.NewReader(manifest)
	output, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to apply %s: %s", description, output)
}
