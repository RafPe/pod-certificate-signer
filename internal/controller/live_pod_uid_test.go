package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/go-logr/logr"
	capiv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/kubernetes/podcertificate"
)

// livePCR returns a PCR carrying a valid PKIX public key that expects the pod
// identified by requestUID, plus a pod object stamped with podUID.
func livePCR(t *testing.T, requestUID, podUID types.UID) (*capiv1beta1.PodCertificateRequest, *corev1.Pod) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	pkixKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal PKIX public key: %v", err)
	}

	pcr := &capiv1beta1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr", Namespace: "ns"},
		Spec: capiv1beta1.PodCertificateRequestSpec{
			PodName:       "mypod",
			PodUID:        requestUID,
			PKIXPublicKey: pkixKey,
		},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "mypod", Namespace: "ns", UID: podUID}}
	return pcr, pod
}

func stubCert() *podcertificate.PodCertificate {
	return podcertificate.NewPodCertificate(
		nil, "pem-chain",
		&podcertificate.PodCertificateConfig{},
		time.Now(), time.Now().Add(time.Hour),
	)
}

// When the manager cache misses but the pod exists on a live read, the
// controller must re-read via the APIReader and proceed to sign, instead of
// recording a terminal AssociatedPodNotFound on a cache/creation race.
func TestProcessCacheMissReadsLive(t *testing.T) {
	pcr, pod := livePCR(t, "uid-1", "uid-1")
	cache := fake.NewClientBuilder().WithScheme(newTestScheme(t)).Build() // pod absent from cache
	live := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(pod).Build()
	stub := &stubSigner{name: "example.org/signer", cert: stubCert()}
	r := &PodCertificateRequestReconciler{Client: cache, APIReader: live, Log: logr.Discard(), Signer: stub}
	ctx := logr.NewContext(context.Background(), logr.Discard())

	cert, err := r.process(ctx, pcr)
	if err != nil {
		t.Fatalf("process() error = %v, want nil (live read should find the pod)", err)
	}
	if !stub.called {
		t.Fatal("process() did not reach the signer after the live re-read")
	}
	if cert == nil {
		t.Fatal("process() cert = nil, want the signed certificate")
	}
	// The config must be built from the pod found on the live read.
	if stub.gotConfig == nil || stub.gotConfig.CommonName != "mypod" {
		t.Fatalf("signed config = %+v, want CommonName %q from the live pod", stub.gotConfig, "mypod")
	}
}

// When the pod that exists has a UID different from the request's PodUID, the
// request is stale: the controller must drop it (nil, nil) and must NOT sign
// with the wrong pod's identity.
func TestProcessStalePodUIDDropped(t *testing.T) {
	pcr, stalePod := livePCR(t, "uid-1", "uid-stale")
	cache := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(stalePod).Build()
	live := fake.NewClientBuilder().WithScheme(newTestScheme(t)).WithObjects(stalePod).Build()
	stub := &stubSigner{name: "example.org/signer", cert: stubCert()}
	r := &PodCertificateRequestReconciler{Client: cache, APIReader: live, Log: logr.Discard(), Signer: stub}
	ctx := logr.NewContext(context.Background(), logr.Discard())

	cert, err := r.process(ctx, pcr)
	if cert != nil || err != nil {
		t.Fatalf("got (%v, %v), want (nil, nil) drop for a UID-mismatched pod", cert, err)
	}
	if stub.called {
		t.Fatal("signer must not run for a UID-mismatched (stale) pod")
	}
}
