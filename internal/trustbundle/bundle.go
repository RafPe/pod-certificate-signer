// Package trustbundle publishes the signer's CA as a ClusterTrustBundle: a
// leader-gated runnable that keeps the published bundle in step with the
// certificate authority, and the startup read that seeds the previous-CA
// history from the bundle a prior process published.
package trustbundle

import (
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// bundleSource is what the publisher needs from the certificate authority: the
// trust bundle to publish. Declared here, where it is consumed, like the
// controller's Signer and the metrics' CAState.
type bundleSource interface {
	TrustBundlePEM() []byte
}

// bundleName returns the name of the ClusterTrustBundle resource for the given
// signer name, following the <domain>:<signerName>:<arbitrary-name>
// convention.
//
// https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles
func bundleName(signerName string) string {
	return strings.ReplaceAll(signerName, "/", ":") + ":bundle"
}

// desiredBundle returns the ClusterTrustBundle the signer should have
// published: the CA's current trust bundle (current and retained previous CAs)
// under the bundle name derived from the signer name.
func desiredBundle(signerName string, source bundleSource) *certificatesv1.ClusterTrustBundle {
	return &certificatesv1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: bundleName(signerName)},
		Spec: certificatesv1.ClusterTrustBundleSpec{
			TrustBundle: string(source.TrustBundlePEM()),
			SignerName:  signerName,
		},
	}
}
