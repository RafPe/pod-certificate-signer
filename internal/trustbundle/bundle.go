package trustbundle

import (
	"strings"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/authority"
)

// Name returns the name of the ClusterTrustBundle resource for the given
// signer name, following the <domain>:<signerName>:<arbitrary-name>
// convention.
//
// https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/#cluster-trust-bundles
func Name(signerName string) string {
	return strings.ReplaceAll(signerName, "/", ":") + ":bundle"
}

// desired returns the ClusterTrustBundle the signer should have published: the
// CA's current trust bundle (current and retained previous CAs) under the
// bundle name derived from the signer name.
func desired(signerName string, ca *authority.CertificateAuthority) *certificatesv1.ClusterTrustBundle {
	return &certificatesv1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: Name(signerName)},
		Spec: certificatesv1.ClusterTrustBundleSpec{
			TrustBundle: string(ca.TrustBundlePEM()),
			SignerName:  signerName,
		},
	}
}
