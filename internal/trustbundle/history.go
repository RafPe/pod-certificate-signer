package trustbundle

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	certificatesv1 "k8s.io/api/certificates/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ErrHistoryBundleAbsent reports that the signer's ClusterTrustBundle does not
// exist. It is a distinct outcome from a failed read: retrying will not make an
// absent object appear, and whether absence is fatal is the caller's policy
// (see LoadPreviousCAHistory), not this package's.
var ErrHistoryBundleAbsent = errors.New("the signer's ClusterTrustBundle does not exist")

// errHistoryBundleCorrupt reports that the bundle was read but holds a
// CERTIFICATE block that does not parse. Rereading the same object cannot fix
// it, so it is not retried; startup fails closed (see parsePEMCertificates).
var errHistoryBundleCorrupt = errors.New("the signer's ClusterTrustBundle holds a certificate that does not parse")

// LoadPreviousCAHistory reads the previous-CA history the signer published
// before this process started, with bounded retry. A transient read error must
// not fall through to an empty history: publishing an empty bundle would drop
// previously-trusted CAs, and every certificate issued under a retired CA would
// stop verifying. Such errors fail closed.
//
// Absence is the case that cannot be decided from the cluster. A bundle that
// has never existed (a first install) and one that was deleted look identical,
// and the controller keeps no other record of its own history, so treating
// absence as fatal would break every first install while treating it as empty
// makes a deleted bundle a permanent, controller-endorsed loss of history.
// The default keeps first installs working; requireHistory lets an operator who
// knows the bundle should exist turn absence into a startup failure. Either way
// the loss is announced rather than logged as routine. See
// docs/adr/0004-bootstrapped-previous-ca-history.md.
func LoadPreviousCAHistory(ctx context.Context, c client.Reader, signerName string, requireHistory bool) ([]*x509.Certificate, error) {
	logger := log.FromContext(ctx)

	var previousCAs []*x509.Certificate
	// Retry transient read errors only: not absence or a corrupt bundle
	// (rereading cannot change either), and not once ctx has ended - the same
	// rule the publisher applies to the same backoff.
	retriable := func(err error) bool {
		return ctx.Err() == nil && !errors.Is(err, ErrHistoryBundleAbsent) && !errors.Is(err, errHistoryBundleCorrupt)
	}
	err := retry.OnError(apiRetryBackoff, retriable, func() error {
		var ferr error
		previousCAs, ferr = fetchPreviousCAs(ctx, c, signerName)

		return ferr
	})

	if err == nil {
		logger.Info("bootstrapped previous CA certificates from ClusterTrustBundle",
			"name", bundleName(signerName), "count", len(previousCAs))
		return previousCAs, nil
	}
	if !errors.Is(err, ErrHistoryBundleAbsent) || requireHistory {
		// A real read error, or an absence the operator declared fatal.
		return nil, err
	}

	// Expected on a first install; after one, the retained history is gone
	// and certificates issued under a retired CA stop verifying once the
	// bundle is republished. docs/operations.md says what to do about it.
	logger.Error(err, "previous-CA history starts empty: a deleted bundle is indistinguishable from a first install; "+
		"restore it before this controller publishes, or run with --require-ca-history to make this fatal",
		"bundle", bundleName(signerName))

	return nil, nil
}

// fetchPreviousCAs reads the existing ClusterTrustBundle for the given signer
// and parses its PEM certificates, so previously-trusted CAs are retained
// across a restart.
//
// A missing bundle is reported as ErrHistoryBundleAbsent rather than as an
// empty history, so the decision of what absence means is taken once, by
// LoadPreviousCAHistory. Any other read error is returned so the caller can
// retry or fail closed: silently returning an empty history would overwrite the
// bundle on startup and drop previously-trusted CAs.
func fetchPreviousCAs(ctx context.Context, c client.Reader, signerName string) ([]*x509.Certificate, error) {
	name := bundleName(signerName)

	bundle := &certificatesv1.ClusterTrustBundle{}
	if err := c.Get(ctx, client.ObjectKey{Name: name}, bundle); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("read existing ClusterTrustBundle %q: %w", name, ErrHistoryBundleAbsent)
		}
		return nil, fmt.Errorf("read existing ClusterTrustBundle %q: %w", name, err)
	}

	certs, err := parsePEMCertificates([]byte(bundle.Spec.TrustBundle))
	if err != nil {
		return nil, fmt.Errorf("parse existing ClusterTrustBundle %q: %w: %w", name, errHistoryBundleCorrupt, err)
	}

	return certs, nil
}

// parsePEMCertificates extracts the x509 certificates from a PEM-encoded
// bundle. Non-certificate blocks are skipped; a CERTIFICATE block that does not
// parse is an error. The bundle is the controller's only record of its own
// history, so a corrupt entry is reported to the caller - which fails closed -
// rather than dropped, which would silently shorten the history the next
// publish writes back.
func parsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return certs, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate %d in the bundle: %w", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
}
