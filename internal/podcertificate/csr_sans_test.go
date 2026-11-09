package podcertificate

import (
	"context"
	"net"
	"testing"
)

// CSR-requested SANs are used when the feature is enabled and no annotation
// overrides them. The CSR values here (csr.example.org, 10.1.2.3) are not
// derived from a verified pod identity, so honoring them requires the
// AllowUnverifiedIdentities opt-in; under the default constraints these same
// values are denied (see TestCSRSANsIdentityConstraint).
func TestCSRSANsHonoredWhenEnabled(t *testing.T) {
	csr := &CSR{DNSNames: []string{"csr.example.org"}, IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}}
	opts := Options{HonorCSRSANs: true, AllowUnverifiedIdentities: true}

	config, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), csr, opts)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if len(config.DNSNames) != 1 || config.DNSNames[0] != "csr.example.org" {
		t.Errorf("DNSNames = %v, want the CSR-requested name", config.DNSNames)
	}
	if len(config.IPAddresses) != 1 || !config.IPAddresses[0].Equal(net.ParseIP("10.1.2.3")) {
		t.Errorf("IPAddresses = %v, want the CSR-requested IP", config.IPAddresses)
	}
}

// When identity constraints are enforced (the default), CSR-requested SANs must
// pass the same verified-identity allowlist that annotation cn/san/uris values
// pass: a CSR SAN the pod does not own is denied, one it does own is honored,
// and IP SANs (which have no verified derivation) are denied outright. The
// blanket denial and honoring are both lifted by AllowUnverifiedIdentities.
func TestCSRSANsIdentityConstraint(t *testing.T) {
	// Emitted by the signer itself for testPod, so it is a verified identity.
	const verifiedDNS = "mypod.myns.pod.cluster.local"
	honor := Options{HonorCSRSANs: true}

	t.Run("unverified CSR DNS name denied", func(t *testing.T) {
		csr := &CSR{DNSNames: []string{"csr.attacker.example"}}
		if _, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), csr, honor); err == nil {
			t.Fatal("want denial for an unverified CSR DNS name, got nil")
		}
	})

	t.Run("verified CSR DNS name honored", func(t *testing.T) {
		csr := &CSR{DNSNames: []string{verifiedDNS}}
		config, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), csr, honor)
		if err != nil {
			t.Fatalf("want the verified CSR DNS name honored, got error: %v", err)
		}
		if len(config.DNSNames) != 1 || config.DNSNames[0] != verifiedDNS {
			t.Errorf("DNSNames = %v, want [%s]", config.DNSNames, verifiedDNS)
		}
	})

	t.Run("CSR IP SAN denied", func(t *testing.T) {
		csr := &CSR{IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}}
		if _, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), csr, honor); err == nil {
			t.Fatal("want denial for a CSR IP SAN under identity constraints, got nil")
		}
	})

	t.Run("unverified CSR SANs allowed with opt-in", func(t *testing.T) {
		csr := &CSR{DNSNames: []string{"csr.attacker.example"}, IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}}
		opts := Options{HonorCSRSANs: true, AllowUnverifiedIdentities: true}
		if _, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), csr, opts); err != nil {
			t.Fatalf("want CSR SANs honored with --allow-unverified-identities, got error: %v", err)
		}
	})
}

// The san annotation takes precedence over CSR-requested DNS names.
func TestCSRSANsAnnotationTakesPrecedence(t *testing.T) {
	pcr := testPCR(map[string]string{testSignerName + "-san": "annotated.example.org"})
	csr := &CSR{DNSNames: []string{"csr.example.org"}}
	opts := Options{HonorCSRSANs: true, AllowUnverifiedIdentities: true} // literal annotation value

	config, err := NewConfig(context.Background(), pcr, testPod(nil), csr, opts)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if len(config.DNSNames) != 1 || config.DNSNames[0] != "annotated.example.org" {
		t.Errorf("DNSNames = %v, want the annotation to win over CSR SANs", config.DNSNames)
	}
}

// With the feature disabled (default), CSR SANs are ignored - the API
// contract explicitly allows signers to ignore CSR contents.
func TestCSRSANsIgnoredWhenDisabled(t *testing.T) {
	csr := &CSR{DNSNames: []string{"csr.example.org"}, IPAddresses: []net.IP{net.ParseIP("10.1.2.3")}}

	config, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), csr, Options{})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if len(config.DNSNames) != 2 || config.DNSNames[0] != "mypod.myns.pod.cluster.local" {
		t.Errorf("DNSNames = %v, want the defaults", config.DNSNames)
	}
	if len(config.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v, want none when the feature is disabled", config.IPAddresses)
	}
}

// The ip-san annotation sets IP SANs and takes precedence over CSR IPs.
func TestIPSANAnnotation(t *testing.T) {
	pcr := testPCR(map[string]string{testSignerName + "-ip-san": "10.0.0.1, 2001:db8::1"})
	csr := &CSR{IPAddresses: []net.IP{net.ParseIP("192.168.0.1")}}
	opts := Options{HonorCSRSANs: true, AllowUnverifiedIdentities: true} // annotation IP SANs need the opt-in

	config, err := NewConfig(context.Background(), pcr, testPod(nil), csr, opts)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if len(config.IPAddresses) != 2 ||
		!config.IPAddresses[0].Equal(net.ParseIP("10.0.0.1")) ||
		!config.IPAddresses[1].Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("IPAddresses = %v, want the annotated IPs to win over CSR IPs", config.IPAddresses)
	}
}

// Malformed ip-san values must deny the request.
func TestIPSANAnnotationInvalid(t *testing.T) {
	cases := map[string]string{
		"not an IP":  "not-an-ip",
		"empty list": " , ",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			// Opt in to unverified identities so the parse error is exercised
			// rather than the blanket IP-SAN denial.
			pcr := testPCR(map[string]string{testSignerName + "-ip-san": value})
			if _, err := NewConfig(context.Background(), pcr, testPod(nil), nil, Options{AllowUnverifiedIdentities: true}); err == nil {
				t.Fatalf("want error for ip-san %q, got nil", value)
			}
		})
	}
}

// Enabled but with an empty CSR (kubelet today): defaults still apply.
func TestCSRSANsEmptyCSRKeepsDefaults(t *testing.T) {
	config, err := NewConfig(context.Background(), testPCR(nil), testPod(nil), &CSR{}, Options{HonorCSRSANs: true})
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if len(config.DNSNames) != 2 || config.DNSNames[0] != "mypod.myns.pod.cluster.local" {
		t.Errorf("DNSNames = %v, want the defaults", config.DNSNames)
	}
	if len(config.IPAddresses) != 0 {
		t.Errorf("IPAddresses = %v, want none for an empty CSR", config.IPAddresses)
	}
}
