package podcertificate

import (
	"strings"
	"testing"
)

func TestDNSNamesRejectMalformedValuesFromEverySource(t *testing.T) {
	invalidName := strings.Repeat("a", 64) + ".example.org"
	tests := []struct {
		name string
		pcr  func() map[string]string
		opts Options
	}{
		{
			name: "literal annotation with unverified identities allowed",
			pcr: func() map[string]string {
				return map[string]string{testSignerName + "-san": invalidName}
			},
			opts: Options{AllowUnverifiedIdentities: true},
		},
		{
			name: "interpolated annotation that is allowlisted",
			pcr: func() map[string]string {
				return map[string]string{testSignerName + "-san": "${pod.name}.${pod.namespace}.pod.${cluster.fqdn}"}
			},
			opts: Options{EnableInterpolation: true},
		},
		{
			name: "CSR with unverified identities allowed",
			pcr:  func() map[string]string { return nil },
			opts: Options{
				HonorCSRSANs:              true,
				AllowUnverifiedIdentities: true,
				CSRDNSNames:               []string{invalidName},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcr := testPCR(tt.pcr())
			pod := testPod(nil)
			if strings.Contains(tt.name, "interpolated") {
				pcr.Spec.PodName = strings.Repeat("a", 64)
				pod.Name = pcr.Spec.PodName
			}

			_, err := NewPodCertificateConfig(pcr, pod, tt.opts, nil, 0)
			if err == nil {
				t.Fatalf("NewPodCertificateConfig(DNS SAN %q) error = nil, want invalid DNS name error", invalidName)
			}
			if !strings.Contains(err.Error(), "DNS name") || !strings.Contains(err.Error(), "63") {
				t.Errorf("NewPodCertificateConfig(DNS SAN %q) error = %q, want DNS label limit detail", invalidName, err)
			}
		})
	}
}

func TestDNSNameValidationBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		dnsName string
		wantErr bool
	}{
		{name: "63 character label", dnsName: strings.Repeat("a", 63) + ".example.org"},
		{name: "64 character label", dnsName: strings.Repeat("a", 64) + ".example.org", wantErr: true},
		{name: "empty label", dnsName: "a..example.org", wantErr: true},
		{name: "trailing hyphen", dnsName: "invalid-.example.org", wantErr: true},
		{name: "invalid character", dnsName: "invalid_name.example.org", wantErr: true},
		{name: "overlong complete name", dnsName: strings.Repeat("a.", 126) + "aa", wantErr: true},
		{name: "wildcard rejected", dnsName: "*.example.org", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcr := testPCR(map[string]string{testSignerName + "-san": tt.dnsName})
			_, err := NewPodCertificateConfig(
				pcr,
				testPod(nil),
				Options{AllowUnverifiedIdentities: true},
				nil,
				0,
			)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Errorf("NewPodCertificateConfig(DNS SAN %q) error = %v, want error = %t", tt.dnsName, err, tt.wantErr)
			}
		})
	}
}

func TestDNSNameValidationRejectsOneInvalidNameInList(t *testing.T) {
	invalidName := strings.Repeat("a", 64) + ".example.org"
	pcr := testPCR(map[string]string{
		testSignerName + "-san": "valid.example.org," + invalidName + ",also-valid.example.org",
	})

	_, err := NewPodCertificateConfig(
		pcr,
		testPod(nil),
		Options{AllowUnverifiedIdentities: true},
		nil,
		0,
	)
	if err == nil || !strings.Contains(err.Error(), invalidName) {
		t.Fatalf("NewPodCertificateConfig(DNS SAN list containing %q) error = %v, want offending name", invalidName, err)
	}
}
