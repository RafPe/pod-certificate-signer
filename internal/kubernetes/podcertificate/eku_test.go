package podcertificate

import (
	"crypto/x509"
	"reflect"
	"testing"
)

func TestEKUAnnotation(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  []x509.ExtKeyUsage
	}{
		{"client only", "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{"server only", "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{"both", "client,server", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}},
		{"whitespace and duplicates", " server , server ", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pcr := testPCR(map[string]string{testSignerName + "-eku": tc.value})
			config, err := NewPodCertificateConfig(pcr, testPod(nil), Options{}, nil, 0)
			if err != nil {
				t.Fatalf("NewPodCertificateConfig: %v", err)
			}
			if !reflect.DeepEqual(config.ExtKeyUsage, tc.want) {
				t.Errorf("ExtKeyUsage = %v, want %v", config.ExtKeyUsage, tc.want)
			}
		})
	}
}

func TestEKUAnnotationInvalid(t *testing.T) {
	for name, value := range map[string]string{
		"unknown token": "client,ssl",
		"empty list":    " , ",
	} {
		t.Run(name, func(t *testing.T) {
			pcr := testPCR(map[string]string{testSignerName + "-eku": value})
			if _, err := NewPodCertificateConfig(pcr, testPod(nil), Options{}, nil, 0); err == nil {
				t.Fatalf("want error for eku %q, got nil", value)
			}
		})
	}
}

func TestEKUDefaultServerAuthOnly(t *testing.T) {
	config, err := NewPodCertificateConfig(testPCR(nil), testPod(nil), Options{}, nil, 0)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	// ClientAuth is an explicit opt-in (via the eku annotation); the default is
	// ServerAuth only, so a leaked pod certificate cannot be replayed as a
	// client credential.
	want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if !reflect.DeepEqual(config.ExtKeyUsage, want) {
		t.Errorf("ExtKeyUsage = %v, want default %v", config.ExtKeyUsage, want)
	}
}

func TestKeyUsagePerAlgorithm(t *testing.T) {
	cases := []struct {
		alg  x509.PublicKeyAlgorithm
		want x509.KeyUsage
	}{
		{x509.RSA, x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment},
		{x509.ECDSA, x509.KeyUsageDigitalSignature},
		{x509.Ed25519, x509.KeyUsageDigitalSignature},
	}
	for _, tc := range cases {
		config, err := NewPodCertificateConfig(testPCR(nil), testPod(nil), Options{}, nil, tc.alg)
		if err != nil {
			t.Fatalf("NewPodCertificateConfig: %v", err)
		}
		if config.KeyUsage != tc.want {
			t.Errorf("alg %v: KeyUsage = %v, want %v", tc.alg, config.KeyUsage, tc.want)
		}
	}
}
