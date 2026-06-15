package podcertificate

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNewPodCertificateConfig_DefaultSANsUseClusterFqdn(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "team-a"}}

	cfg, err := NewPodCertificateConfig(context.Background(), pod, "example.org/signer", "mycluster.example.com", nil, x509.RSA)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}

	want := []string{
		"app.team-a.pod.mycluster.example.com",
		"app.team-a.svc.mycluster.example.com",
	}
	if len(cfg.DNSNames) != len(want) {
		t.Fatalf("DNSNames = %v, want %v", cfg.DNSNames, want)
	}
	for i := range want {
		if cfg.DNSNames[i] != want[i] {
			t.Errorf("DNSNames[%d] = %q, want %q", i, cfg.DNSNames[i], want[i])
		}
	}
}

func TestNewPodCertificateConfig_AnnotationOverridesWin(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "app", Namespace: "team-a",
		Annotations: map[string]string{"example.org/signer-san": "custom.example.com"},
	}}
	cfg, err := NewPodCertificateConfig(context.Background(), pod, "example.org/signer", "mycluster.example.com", nil, x509.RSA)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if len(cfg.DNSNames) != 1 || cfg.DNSNames[0] != "custom.example.com" {
		t.Fatalf("DNSNames = %v, want [custom.example.com]", cfg.DNSNames)
	}
}

func TestNewPodCertificateConfig_BadDurationAnnotationFallsBackToDefault(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "app", Namespace: "team-a",
		Annotations: map[string]string{"example.org/signer-duration": "not-a-duration"},
	}}
	cfg, err := NewPodCertificateConfig(context.Background(), pod, "example.org/signer", "cluster.local", nil, x509.RSA)
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if cfg.Duration != 24*time.Hour {
		t.Fatalf("Duration = %v, want 24h default on invalid annotation", cfg.Duration)
	}
}
