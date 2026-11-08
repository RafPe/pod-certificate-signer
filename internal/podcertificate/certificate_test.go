package podcertificate

import (
	"context"
	"testing"
	"time"
)

// An explicitly requested duration above maxExpirationSeconds must fail
// validation instead of being rejected by kube-apiserver on status update.
func TestValidateDurationExceedingMaxExpiration(t *testing.T) {
	pcr := testPCR(map[string]string{testSignerName + "-duration": "4h"})
	maxExpirationSeconds := int32(7200)
	pcr.Spec.MaxExpirationSeconds = &maxExpirationSeconds

	config, err := NewPodCertificateConfig(context.Background(), pcr, testPod(nil), nil, Options{})
	if err != nil {
		t.Fatalf("NewPodCertificateConfig: %v", err)
	}
	if err := config.Validate(); err == nil {
		t.Fatal("want validation error for duration above maxExpirationSeconds, got nil")
	}
}

func TestPodCertificateConfigValidate(t *testing.T) {
	valid := PodCertificateConfig{CommonName: "cn", Duration: time.Hour, RefreshBefore: 15 * time.Minute}

	cases := []struct {
		name    string
		mutate  func(c *PodCertificateConfig)
		wantErr bool
	}{
		{"valid", func(c *PodCertificateConfig) {}, false},
		{"missing common name", func(c *PodCertificateConfig) { c.CommonName = "" }, true},
		{"non-positive duration", func(c *PodCertificateConfig) { c.Duration = 0 }, true},
		{"duration below apiserver minimum", func(c *PodCertificateConfig) { c.Duration = 30 * time.Minute }, true},
		{"duration above max expiration", func(c *PodCertificateConfig) { c.MaxExpiration = 30 * time.Minute; c.Duration = time.Hour }, true},
		{"negative refresh", func(c *PodCertificateConfig) { c.RefreshBefore = -time.Minute }, true},
		{"refresh below apiserver margin", func(c *PodCertificateConfig) { c.RefreshBefore = 5 * time.Minute }, true},
		{"refresh not shorter than duration", func(c *PodCertificateConfig) { c.RefreshBefore = time.Hour }, true},
		{"refresh too close to duration", func(c *PodCertificateConfig) { c.RefreshBefore = 55 * time.Minute }, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := valid
			tc.mutate(&config)
			if err := config.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate() = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}
