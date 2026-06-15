package authority

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestNotAfterReturnsCertExpiry(t *testing.T) {
	exp := time.Now().Add(48 * time.Hour)
	ca := &CertificateAuthority{certificate: &x509.Certificate{NotAfter: exp}, nowFunc: time.Now}
	if got := ca.NotAfter(); !got.Equal(exp) {
		t.Fatalf("NotAfter() = %v, want %v", got, exp)
	}
}
