// Command dev-ca writes a self-signed P-256 CA as tls.crt and tls.key into a
// directory, for `make dev-ca`. It replaces an openssl invocation that LibreSSL
// on macOS accepted but mis-generated.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/internal/testutil"
)

func main() {
	dir := flag.String("dir", "", "directory to write tls.crt and tls.key into (required)")
	commonName := flag.String("cn", "podcertificate-signer-dev-ca", "certificate common name")
	days := flag.Int("days", 30, "validity in days from now")
	flag.Parse()

	if *dir == "" {
		fmt.Fprintln(os.Stderr, "dev-ca: -dir is required")
		os.Exit(2)
	}
	if err := run(*dir, *commonName, *days); err != nil {
		fmt.Fprintf(os.Stderr, "dev-ca: %v\n", err)
		os.Exit(1)
	}
}

func run(dir, commonName string, days int) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	now := time.Now()
	kp, err := testutil.NewCAWithValidity(commonName, now.Add(-time.Hour), now.Add(time.Duration(days)*24*time.Hour))
	if err != nil {
		return err
	}
	certPath, keyPath, err := kp.WriteFiles(dir)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s and %s (CN=%s, valid until %s)\n", certPath, keyPath, commonName, kp.Cert.NotAfter.UTC().Format(time.RFC3339))
	return nil
}
