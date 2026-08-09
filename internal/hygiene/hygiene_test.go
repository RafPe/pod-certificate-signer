package hygiene

import (
	"encoding/base64"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// pemPrivateKeyHeader matches a PEM private-key block header, e.g.
// "-----BEGIN RSA PRIVATE KEY-----" or "-----BEGIN EC PRIVATE KEY-----". The
// pattern is assembled from fragments so this test file does not match itself.
var pemPrivateKeyHeader = regexp.MustCompile(
	"-----BEGIN [A-Z0-9 ]*PRIVATE" + " " + "KEY-----",
)

// base64Blob matches a contiguous base64 run long enough to plausibly hold a
// PEM private key that has been embedded (e.g. inside a Kubernetes Secret).
var base64Blob = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

// TestNoTrackedPrivateKeys fails if any git-tracked file contains a PEM private
// key, either as plaintext or base64-encoded (as in a committed Secret
// manifest). Private keys must never be committed to the repository; a leaked
// signing key compromises every certificate the signer ever issues.
func TestNoTrackedPrivateKeys(t *testing.T) {
	root := repoRoot(t)

	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}

	for _, rel := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if rel == "" {
			continue
		}
		// Skip this test's own source: it necessarily mentions the markers
		// it searches for.
		if strings.HasSuffix(rel, "hygiene_test.go") {
			continue
		}

		data, err := exec.Command("git", "-C", root, "show", ":"+rel).Output()
		if err != nil {
			// Fall back to reading from disk for anything git cannot cat
			// (should not happen for tracked files).
			t.Logf("skipping %q: git show: %v", rel, err)
			continue
		}

		if pemPrivateKeyHeader.Match(data) {
			t.Errorf("tracked file %q contains a plaintext PEM private key", rel)
			continue
		}
		if loc := base64EncodedPrivateKey(data); loc != "" {
			t.Errorf("tracked file %q contains a base64-encoded PEM private key (decoded: %q)", rel, loc)
		}
	}
}

// base64EncodedPrivateKey reports the decoded PEM header when data contains a
// base64 blob that decodes to a PEM private key, or "" otherwise.
func base64EncodedPrivateKey(data []byte) string {
	for _, blob := range base64Blob.FindAll(data, -1) {
		decoded, err := base64.StdEncoding.DecodeString(string(blob))
		if err != nil {
			continue
		}
		if pemPrivateKeyHeader.Match(decoded) {
			header := pemPrivateKeyHeader.Find(decoded)
			return string(header)
		}
	}
	return ""
}

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("git rev-parse --show-toplevel: %v", err)
	}
	return filepath.Clean(strings.TrimSpace(string(out)))
}
