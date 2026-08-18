/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Command credprobe validates, from inside a workload pod, the credential
// kubelet projected into it.
//
// The e2e suite can read a PodCertificateRequest's status from outside the
// cluster and check that it carries a well-formed certificate. What it cannot
// do from there is answer the question the workload actually cares about:
// whether the files under the projected volume are present, readable by the
// user the container runs as, internally consistent, and usable to complete a
// TLS handshake against the trust anchors projected alongside them. This
// binary answers that, writes one line of JSON (see the report package), and
// then holds the process open so the pod stays Running while the suite reads
// it.
//
// It asserts nothing about material it cannot publish: the private key is used
// and never reported, and everything in the report is public - fingerprints,
// PEM block types, sizes, certificate fields and booleans.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rafpe/kubernetes-podcertificate-signer/test/credprobe/report"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.bundlePath, "bundle", "/var/run/x509/credentialbundle.pem",
		"path of the projected credential bundle")
	flag.StringVar(&cfg.trustPath, "trust", "/var/run/x509/ca.crt",
		"path of the projected ClusterTrustBundle")
	flag.StringVar(&cfg.role, "role", report.RoleServer,
		"extended key usage the projected certificate was issued with: server or client")
	flag.IntVar(&cfg.expectChainLen, "expect-chain-len", 2,
		"number of certificates the bundle must carry after the private key")
	flag.StringVar(&cfg.allowedDNS, "allowed-dns", "",
		"a DNS name the projected certificate is expected to carry")
	flag.StringVar(&cfg.unrelatedDNS, "unrelated-dns", "unrelated.invalid",
		"a DNS name the projected certificate must not be accepted for")
	flag.DurationVar(&cfg.hold, "hold", 15*time.Minute,
		"how long to stay alive after reporting, so the pod stays Running")
	flag.Parse()

	encoded, err := json.Marshal(probe(cfg))
	if err != nil {
		// Nothing useful can be reported if the report itself cannot be
		// encoded, so this is the one path that exits non-zero.
		fmt.Fprintf(os.Stderr, "credprobe: encoding the report: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("%s%s\n", report.Prefix, encoded)

	// The probe never exits on a failed check: the suite is the judge, and a
	// pod that stays Running lets it assert on the pod phase and read the log
	// without racing a container that has already terminated. Cleanup is the
	// suite's, via the pod deletion its DeferCleanup registers - which arrives
	// here as SIGTERM.
	hold(cfg.hold)
}

// hold blocks until the deadline passes or the container is asked to stop.
func hold(d time.Duration) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-stop:
	case <-timer.C:
	}
}
