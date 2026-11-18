# Evidence: article 01

Cluster: Kind `pcs-art-01`, Kubernetes v1.37.0, one control-plane node, 2026-11-16 (UTC).
Client: kubectl v1.35.0, helm v4.0.1, OpenSSL 4.1.0, kind v0.33.0.
Each entry: `# date:` (UTC), the command after `$`, the output (stdout and stderr), `# exit code:`.
Commands that use `ca.pem`, `ca-key.pem` and `wrong-signer-pod.yaml` ran in a scratch directory outside the repository. The CA key is not in this directory.

| File | Step |
| --- | --- |
| `00-cluster.txt` | Cluster and API version |
| `01-ca-secret.txt` | Test CA fields, namespace, CA Secret |
| `02-install.txt` | Helm install 3.1.0, rollout, ClusterTrustBundle, chart values |
| `03-workload.txt` | Apply `examples/workload-pod.yaml`, wait |
| `04-pcr.txt` | Request, conditions, managed fields, signer log |
| `05-files.txt` | Files in the container, PEM block headers |
| `06-openssl.txt` | Certificate fields, chain verify, `openssl version` |
| `07-wrong-signer.txt` | Pod with signer name `example.org/other-signer` |
| `08-cleanup.txt` | Delete both pods |
| `09-verify.txt` | Verify section, first run |
| `10-busybox-openssl.txt` | The busybox image has no `openssl` |
| `11-wrong-signer-rerun.txt` | Wrong-signer pod, second run |
| `12-cards.txt` | Example pod with the commands that the article shows |
| `13-wrong-signer-cards.txt` | Wrong-signer pod with the commands that the article shows |
| `14-verify-final.txt` | Verify section, as the article shows it |
| `wrong-signer-pod.yaml` | Manifest of the wrong-signer pod |

## Edits after capture

- Files `00` to `09`: the recorder printed the `$` line with zsh `echo`, which changed `\t` and `\n` in jsonpath strings into a tab and a line break. A `perl` step restored the literal `{"\t"}` and `{"\n"}` in those `$` lines. The commands ran with the literal escapes. Files `10` and later use `printf` and need no edit.
- `08-cleanup.txt`: a `sed` step removed the absolute scratch path in front of `wrong-signer-pod.yaml`.
- No output line was changed.
