# pod-certificate-signer article series: contract for every article

This file is the contract for each article in the series. Each author follows
it, a person or an agent. If a rule conflicts with a fact, correct the rule in
a pull request. [README.md](README.md) gives the workflow.

## Reader and purpose

The reader is a platform engineer who operates Kubernetes clusters. The reader
knows Kubernetes and TLS. The reader does not know this project.

Each article is an operator how-to tied to release 3.1.0. The reader runs the
commands and sees the same result. It is not a design essay and not a product
announcement.

## Fixed names (use these in every article)

| Thing | Value |
| --- | --- |
| Project | `pod-certificate-signer` |
| Repository | `https://github.com/RafPe/pod-certificate-signer` |
| Release | 3.1.0 (2026-11-11) |
| Kubernetes | 1.37+ (write `Kubernetes 1.37+` for the supported range, and `1.37.0` only for the test cluster) |
| Signer name | `example.org/signer` |
| Helm release | `pod-certificate-signer` |
| Namespace | `pcs-system` |
| CA Secret | `podcertificate-signer-ca` |
| Example pod | `pcs-example-workload` (`examples/workload-pod.yaml`) |
| Trust bundle | `example.org:signer:bundle` |
| Chart | `oci://ghcr.io/rafpe/charts/pod-certificate-signer --version 3.1.0` |
| Author byline | Rafal Pieniazek |

Use the repo terms and one name per thing: PodCertificateRequest,
ClusterTrustBundle, signer name, credential bundle, verified identity, kubelet,
kube-apiserver.

## Facts that earlier drafts had wrong (do not repeat the error)

- Kubelet creates the PodCertificateRequest. The kube-apiserver verifies its
  identity fields.
- The API writes the denial reason `InvalidUnverifiedUserAnnotations`.
- The release workflow signs the image with cosign. It does not sign the chart.
- The CA watcher runs on every replica. The reconciler and the
  ClusterTrustBundle publisher run on the leader only.
- The signer denies an explicit `duration` above the maximum. It reduces only
  the default.

## Sources and evidence

1. The code is the source of truth. Then the docs on `main`. Use CodeGraph
   first: `codegraph explore "<symbols or question>"` from the repo root.
2. Each factual claim in the article has one row in `facts.md`: the claim, the
   source file and line (or the evidence file), and a verbatim quote.
3. Each command in the article ran on a real cluster. Save the raw command and
   its output under `evidence/`. Quote output from the evidence file only. Do
   not write output from memory.
4. Soften a sentence to what the source supports. Keep every hedge and number.
   If you cannot verify a claim, remove it or state the limit in the article.
5. Links go to the repository docs on `main`, for example
   `https://github.com/RafPe/pod-certificate-signer/blob/main/docs/operations.md#rotating-the-signing-ca`.
   Check that each anchor exists.

## Test cluster rules (shared machine)

- Create one Kind cluster with a unique name `pcs-art-NN` and a private
  kubeconfig: `kind create cluster --name pcs-art-NN --config kind/kind-config.yaml --kubeconfig <dir>/kubeconfig`.
  Export `KUBECONFIG` to that file in every command. Never touch
  `~/.kube/config`. Never touch another Kind cluster.
- Generate a test CA with `go run ./hack/dev-ca -dir <dir> -days 30 -cn <name>`.
  It writes `tls.crt` and `tls.key`. Copy them to `ca.pem` and `ca-key.pem`.
  Keep the directory outside the repo, in your scratch directory.
- Install the published chart 3.1.0 with default flags, as the docs say.
- Delete the cluster when your evidence is complete:
  `kind delete cluster --name pcs-art-NN --kubeconfig <dir>/kubeconfig`.
- Never put a private key in `evidence/` or in the article.

## Files you write

All files go in `articles/NN-slug/`. One pull request adds one article.

| File | Content |
| --- | --- |
| `article.md` | The article. 1,300 to 1,600 words of prose, not counting code. |
| `post.md` | The teaser post. 100 to 120 words, 4 or 5 short paragraphs. |
| `facts.md` | The claim ledger, plus "Checks completed" and "Not verified". |
| `evidence/` | Raw commands and outputs, one file per step. |
| `assets/BRIEF.md` | The visual brief for the images and the HTML. |

Write the text first. Then make the images and the HTML from `assets/BRIEF.md`
with the toolkit in [`_shared/`](_shared/README.md).

## Article structure

1. One H1 title that states the topic.
2. An image line for the cover directly after the H1: `![cover](assets/cover.jpg)`.
3. Opening: a concrete situation or puzzle in 2 to 4 short paragraphs.
4. A scope paragraph: what the article does. Then one bold line:
   `**This article covers pod-certificate-signer 3.1.0** on Kubernetes 1.37+.`
5. Five to nine H2 sections in sentence case. No H3.
6. Each fenced code block has an image line directly above it for its code
   card, for example `![Helm install](assets/install.png)`. The fenced block
   stays for copying. Languages: `sh`, `yaml`, `text`, `promql`.
   Code card limits, because each card is an image on LinkedIn:
   - At most 9 code cards in one article. Put a command and its output in one
     block when both are short. Describe a minor output in prose.
   - No line longer than 90 characters. Break a long command with `\`. For
     long output, show an excerpt: cut the line and mark the cut with `...`.
     The sentence before the block says that it is an excerpt. The full
     output stays in `evidence/`.
   - At most 25 lines in one block.
   - A block that shows only commands uses the language `sh` and no prompt.
     A block that shows commands with their output uses the language `text`,
     and each command line starts with `$ `. Do not mix commands and output
     in an `sh` block.
   - Do not write an image line for a table. The render tool makes an image
     of each Markdown table.
   - A YAML block is valid YAML by itself. To show a change, show the complete
     small object or the complete changed key with its parents.
7. Diagrams: an image line where the diagram belongs, for example
   `![Request flow](assets/flow.png)`.
8. The last section tells the reader how to verify the result. No sales text.
   End with the repository URL and one link to the next relevant docs page.
9. Tables: at most two, at most three columns each.
10. No callout blocks. Use one bold sentence for a key idea.

## Voice (ASD-STE100)

- Imperative and "you". No "I" or "we".
- Active voice. One instruction per sentence. Instructions 20 words or fewer.
  Descriptions 25 words or fewer. No semicolons. No phrasal verbs. No
  nominalization. Simple tenses, but keep a hedge or a compound tense that
  carries meaning.
- No marketing adjectives: seamless, robust, powerful, simple, easy,
  effortless, cutting-edge, blazing, game-changing, revolutionary, elegant.
- Define a term on first use.
- State limits: what the article does not prove.
- The post has no question mark, no hashtag and no emoji. It ends with two
  lines: `Article: <link>` and `Repo: https://github.com/RafPe/pod-certificate-signer`.
- Linter: `ste-lint.py article.md post.md`. The script is part of the
  `asd-ste100` agent skill. It is not in this repository.
  Target: zero hard violations. Report each finding that you keep and why.

## Visual brief (`assets/BRIEF.md`)

Write it in strict ASD-STE100, because an agent can read it. It contains:

- **Cover:** the eyebrow line, the three-line title (first line is the word
  that renders in blue), the subtitle, three pill texts, and one prop that the
  mascot holds. Give exact text.
- **Diagrams:** for each one, the file name, the title, each box with its exact
  label, each arrow with its exact label and direction, and the reading order.
  Each diagram shows one idea. Maximum 8 boxes.
- **Code cards:** for each fenced block, the file name, the header label and
  the language. The card text is the fenced block, byte for byte.
- **Reused images:** repository images that must stay unmodified, with their
  path and a caption.
- **Alt text** for each image.

## Series map (for cross-references)

| # | Slug | Topic |
| --- | --- | --- |
| 01 | `01-per-pod-certificates` | Install, request a certificate, read it |
| 02 | `02-verified-identity` | The verified-identity allowlist and denials |
| 03 | `03-ca-rotation` | CA rotation, the trust bundle and the kubelet delay |
| 04 | `04-metrics-and-dashboard` | Metrics, alerts and the dashboard |

An article can refer to an earlier one by its title. Do not write a URL for
another article. Reserve for later articles: mTLS between two services,
leader handover, testing.

## Done report

A pull request for an article states these items:

- the word counts
- the linter result
- the list under "Not verified"
- each place where the docs or the code disagreed with this contract
