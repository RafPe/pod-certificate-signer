---
status: proposed
date: 2026-08-21
decision-makers: RafPe
---

# Shard the nightly e2e tier by cost, and make every nightly spec name its shard

## Context and Problem Statement

The nightly e2e tier is one job. `test-e2e-nightly.yml` runs
`make test-e2e-nightly`, which is `make test-e2e` with `E2E_LABEL_FILTER`
emptied, so a single Ginkgo process runs every spec serially in declaration
order. The last green scheduled run (`32445553984`, 2026-08-21) took **44m07**
wall clock for 91 specs.

That number is now wrong in the direction that matters. Three things have
changed under it.

**The suite grew 15% after that run was measured.** `ha_test.go` (#112) merged
at 11:49 on 2026-08-21, after the 04:03 cron. The tree today dry-runs **105
specs, 27 of them `nightly`** — up from 91 and 13. The 14 new HA specs include a
rolling upgrade, a PodDisruptionBudget probe and a leader failover bounded by
`haLeaderHandoffTimeout` (90s), none of which is cheap.

**Those 14 specs have never executed in CI.** The only nightly run on their
branch (`32160019281`) failed in `Unusable replacement material` at
`ca_lifecycle_test.go:513` after 26 minutes, and Ginkgo skipped the remaining 40
specs — "Spec skipped because an earlier spec in an ordered container failed."
They then merged after the cron. A single ordered container means one failure
three-quarters of the way in discards every result behind it, and the specs most
likely to be discarded are the ones declared last, which is where new work
lands.

**The cost is concentrated, not spread.** Summing Ginkgo's per-spec durations
from that run:

| Context | Specs | Time |
|---|---|---|
| `CA lifecycle > Unusable replacement material` | 5 | **12m00** |
| `CA lifecycle > ClusterTrustBundle drift` | 2 | 3m54 |
| `Interoperability with a real TLS workload` | 4 | 0m24 |
| `CA lifecycle > Previous-CA retention` | 1 | 0m23 |
| `CA lifecycle > Controller restart` | 1 | 0m02 |
| **`!nightly` (the per-PR tier)** | 78 | **16m39** |

Two facts fall out. `Unusable replacement material` alone is 72% of nightly-only
time — four table entries each writing unusable material, waiting out a kubelet
mounted-secret refresh, and restoring last-good material. And the `!nightly`
tier, at 16m39, is larger than everything nightly-only combined (16m42 including
the not-yet-measured HA specs, which are excluded from both figures because
they have no CI timing).

The obvious axis — one job per Helm install profile — was measured and
rejected before this record was written. The five profile containers total
**4m15**, and none of the 27 nightly specs lives inside one. Sharding there
would parallelize four minutes while the shard carrying `CA lifecycle` stayed at
forty. The runtime is not on that axis.

## Decision

Split the nightly workflow into a **matrix of three shards, selected by
colon-namespaced Ginkgo labels**, and add a guard that fails when a nightly spec
belongs to no shard.

Every `nightly` container gains a second label naming its shard. Ginkgo has
supported `namespace:value` labels since v2 — `ValidateAndCleanupLabel`
(`types/label_filter.go:565-583`) rejects `&|!,()/` and a leading colon, and
explicitly permits an interior one — so this reuses the `<area>:<detail>`
convention #123 established for job display names rather than inventing a second
scheme.

| Shard | Contents | Filter | Est. wall clock |
|---|---|---|---|
| `ca-slow` | `Unusable replacement material` | `!nightly \|\| shard:ca-slow` | ~33m |
| `ca-rest` | `Controller restart`, `Previous-CA retention`, `ClusterTrustBundle drift`, `Interoperability` | `shard:ca-rest` | ~14m |
| `ha` | `High availability` | `shard:ha` | unmeasured; budget 45m |

Verified against the current tree by dry run: `shard:ca-slow` selects 5,
`shard:ca-rest` 8, `shard:ha` 14. **5 + 8 + 14 = 27**, the full nightly set,
with no spec in two shards.

### Why `ca-slow` carries the whole per-PR tier and the others do not

This is the load-bearing asymmetry, and it is what makes the split cheap enough
to be worth doing.

`Previous-CA retention` cannot stand alone. It opens with

```go
Expect(caB).NotTo(BeNil(),
    "the window this spec asserts on is built by the rotations above; run the container whole")
```

(`ca_lifecycle_test.go:395-397`) and then asserts the published bundle is
exactly `[D, B, C]` after rotating A → B → C → D. `caB` is created by
`rotates the issuing CA without breaking transitional trust` — a **`!nightly`**
spec. `Controller restart` and `Unusable replacement material` are looser: they
call `currentCA()`, which needs *a* current CA, not specifically `caB`.

So one shard must run the non-nightly CA-lifecycle specs to have a valid
history, and running the `!nightly` tier is how it gets one **without editing a
single test file.** `ca-slow` draws that duty because it is the shard whose own
work is longest; adding 16m39 to a 12m shard yields ~33m, while adding it to
`ca-rest` would have made that shard the critical path for nothing.

`ca-rest` and `ha` filter on their shard alone. Both are self-sufficient:
`CA lifecycle`'s `BeforeAll` rotates to `caA` unconditionally
(`ca_lifecycle_test.go:204-206`), and `High availability` reinstalls at
`replicaCount=2` in its own `BeforeAll` (`ha_test.go:162-164`) and manages
`haRotatedCA`/`haPreRotationCA` internally.

**No test file changes except adding labels.** That is the point of this shape.
The dependency comments in `ca_lifecycle_test.go` and `e2e_test.go` document
ordering that took real work to get right; a design requiring each context to
rebuild its own CA history would have to relitigate all of it.

### The guard

A shard partition fails silently in a way a green matrix does not reveal: give a
new nightly container no shard label, and it runs in **no job** while every
shard reports success. That is the failure mode `check-e2e-partition` already
exists to prevent for the two-tier split, and it does not currently cover this.

`-ginkgo.fail-on-empty` cannot express it, because here **empty is the passing
condition**. The guard dry-runs the complement and asserts it selects nothing:

```
nightly && !(shard:ca-slow || shard:ca-rest || shard:ha)
```

Verified in both directions on the current tree. With every nightly container
labelled it reports `Ran 0 of 105 Specs` and the guard passes. Removing
`shard:ha` from `ha_test.go` to simulate a forgotten label makes it report
`Ran 14 of 105 Specs` and the guard fails naming the count. It extends
`check-e2e-partition`, which is already a prerequisite of `test-e2e-nightly`
and so cannot be skipped by editing the workflow alone.

The shard list lives in exactly one place, `E2E_SHARDS` in the Makefile, which
both the guard and the workflow matrix read. A shard added to the matrix but not
the guard would otherwise be the same hole one level up.

### Job naming

Three jobs on the `<area>:<detail>` scheme from #123 and #127:
`test:e2e-ca-slow`, `test:e2e-ca-rest`, `test:e2e-ha`. The current name
`test:e2e-full` retires with the job it names.

This is a visible break for anyone with a required status check or a branch
protection rule on `test:e2e-full`. It is also most of the value: a nightly
failure currently reads as one red check on a 44-minute log, and afterwards it
names the area that broke. `test:e2e` (per-PR) and `release:e2e` are untouched.

`fail-fast: false` on the matrix. A shard failing must not cancel the others —
that is the discarded-results problem this record opens with, reintroduced at
the job level.

## Consequences

**Positive.** Nightly wall clock drops from **44m to ~33m**, bounded by
`ca-slow`. A failure names its shard. A shard failing no longer discards the
other two shards' results, so the HA specs — which have never run — stop being
hostage to a CA-lifecycle failure declared ahead of them.

**Negative, and stated plainly: the speedup is modest, and it is capped by
design.** `ca-slow` runs the entire per-PR tier plus the single most expensive
nightly context, so the floor is 16m39 + 12m + ~5m setup. Sharding cannot go
below that without either splitting `Unusable replacement material`'s four table
entries or making `Previous-CA retention` self-sufficient — the second of which
this record explicitly declines to do. **If the goal is a 20-minute nightly,
this decision does not reach it, and the next lever is the `!nightly` tier
rather than more shards.**

Aggregate runner minutes roughly double, because setup (~5m: checkout, Go, kind,
vet+lint, image build and load, cert-manager) is paid three times and the
`!nightly` tier is executed twice — once in `test:e2e` on the PR and again
inside `ca-slow`. On a public repository these minutes are free; on a private
one this trade would need restating.

**Neutral.** No change to issuance, the identity model, the trust boundary, or
any chart resource. Nothing outside `.github/workflows/`, the Makefile and
Ginkgo labels moves. The two-tier `nightly` partition and its existing guard are
unchanged; shards subdivide the nightly half.

## Implementation Plan

Sequenced so each step is independently reviewable and revertible.

1. **Labels.** Add the shard label to each of the six nightly containers. Six
   one-line edits, no logic. Verify by dry run that the three shards select
   5 / 8 / 14 and that the complement selects 0.
2. **Makefile.** Add `E2E_SHARDS`, a `test-e2e-shard` target taking `SHARD`, and
   the complement assertion in `check-e2e-partition`. Verify the guard fails
   when a label is removed.
3. **Workflow.** Convert `test-e2e-nightly.yml` to a `strategy.matrix` over
   `E2E_SHARDS` with `fail-fast: false` and per-shard `timeout-minutes`.
4. **Measure `ha`.** Its budget is a guess — the specs have never run in CI.
   Run the workflow on the PR via the `run-nightly` label and set the timeout
   from the observed number.

### Verification

The complement dry run is the durable check and runs in `check-e2e-partition`,
which `test-e2e-nightly` already depends on. Beyond that, the PR itself is
verification: label it `run-nightly` and all three shards execute, which also
produces the first CI evidence for the HA specs.

## Alternatives Considered

**A matrix over the five Helm install profiles.** Rejected on measurement. The
profile containers are 4m15 of a 44m run and hold none of the 27 nightly specs;
the shard carrying `CA lifecycle` would still be ~40m. It would improve
diagnosability, but this record buys that as a side effect of an axis that also
carries the runtime.

**One shard per nightly context (five or six jobs).** Rejected. `Controller
restart` is 2 seconds and `Previous-CA retention` 23; giving each a job spends
5m of setup on 25s of work, and `Previous-CA retention` would additionally need
its own `!nightly` run for `caB`. Three shards is where the marginal job stops
paying.

**Making each nightly context self-sufficient, then sharding freely.** This is
the only path below the ~33m floor, and it is deferred rather than dismissed.
`Previous-CA retention` would perform its own A → B rotation instead of
inheriting one — roughly 90 seconds of kubelet propagation, plus edits to
`ca_lifecycle_test.go`'s carefully reasoned ordering. Worth doing when the floor
is the binding constraint. It is not yet: the `!nightly` tier is.

**Pre-building the images in a setup job and passing them as artifacts.**
Rejected on measurement. Build and load of both images is 2m03; a setup job adds
~2m30 serialized ahead of every shard, and each shard still pays to download and
`kind load image-archive`. It also requires an opt-out for `BeforeSuite`'s
`make docker-build` (`e2e_suite_test.go:88-106`), creating a way for CI to test
a stale image. Neutral-to-negative on the critical path for a new correctness
hazard.

**Ginkgo's own `--procs` parallelism.** Rejected, and it is not close.
`BeforeSuite` fails the run outright when `ParallelTotal != 1`
(`e2e_suite_test.go:81-86`) because `installProfile` upgrades the release in
place and the CA specs rotate a cluster-wide secret. Sharding across jobs gives
each shard its own kind cluster, which is what makes it safe where `--procs` is
not.

**Doing nothing.** The status quo is a 44-minute serial job that grew 15% in one
day, in which one failure discards every result behind it, and whose newest 14
specs have never produced a CI result.

## More Information

- Measurements: run `32445553984` (2026-08-21, green, 91 specs, 44m07) for
  per-spec timings; run `32160019281` (2026-08-18, red) for the discarded-results
  behaviour. Spec counts and all filter selections are from `-ginkgo.dry-run`
  against `ce23560`.
- Job naming follows #123 and #127.
- Related: [[0005-bounded-metrics-surface]], whose e2e migration step also
  touches this suite's coupling to controller logs.
