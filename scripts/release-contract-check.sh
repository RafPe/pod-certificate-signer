#!/bin/sh
set -eu

fail() {
	printf '%s\n' "release-contract-check: $*" >&2
	exit 1
}

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$root"

for file in \
	.github/workflows/pr-release-metadata.yml \
	.github/workflows/prepare-release.yml \
	.github/workflows/release.yml \
	docs/releasing.md
do
	[ -f "$file" ] || fail "missing $file"
done

grep -q '^  workflow_dispatch:' .github/workflows/prepare-release.yml ||
	fail "Prepare Release must be manually dispatched"
grep -q 'group: prepare-release' .github/workflows/prepare-release.yml ||
	fail "Prepare Release must be serialized"
grep -q 'release/next' .github/workflows/prepare-release.yml ||
	fail "Prepare Release must own release/next"
grep -q 'autorelease: pending' .github/workflows/prepare-release.yml ||
	fail "release PR must carry autorelease: pending"

grep -q "head.ref == 'release/next'" .github/workflows/release.yml ||
	fail "Release must only accept the generated release branch"
grep -q "contains(github.event.pull_request.labels.*.name, 'autorelease: pending')" .github/workflows/release.yml ||
	fail "Release must require the automation label"
grep -q '^  group: release' .github/workflows/release.yml ||
	fail "Release must be serialized"
grep -q 'uses: ./.github/workflows/test-e2e.yml' .github/workflows/release.yml ||
	fail "Release must run the reusable E2E workflow before publishing"
grep -q 'git tag -a' .github/workflows/release.yml ||
	fail "Release must create an annotated tag only after verification"

grep -q 'exactly one' .github/workflows/pr-release-metadata.yml ||
	fail "PR metadata must enforce exactly one release label"
grep -q '.changes/unreleased' .github/workflows/pr-release-metadata.yml ||
	fail "PR metadata must enforce changelog fragments"

grep -q 'Ordinary pull requests never publish' docs/releasing.md ||
	fail "maintainer docs must state that ordinary PRs do not publish"
grep -q 'Prepare Release' README.md ||
	fail "README must describe the explicit prepare step"

printf '%s\n' 'release-contract-check: ok'
