#!/usr/bin/env bash
# Regenerates assets/social-card.png (the GitHub social preview image) by
# rendering hack/social-card/social-card.html with headless Chrome.
#
# Usage: hack/social-card/generate.sh
#
# GitHub expects the social preview to be 1280x640 and under 1 MB. After
# regenerating, upload the image manually via GitHub repo Settings ->
# General -> Social preview (there is no API for this step).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "${SCRIPT_DIR}" rev-parse --show-toplevel)"
OUTPUT="${REPO_ROOT}/assets/social-card.png"

CHROME_BIN="${CHROME_BIN:-}"
if [[ -z "${CHROME_BIN}" ]]; then
  for candidate in \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium" \
    google-chrome-stable google-chrome chromium chromium-browser; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      CHROME_BIN="${candidate}"
      break
    fi
  done
fi
if [[ -z "${CHROME_BIN}" ]]; then
  echo "error: no Chrome/Chromium binary found; set CHROME_BIN" >&2
  exit 1
fi

"${CHROME_BIN}" \
  --headless \
  --disable-gpu \
  --no-sandbox \
  --hide-scrollbars \
  --force-device-scale-factor=1 \
  --window-size=1280,640 \
  --screenshot="${OUTPUT}" \
  "file://${SCRIPT_DIR}/social-card.html"

SIZE_BYTES=$(wc -c < "${OUTPUT}" | tr -d ' ')
if (( SIZE_BYTES >= 1048576 )); then
  echo "error: ${OUTPUT} is ${SIZE_BYTES} bytes; GitHub caps social previews at 1 MB" >&2
  exit 1
fi
echo "wrote ${OUTPUT} (${SIZE_BYTES} bytes)"
