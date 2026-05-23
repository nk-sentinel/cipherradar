#!/usr/bin/env bash
# Local pre-tag smoke check for the release pipeline.
# Builds cradar for linux/amd64 (the dev host), assembles cradar-pkg and
# cradar-full-pkg the same way release.yml does, then verifies:
#   - every embedded binary actually executes (--version)
#   - every bundled doc file is present and non-empty
#   - the cradar-full archive is strictly larger than the slim archive
# Exits non-zero on any failure. Burn 0 GitHub minutes on a broken release —
# run this locally before pushing a v* tag.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
OS="linux"
ARCH="amd64"
OPENGREP_VERSION="v1.16.5"
YARAX_VERSION="v1.14.0"
OUT="/tmp/cradar-release-smoke"

echo "==> Smoke test for cradar ${VERSION} on ${OS}/${ARCH}"
rm -rf "$OUT" && mkdir -p "$OUT/dist"

echo "==> Build cradar"
(cd cli && go generate ./internal/rules >/dev/null \
       && go build -ldflags "-s -w \
            -X github.com/nk-sentinel/cipherradar/cli/internal/cmd.Version=${VERSION} \
            -X github.com/nk-sentinel/cipherradar/cli/internal/cmd.Commit=$(git rev-parse --short HEAD) \
            -X github.com/nk-sentinel/cipherradar/cli/internal/cmd.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
            -o "$OUT/dist/cradar" ./cmd/cradar)
"$OUT/dist/cradar" version

echo "==> Download OpenGrep"
mkdir -p "$OUT/dist/opengrep"
curl -fsSL --retry 3 -o "$OUT/dist/opengrep/opengrep-bin" \
  "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86"
chmod +x "$OUT/dist/opengrep/opengrep-bin"

echo "==> Download + extract YARA-X"
mkdir -p "$OUT/dist/yarax"
curl -fsSL --retry 3 -o "$OUT/yarax-archive.gz" \
  "https://github.com/VirusTotal/yara-x/releases/download/${YARAX_VERSION}/yara-x-${YARAX_VERSION}-x86_64-unknown-linux-gnu.gz"
(cd "$OUT/dist/yarax" && gunzip -c "$OUT/yarax-archive.gz" | tar -xf -)
YR_BIN="$(find "$OUT/dist/yarax" -type f \( -name 'yr' -o -name 'yr.exe' \) | head -1)"
[ -n "$YR_BIN" ] || { echo "FAIL: yr not found after extraction"; exit 1; }
mv "$YR_BIN" "$OUT/dist/yarax/yr-bin"
chmod +x "$OUT/dist/yarax/yr-bin"

echo "==> Sanity-exec bundled tools"
# Temporarily disable pipefail so SIGPIPE from `head` closing the pipe early
# doesn't fail an otherwise-healthy version probe.
set +o pipefail
"$OUT/dist/opengrep/opengrep-bin" --version 2>&1 | head -3
OG_EXIT=${PIPESTATUS[0]}
"$OUT/dist/yarax/yr-bin" --version 2>&1 | head -3
YR_EXIT=${PIPESTATUS[0]}
set -o pipefail
[ "$OG_EXIT" -eq 0 ] || { echo "FAIL: opengrep-bin does not execute (exit=$OG_EXIT)"; exit 1; }
[ "$YR_EXIT" -eq 0 ] || { echo "FAIL: yr-bin does not execute (exit=$YR_EXIT)"; exit 1; }

bundle_extras() {
  local pkg="$1"
  # LICENSE lives at cli/LICENSE — Apache 2.0 covers the CLI only. The repo
  # root deliberately has no LICENSE (other top-level dirs like backend/ and
  # frontend/ are licensed separately; see LICENSING.md).
  cp cli/LICENSE "$pkg/LICENSE"
  cp CHANGELOG.md "$pkg/"
  cp .github/release-README.md "$pkg/README.md"
  mkdir -p "$pkg/docs"
  cp -r docs/guides/cli/* "$pkg/docs/"
}

verify_archive_layout() {
  local pkg="$1" label="$2"
  echo "==> Verify $label layout"
  for f in cradar LICENSE CHANGELOG.md README.md docs/README.md docs/commands.md docs/output-formats.md docs/configuration.md docs/exit-codes.md docs/workflows.md; do
    [ -s "$pkg/$f" ] || { echo "FAIL: $label missing or empty: $f"; exit 1; }
  done
}

echo "==> Assemble cradar (lightweight)"
PKG="$OUT/dist/cradar-pkg"
mkdir -p "$PKG"
cp "$OUT/dist/cradar" "$PKG/cradar"
bundle_extras "$PKG"
verify_archive_layout "$PKG" "cradar (lite)"

echo "==> Assemble cradar-full"
PKG_FULL="$OUT/dist/cradar-full-pkg"
mkdir -p "$PKG_FULL"
cp "$OUT/dist/cradar" "$PKG_FULL/cradar"
cp "$OUT/dist/opengrep/opengrep-bin" "$PKG_FULL/opengrep"
cp "$OUT/dist/yarax/yr-bin" "$PKG_FULL/yr"
chmod +x "$PKG_FULL/opengrep" "$PKG_FULL/yr"
bundle_extras "$PKG_FULL"
verify_archive_layout "$PKG_FULL" "cradar-full"
# Full must also include opengrep + yr
for f in opengrep yr; do
  [ -x "$PKG_FULL/$f" ] || { echo "FAIL: cradar-full missing or non-exec: $f"; exit 1; }
done

echo "==> Pack archives"
(cd "$OUT/dist" && tar czf "cradar_${VERSION}_${OS}_${ARCH}.tar.gz" -C cradar-pkg .)
(cd "$OUT/dist" && tar czf "cradar-full_${VERSION}_${OS}_${ARCH}.tar.gz" -C cradar-full-pkg .)

SLIM_SIZE=$(stat -c%s "$OUT/dist/cradar_${VERSION}_${OS}_${ARCH}.tar.gz")
FULL_SIZE=$(stat -c%s "$OUT/dist/cradar-full_${VERSION}_${OS}_${ARCH}.tar.gz")
echo "Slim archive: $(numfmt --to=iec "$SLIM_SIZE")"
echo "Full archive: $(numfmt --to=iec "$FULL_SIZE")"
[ "$FULL_SIZE" -gt "$SLIM_SIZE" ] \
  || { echo "FAIL: full archive ($FULL_SIZE) is not larger than slim ($SLIM_SIZE)"; exit 1; }

echo ""
echo "OK — local smoke passed. Archives at:"
ls -lh "$OUT/dist/"cradar_*.tar.gz "$OUT/dist/"cradar-full_*.tar.gz
echo ""
echo "Safe to tag and push: git tag -a v${VERSION} -m ... && git push origin v${VERSION}"
