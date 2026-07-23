#!/usr/bin/env bash
# install-external-skills.sh — pull a vetted, MIT-licensed bug-bounty skill pack into
# vendor/, copying ONLY markdown (no payloads/binaries/executables). Attribution + LICENSE
# are preserved. See EXTERNAL-SKILLS.md for the catalog and the legality bar.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/vendor"

# name -> "git_url|markdown_subdirs(space-sep)"
declare -A PACKS=(
  ["claude-bug-bounty"]="https://github.com/shuvonsec/claude-bug-bounty.git|skills rules"
  ["awesome-skills-security"]="https://github.com/Eyadkelleh/awesome-skills-security.git|skills"
  ["claude-bughunter"]="https://github.com/elementalsouls/Claude-BugHunter.git|skills"
)

usage() {
  echo "Usage: $0 <pack-name>"
  echo "Available vetted packs (all MIT, markdown only):"
  for k in "${!PACKS[@]}"; do echo "  - $k"; done
  echo "See EXTERNAL-SKILLS.md for details. Only permissively-licensed repos are listed here."
}

[ $# -eq 1 ] || { usage; exit 1; }
PACK="$1"
[ -n "${PACKS[$PACK]:-}" ] || { echo "[!] Unknown pack: $PACK"; usage; exit 1; }

URL="${PACKS[$PACK]%%|*}"
SUBDIRS="${PACKS[$PACK]##*|}"
DEST="$VENDOR_DIR/$PACK"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[+] Cloning $URL (shallow)..."
git clone --depth 1 "$URL" "$TMP/src" >/dev/null 2>&1

mkdir -p "$DEST"
[ -f "$TMP/src/LICENSE" ] && cp "$TMP/src/LICENSE" "$DEST/LICENSE"
for d in $SUBDIRS; do
  [ -d "$TMP/src/$d" ] || continue
  echo "[+] Importing markdown from $d/ ..."
  rsync -am --include='*/' --include='*.md' --exclude='*' "$TMP/src/$d/" "$DEST/$d/"
done
echo "[✓] $PACK imported into vendor/$PACK (markdown only). Review before use."
echo "    Reminder: update vendor/SOURCES.md with attribution."
