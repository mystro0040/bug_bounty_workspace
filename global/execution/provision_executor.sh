#!/usr/bin/env bash
# provision_executor.sh — install the recon toolchain on a remote executor.
#
# WHY THIS EXISTS
#   The executor is a separate machine with its own toolchain. A tool installed at home
#   is NOT present there, and remote dispatch correctly refuses to run what the box does
#   not have. Today the box has subfinder/dnsx/httpx and nothing else, so most work
#   cannot be offloaded. This closes that gap.
#
# SAFETY (§2F-TOOLS — read before changing anything here)
#   * Official upstream releases ONLY (ProjectDiscovery / tomnomnom / GitHub releases).
#   * NEVER pipe a download into a shell. Every artifact is fetched, hashed, then run.
#   * SHA-256 of every artifact is recorded to an install log for provenance.
#   * Installs to ~/.local/bin (user space). No sudo, nothing system-wide.
#   * Nothing here touches scope or authorization. It installs binaries, full stop.
#
# USAGE (from the operator's machine)
#   scp -i ~/.ssh/recon_ed25519 provision_executor.sh recon@<HOST>:~/
#   ssh -i ~/.ssh/recon_ed25519 recon@<HOST> 'bash ~/provision_executor.sh'
#   ssh -i ~/.ssh/recon_ed25519 recon@<HOST> 'bash ~/provision_executor.sh --verify'
#
set -uo pipefail

BIN="$HOME/.local/bin"
LOG="$HOME/.config/offsec/tool-provenance.log"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$BIN" "$(dirname "$LOG")"

# Tools the bug-bounty workflow actually uses, minus anything that is not
# offload-relevant. Deliberately EXCLUDED: masscan (mass scanning conflicts with the
# rate discipline), any brute-force or DoS tooling, anything requiring root.
# interactsh-client is the OAST callback listener. Without it, BLIND vulnerability classes
# cannot be proven at all — you can send a payload and see the direct response, but you cannot
# observe an out-of-band callback, so blind SSRF, blind XXE and blind command injection stay
# UNTESTED rather than clean. A class parked for missing tooling is a hole in coverage that
# no amount of retesting the other classes fills.
#
# It talks only to the interactsh server (oast.pro and friends), never to the target, so it
# generates no traffic against an engagement asset.
PD_TOOLS="subfinder dnsx httpx nuclei katana naabu interactsh-client"   # ProjectDiscovery
GO_TOOLS="github.com/tomnomnom/waybackurls@latest
github.com/lc/gau/v2/cmd/gau@latest
github.com/tomnomnom/assetfinder@latest
github.com/ffuf/ffuf/v2@latest
github.com/OJ/gobuster/v3@latest"

log()  { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" | tee -a "$LOG"; }
have() { command -v "$1" >/dev/null 2>&1; }

record_hash() {   # record_hash <path> <source>
  local h; h="$(sha256sum "$1" | cut -d' ' -f1)"
  log "INSTALLED $(basename "$1") sha256=$h source=$2"
}

# --------------------------------------------------------------------- verify mode
if [ "${1:-}" = "--verify" ]; then
  echo "=== executor toolchain ==="
  for t in subfinder dnsx httpx nuclei katana naabu ffuf gobuster gau waybackurls assetfinder go; do
    printf '%-14s %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo MISSING)"
  done
  echo
  echo "=== provenance log (last 20) ==="
  tail -20 "$LOG" 2>/dev/null || echo "(none)"
  exit 0
fi

log "=== provisioning start on $(hostname) ==="

# --------------------------------------------------------------------- prerequisites
if ! have go; then
  log "installing golang (needed to build several tools from source)"
  sudo apt-get update -qq && sudo apt-get install -y -qq golang-go >/dev/null 2>&1 \
    && log "go installed: $(go version 2>/dev/null)" \
    || log "WARN go install failed — go-based tools will be skipped"
fi
have unzip || sudo apt-get install -y -qq unzip >/dev/null 2>&1

# --------------------------------------------------------------------- ProjectDiscovery
# Official GitHub releases. Fetch → verify checksum → unzip → install. Never piped.
install_pd() {
  local tool="$1" ver url zip sums expected actual repo
  # The REPO and the BINARY are not always the same name. interactsh-client ships from the
  # `interactsh` repo, so deriving the repo from the binary name 404s the releases API and the
  # tool is silently skipped with a WARN — which reads like an upstream hiccup rather than
  # "this tool will never install". Map the exceptions explicitly.
  case "$tool" in
    interactsh-client|interactsh-server) repo="interactsh" ;;
    *)                                   repo="$tool" ;;
  esac
  ver="$(curl -fsSL "https://api.github.com/repos/projectdiscovery/${repo}/releases/latest" \
        | grep -m1 '"tag_name"' | cut -d'"' -f4 | sed 's/^v//')"
  [ -n "$ver" ] || { log "WARN could not resolve latest version for $tool (repo: $repo)"; return 1; }
  zip="${tool}_${ver}_linux_amd64.zip"
  url="https://github.com/projectdiscovery/${repo}/releases/download/v${ver}/${zip}"

  curl -fsSL -o "$TMP/$zip" "$url" || { log "WARN download failed: $tool"; return 1; }

  # Upstream publishes a checksums file — verify against it rather than trusting the download.
  sums="${tool}_${ver}_checksums.txt"
  if curl -fsSL -o "$TMP/$sums" \
       "https://github.com/projectdiscovery/${repo}/releases/download/v${ver}/${sums}" 2>/dev/null; then
    expected="$(grep " $zip\$" "$TMP/$sums" | cut -d' ' -f1)"
    actual="$(sha256sum "$TMP/$zip" | cut -d' ' -f1)"
    if [ -n "$expected" ] && [ "$expected" != "$actual" ]; then
      log "HARD STOP checksum MISMATCH for $tool ($expected != $actual) — discarding"
      rm -f "$TMP/$zip"; return 1
    fi
    log "checksum verified upstream for $tool v$ver"
  else
    log "NOTE no upstream checksums file for $tool v$ver — recording our own hash only"
  fi

  unzip -o -q "$TMP/$zip" -d "$TMP/$tool" && install -m 0755 "$TMP/$tool/$tool" "$BIN/$tool" \
    && record_hash "$BIN/$tool" "$url"
}

for t in $PD_TOOLS; do
  if have "$t"; then log "SKIP $t (already present: $(command -v "$t"))"; else install_pd "$t"; fi
done

# --------------------------------------------------------------------- go-install tools
if have go; then
  export GOBIN="$BIN"
  for pkg in $GO_TOOLS; do
    # Strip a trailing major-version segment before taking the basename. Go module paths carry
    # /v2, /v3 etc, so a naive basename yields "v2" — the build then succeeds, the binary lands
    # under its real name, and the script reports "WARN build failed" because it looked for a
    # binary called v2. That happened to ffuf and gobuster on 2026-07-26: both installed fine and
    # both were reported as failures. A false failure is less dangerous than a false success, but
    # it still teaches you to ignore the log.
    base="${pkg%@*}"
    case "$(basename "$base")" in
      v[0-9]|v[0-9][0-9]) base="$(dirname "$base")" ;;
    esac
    name="$(basename "$base")"
    if have "$name"; then log "SKIP $name (already present)"; continue; fi
    log "building $name from $pkg"
    if go install "$pkg" >/dev/null 2>&1 && [ -x "$BIN/$name" ]; then
      record_hash "$BIN/$name" "$pkg"
    else
      log "WARN build failed: $pkg"
    fi
  done
fi

# --------------------------------------------------------------------- PATH
if ! grep -q '.local/bin' "$HOME/.bashrc" 2>/dev/null; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
  log "added ~/.local/bin to PATH in .bashrc"
fi

# --------------------------------------------------------------------- resolvers
# Bulk DNS must never hit the box's default resolver (§2F-DNS).
RES="$HOME/.config/offsec/resolvers.txt"
if [ ! -s "$RES" ]; then
  printf '1.1.1.1\n8.8.8.8\n9.9.9.9\n8.8.4.4\n1.0.0.1\n149.112.112.112\n' > "$RES"
  log "wrote default resolver list to $RES"
fi

log "=== provisioning complete ==="
echo
bash "$0" --verify
