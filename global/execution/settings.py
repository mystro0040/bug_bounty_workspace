"""
CENTRAL EXECUTION SETTINGS — the one obvious place for global run toggles.
=========================================================================

Everything that controls HOW and WHERE tools run lives here, so there is a single
file to open when you want to change execution behaviour. Import it:

    from execution import settings as S
    cap = S.GLOBAL_MAX_RPS

or read it as data (it is plain module-level constants).

This is OPERATIONAL config the operator tunes — it is NOT part of an engagement's
scope-lock and can never widen scope. The scope-lock (per-engagement asset/binary
wall) and the enforce_scope hook are unaffected by anything in this file.

ISP-AGNOSTIC BY DESIGN: nothing here is tied to a specific ISP or provider. The
defaults are conservative enough to be safe on any residential line. If you know
your connection tolerates more, raise the number — but the default should never
need lowering for a new ISP.
"""

# =============================================================================
# 1. GLOBAL NETWORK / ISP RATE SAFETY
# =============================================================================
# The AGGREGATE ceiling across ALL running tools and ALL engagements combined.
# This is the fix for "two engagements each capped at 10 still summed to 60/s".
# The per-engagement limit below governs ONE engagement; this governs the whole box.
GLOBAL_RATE_LIMIT_ENABLED = True

# Total outbound requests/DNS per second, summed across everything running.
# Conservative residential-safe default. Not tied to any ISP. Raise only if you
# know your line handles it; you should never have to lower it for a new provider.
GLOBAL_MAX_RPS = 20

# Per-ENGAGEMENT default ceiling (one engagement, all its tools combined). A
# program's own stated limit ALWAYS overrides this, and a lower limit always wins.
# Mirrors DEFAULT_RATE_LIMIT in global/CLAUDE.md — keep them in step.
PER_ENGAGEMENT_MAX_RPS = 10

# --- ESCAPE HATCH: raw-local mode (run like before today, no global ISP cap) ---------
# The safe config above is the DEFAULT. This override lets you deliberately drop the
# GLOBAL ISP rate cap and run tools raw-local (each tool uses its own rate, as before
# today). Disabled by default. It CANNOT be triggered by accident: a stray True, a typo,
# or a bad merge will NOT enable it — it activates ONLY when RAW_LOCAL_ACK is set to the
# EXACT acknowledgement string below. When active it prints a loud banner.
#
# SCOPE OF THIS OVERRIDE — read carefully. It disables ONLY the global ISP rate cap.
# It does NOT, and the code will NOT let it, disable any of:
#   • the engagement scope-lock (asset/binary wall)      • the hard floor (no DoS/brute/OOS)
#   • the Anthropic-stays-direct rule (no VPN for Claude) • §2F-DNS/LOCAL/TOOLS/WEB safety
# Those are never "the ISP stuff" — they are non-negotiable and unaffected by this flag.
RAW_LOCAL_ACK = ""                                   # to enable, set EXACTLY to _RAW_LOCAL_MAGIC
_RAW_LOCAL_MAGIC = "YES-run-raw-local-drop-isp-cap"  # the only value that activates it


def raw_local_active():
    """True only if the operator set the exact acknowledgement string. Typo-proof."""
    return RAW_LOCAL_ACK.strip() == _RAW_LOCAL_MAGIC

# Default DNS-specific concurrency for the resumable enum wrapper (see §2F-DNS).
DNS_THREADS = 25
DNS_RATE_LIMIT = 20


# =============================================================================
# 2. WHERE TOOLS RUN  (local box vs a remote executor)
# =============================================================================
# This ONLY moves the security TOOLING. The orchestrator's connection to Anthropic
# is never affected by this setting and ALWAYS stays on this machine's direct
# connection. See ORCHESTRATOR_LOCATION below and the hard rule at the bottom.
#
#   "auto"   -> DEFAULT + intended steady state: run tools REMOTE as soon as a remote
#               executor is configured AND its vendor is cleared; otherwise fall back to
#               local. So once the VPS is set up, tools-through-VPS becomes the default
#               with no switch to flip. Until then (no VPS), it is local automatically.
#   "local"  -> force local (a deliberate manual override — run here like before)
#   "remote" -> force remote (fails if no usable executor is configured)
EXECUTE_MODE = "auto"


def resolve_mode():
    """Resolve "auto" to the concrete mode. Returns "remote" only when at least one
    REMOTE_EXECUTORS entry is fully configured AND its vendor is CLEARED (status=allowed);
    otherwise "local". Explicit "local"/"remote" are returned as-is."""
    if EXECUTE_MODE in ("local", "remote"):
        return EXECUTE_MODE
    try:
        from execution import vendors
    except Exception:
        return "local"
    for e in REMOTE_EXECUTORS:
        if e.get("host") and e.get("user") and vendors.is_usable(e.get("vendor", "")):
            return "remote"
    return "local"

# Remote tool-executors. More than one entry = more than one source IP to choose
# from / rotate for attribution. DISABLED by default (mode=local + list guidance).
# Each command dispatched here is STILL validated against the local scope-lock
# BEFORE it is sent (see remote_exec.py) — offloading never bypasses the scope wall.
REMOTE_EXECUTORS = [
    # {
    #     "name": "linode-dallas",
    #     "vendor": "linode",              # MUST match a CLEARED vendor in vendors.py (status=allowed)
    #     "host": "203.0.113.10",          # the VPS's public IPv4 (a REAL, attributed IP)
    #     "user": "recon",
    #     "ssh_key": "~/.ssh/recon_ed25519",
    #     "workdir": "/home/recon/run",
    #     "note": "primary recon box (Dallas)",
    # },
    # {
    #     "name": "linode-atlanta",
    #     "vendor": "linode",
    #     "host": "203.0.113.20",
    #     "user": "recon",
    #     "ssh_key": "~/.ssh/recon_ed25519",
    #     "workdir": "/home/recon/run",
    #     "note": "second source IP",
    # },
]
DEFAULT_EXECUTOR = None                    # a name from REMOTE_EXECUTORS, or None

# Operator-local executors: real box IPs/config live ONLY here, never in any repo (public OR the
# bucket). If ~/.config/offsec/executors.json exists (a JSON list of executor dicts, same shape as
# above), it REPLACES the template list. This keeps your source IPs out of git entirely.
import json as _json, os as _os  # noqa: E402
_LOCAL_EXECUTORS = _os.path.expanduser("~/.config/offsec/executors.json")
if _os.path.isfile(_LOCAL_EXECUTORS):
    try:
        with open(_LOCAL_EXECUTORS, encoding="utf-8") as _fh:
            _loaded = _json.load(_fh)
        if isinstance(_loaded, list) and _loaded:
            REMOTE_EXECUTORS = _loaded
            if DEFAULT_EXECUTOR is None:
                DEFAULT_EXECUTOR = _loaded[0].get("name")
    except (OSError, ValueError):
        pass

# Where the orchestrator (Claude) itself runs. Informational + a guard flag for the
# move-to-cloud step. "home" now; will become a control-VPS later. WHEREVER it is,
# its connection to Anthropic must be direct + clean (see hard rule below).
ORCHESTRATOR_LOCATION = "home"             # "home" | "control-vps"


# =============================================================================
# 3. LOCAL-TOOL VPN — DELIBERATELY NOT IMPLEMENTED (read this)
# =============================================================================
# There is NO code path to route THIS machine's tool traffic through a VPN, on
# purpose. A VPN on the same host that talks to Anthropic can leak that traffic
# (DNS leak, route load-order, a silent reconnect) — and the cost of one leak is
# the operator's Anthropic account. That trade is never worth it.
#
# The safe way to get tool traffic off your home IP is EXECUTE_MODE="remote": the
# tools run on a separate machine that Claude never routes through. A VPN, if you
# ever want one, belongs ONLY on that separate executor — physically away from the
# orchestrator — never here. See docs/REMOTE-EXECUTION.md and the Desktop note.
#
# This flag exists only to document the decision. It does nothing.
LOCAL_TOOL_VPN_ENABLED = False             # intentionally inert — no implementation


# =============================================================================
# 4. UNATTENDED-RUN SAFETY
# =============================================================================
# Wrap long unattended tool runs so nothing can loop for hours while you are away
# (the second real residential-ISP concern after bulk DNS). Helpers read these.
UNATTENDED_TOOL_TIMEOUT = "2h"             # passed to `timeout <val> <cmd>`
UNATTENDED_DEFER_BULK_DNS = True           # skip mass-DNS unless attended or remote


# =============================================================================
#  HARD RULE — the one line that must always hold, regardless of everything above
# =============================================================================
#  Whatever machine talks to Anthropic reaches it DIRECTLY, on a clean stable IP,
#  NEVER through a VPN/Tor/proxy. The Anthropic path and the scanning path stay on
#  SEPARATE IPs. Moving tools remote is fine; moving Anthropic behind a VPN is not.
#
#  IP STABILITY (it's not just VPNs — access PATTERN matters too):
#  Rapid IP/geo changes on the connection Claude uses can themselves raise account-risk
#  signals, independent of VPNs. So:
#   • The ORCHESTRATOR's connection to Anthropic must be ONE stable IP, US-based, never
#     rotated. NOW that is the home residential IP (fine — it doesn't change). LATER, if
#     the orchestrator moves to a control-VPS, that box must be a single fixed US IP that
#     you do NOT rotate or rebuild frequently, and never a VPN/known-abuse range.
#   • TOOL-EXECUTOR IPs (REMOTE_EXECUTORS) may vary/rotate/be rebuilt freely — they are
#     isolated from Claude's connection, so their IP churn has ZERO account impact. That
#     isolation is exactly why rotating recon IPs is safe while rotating Claude's is not.
# =============================================================================


def summary():
    """One-line human summary of the active execution posture."""
    where = EXECUTE_MODE
    if EXECUTE_MODE == "remote":
        where += f" -> {DEFAULT_EXECUTOR or '(no DEFAULT_EXECUTOR set!)'}"
    if raw_local_active():
        cap = "OFF (RAW-LOCAL OVERRIDE ACTIVE)"
    else:
        cap = ("ON " + str(GLOBAL_MAX_RPS) + "rps") if GLOBAL_RATE_LIMIT_ENABLED else "OFF"
    return (f"tools={where} | global_cap={cap}"
            f" | per_engagement={PER_ENGAGEMENT_MAX_RPS}rps | orchestrator={ORCHESTRATOR_LOCATION}"
            f" | local_vpn=absent(by design)")


def banner():
    """Loud warning line(s) when a non-default, higher-risk posture is active. Empty otherwise."""
    lines = []
    if raw_local_active():
        lines.append("⚠️  RAW-LOCAL OVERRIDE ACTIVE — global ISP rate cap is OFF. Tools run at their own "
                     "rates. (Scope-lock, hard floor, and Anthropic-direct rule STILL enforced.)")
    if EXECUTE_MODE == "remote" and not DEFAULT_EXECUTOR:
        lines.append("⚠️  EXECUTE_MODE=remote but no DEFAULT_EXECUTOR set — dispatch will fail.")
    return "\n".join(lines)


if __name__ == "__main__":
    print(summary())
