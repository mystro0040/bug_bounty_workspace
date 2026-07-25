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
#   "auto"   -> DEFAULT: resolve to "remote" when a remote executor is configured AND its
#               vendor is cleared; otherwise "local". Note "on the VPS", never "through"
#               it — tools RUN on that box; traffic is not tunnelled/proxied through it.
#   "local"  -> force local (a deliberate manual override — run here like before)
#   "remote" -> force remote (fails if no usable executor is configured)
#
# ⛔ WHAT resolve_mode() DOES *NOT* DO — read before you trust it.
# This is a DECLARATION of where tools SHOULD run. It is NOT a router. Nothing intercepts
# a Bash call and re-dispatches it. A tool you invoke normally runs HERE, on the home IP,
# no matter what this returns. The ONLY thing that runs a tool on the executor is calling
# remote_exec.run_remote() explicitly.
#
# This comment used to claim remote became the default "with no switch to flip". That was
# false for as long as it stood, and nobody caught it because it read confidently. The
# rule it cost us: for every important behaviour, ask what ENFORCES it. Hook, test, or
# code path -> a guarantee. "The agent reads this and complies" -> an intention. Label it.
EXECUTE_MODE = "auto"


def _load_vendors():
    """Import the vendor registry however this module was loaded.

    `from execution import vendors` alone only works when the PARENT of execution/ is on
    sys.path — true for `from execution import settings`, false for `python3 execution/
    settings.py`, which is exactly the command the §2 init protocol tells the agent to run.
    That mismatch made resolve_mode() report "local" on a box that was configured remote:
    a silent, wrong, and safety-relevant answer to the one question the agent came to ask.
    So try every load style, and if the registry genuinely cannot be read, RAISE — never
    quietly return an answer we cannot stand behind.
    """
    try:                                        # package-relative (normal import)
        from . import vendors                   # noqa: PLC0415
        return vendors
    except ImportError:
        pass
    try:                                        # parent-on-path
        from execution import vendors           # noqa: PLC0415
        return vendors
    except ImportError:
        pass
    import importlib.util, os.path              # sibling file, no package context
    spec = importlib.util.spec_from_file_location(
        "_offsec_vendors", os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendors.py"))
    if spec and spec.loader:
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    raise ImportError("vendors.py could not be loaded; refusing to guess the execution mode.")


def resolve_mode():
    """Resolve "auto" to the concrete mode. Returns "remote" only when at least one
    REMOTE_EXECUTORS entry is fully configured AND its vendor is CLEARED (status=allowed);
    otherwise "local". Explicit "local"/"remote" are returned as-is.

    A vendor registry that will not load is a hard error, not a fall-back to "local" —
    "local" is a real instruction to put scan traffic on the home IP, and it must never be
    reached by accident. See _load_vendors().
    """
    if EXECUTE_MODE in ("local", "remote"):
        return EXECUTE_MODE
    vendors = _load_vendors()
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
    """One-line human summary of the active execution posture.

    Always reports the RESOLVED mode, never a bare "auto". The §2 init protocol tells the
    agent to run this file and act on what it says, so "auto" alone would leave the one
    question that matters — do my tools go out from home or from the box? — unanswered.
    """
    resolved = resolve_mode()
    where = EXECUTE_MODE if EXECUTE_MODE == resolved else f"{EXECUTE_MODE}->{resolved}"
    if resolved == "remote":
        where += f" ON {DEFAULT_EXECUTOR or '(no DEFAULT_EXECUTOR set!)'}"
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
    _b = banner()
    if _b:
        print(_b)
    # The §2 init protocol sends the agent here to answer "where do my tools run?". Answer it
    # in full: resolving to remote is a REQUIREMENT to dispatch, not a promise that anything
    # will. Saying so at the point of use is what stops the 2026-07-25 mistake recurring.
    if resolve_mode() == "remote":
        print(f"\n⛔ Tools for this session must RUN ON the executor '{DEFAULT_EXECUTOR}'.\n"
              "   NOTHING routes automatically. A tool you invoke through Bash runs HERE, on the\n"
              "   home IP. Dispatch it: execution.remote_exec.run_remote(cmd, engagement, pull=[...]).\n"
              "   Check the box and its toolchain first: python3 execution/remote_data.py status")
    else:
        print("\n▶ Tools run LOCALLY, from this machine's own IP. No executor is usable "
              "(none configured, or its vendor is not cleared in vendors.py).")
