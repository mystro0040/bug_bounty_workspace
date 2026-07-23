"""
vendors — provider profiles for remote tool-execution, with AUP status baked in.
================================================================================

Each remote executor (a VPS) belongs to a VENDOR. This registry records, per vendor,
what their Acceptable Use Policy actually permits for authorized security testing, so
the agent can SEE what's allowed before it dispatches anything — and so the framework
will only ever run on a vendor that has been CLEARED.

The safety property: `is_usable()` returns True ONLY for status "allowed". A vendor that
is "ask_first" / "unknown" / "prohibited" is NOT usable until the operator confirms and
flips its status here. Default posture = don't use what we haven't cleared.

To add / clear a vendor: add or edit an entry below (structured + human-readable in one
place), set status="allowed" once you've read the AUP (or received written approval), and
point a REMOTE_EXECUTORS entry's "vendor" field at its slug.

Stdlib only. This is DATA the agent reads — no network, no secrets.
"""

# status values:
#   "allowed"    — AUP permits authorized in-scope testing; cleared for use.
#   "ask_first"  — wording is strict/ambiguous, or a policy ticket is pending. Not usable yet.
#   "unknown"    — AUP not yet read/confirmed. Not usable yet.
#   "prohibited" — AUP forbids it. Never usable.
VENDORS = {
    "linode": {
        "name": "Linode / Akamai",
        "aup_url": "https://www.akamai.com/legal/acceptable-use-policy",
        "aup_checked": "2026-07-23",
        "status": "allowed",
        "key_clause": ("prohibits probe/scan/test 'WITHOUT PROPER AUTHORIZATION' — authorized "
                       "in-scope bug-bounty testing IS authorized, so it is not barred."),
        "ask_required": False,
        "abuse_posture": "Akamai acts on abuse complaints; twitchy on brand-new accounts. Keep gentle.",
        "notes": "Cleanest AUP of vendors reviewed. Operator has an account. ~$5 Nanode 1GB. Preferred.",
    },
    "hosting_com": {
        "name": "hosting.com (Root Access Linux VPS)",
        "aup_url": "https://hosting.com/about/acceptable-usage-policy/",
        "aup_checked": "2026-07-23",
        "status": "prohibited",
        "key_clause": "Support answered ticket UHE-206-61572 (2026-07-23): bug-bounty / security "
                      "testing against EXTERNAL services is NOT permitted without prior authorization. "
                      "Explicitly disallowed for our use case. DO NOT USE.",
        "ask_required": True,
        "abuse_posture": "Would suspend on abuse. They said no in writing. Off the table.",
        "notes": "Ruled out 2026-07-23 by their own T&S reply. Use Linode instead.",
    },
    "digitalocean": {
        "name": "DigitalOcean",
        "aup_url": "https://www.digitalocean.com/legal/acceptable-use-policy",
        "aup_checked": "2026-07-23",
        "status": "ask_first",
        "key_clause": ("bars security/malware research 'on or USING the Services, without prior "
                       "written consent' — the 'using the Services' phrase may require consent to "
                       "run tools FROM a droplet. Stricter/ambiguous vs Linode."),
        "ask_required": True,
        "abuse_posture": "Historically wants notification for droplet-based pentesting.",
        "notes": "Usable, but the one provider here where asking may be warranted. Prefer Linode unless "
                 "you get DO's written consent first, then flip to 'allowed'.",
    },
    "vultr": {
        "name": "Vultr",
        "aup_url": "https://www.vultr.com/legal/aup/",
        "aup_checked": "2026-07-23 (AUP fetch returned 403 — NOT yet read)",
        "status": "unknown",
        "key_clause": "AUP could not be retrieved automatically; read it manually before use.",
        "ask_required": True,
        "abuse_posture": "Generally considered research-tolerant, but unconfirmed here.",
        "notes": "Cheap, many regions. Read vultr.com/legal/aup yourself, then set status accordingly.",
    },
    "aws": {
        "name": "AWS EC2",
        "aup_url": "https://aws.amazon.com/aup/",
        "aup_checked": "2026-07-23",
        "status": "ask_first",
        "key_clause": ("distinguishes testing YOUR OWN resources (allowed) from scanning THIRD "
                       "parties (AUP-governed, stricter). Abuse handling is aggressive."),
        "ask_required": True,
        "abuse_posture": "Acts fast on complaints. EC2 IP ranges are known-cloud → target WAFs "
                         "scrutinize/block them more, degrading recon.",
        "notes": "Worst fit here: pricier, fussier, poorer IP reputation. Use only if already in AWS.",
    },
    "generic": {
        "name": "(template — copy for a new vendor)",
        "aup_url": "",
        "aup_checked": "",
        "status": "unknown",
        "key_clause": "Read the vendor's AUP; record the operative clause here.",
        "ask_required": True,
        "abuse_posture": "",
        "notes": "Duplicate this entry, fill it in, set status='allowed' once cleared.",
    },
}


def get(slug):
    v = VENDORS.get(slug)
    if v is None:
        raise KeyError(f"unknown vendor '{slug}'. Known: {', '.join(sorted(VENDORS))}")
    return v


def is_usable(slug):
    """True only if the vendor's AUP has been cleared for authorized testing."""
    try:
        return get(slug)["status"] == "allowed"
    except KeyError:
        return False


def assert_usable(slug):
    """Raise if the vendor is not cleared — used by remote_exec before any dispatch."""
    v = get(slug)
    if v["status"] != "allowed":
        raise PermissionError(
            f"vendor '{slug}' ({v['name']}) is status='{v['status']}', not cleared for use. "
            f"{v['key_clause']} Clear it in vendors.py only after confirming its AUP / approval.")


def usable_vendors():
    return [s for s in VENDORS if is_usable(s)]


def _fmt(slug):
    v = VENDORS[slug]
    mark = {"allowed": "✅ USABLE", "ask_first": "🟡 ASK FIRST",
            "unknown": "⬜ UNKNOWN", "prohibited": "⛔ PROHIBITED"}.get(v["status"], v["status"])
    return (f"[{slug}] {v['name']} — {mark}\n"
            f"    AUP: {v['aup_url']}  (checked {v['aup_checked']})\n"
            f"    clause: {v['key_clause']}\n"
            f"    abuse: {v['abuse_posture']}\n"
            f"    notes: {v['notes']}")


def _cli(argv):
    args = argv[1:]
    if args and args[0] == "--usable":
        print("cleared for use:", ", ".join(usable_vendors()) or "(none)")
        return 0
    if args and args[0] in VENDORS:
        print(_fmt(args[0]))
        return 0
    if args:
        print(f"unknown vendor '{args[0]}'. Known: {', '.join(sorted(VENDORS))}")
        return 2
    print("VENDOR PROFILES (only 'allowed' are used by the framework):\n")
    for slug in VENDORS:
        print(_fmt(slug), "\n")
    print(f"USABLE right now: {', '.join(usable_vendors()) or '(none)'}")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_cli(sys.argv))
