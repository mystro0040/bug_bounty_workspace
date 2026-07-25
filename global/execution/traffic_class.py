"""
traffic_class.py — decide WHERE a given command is allowed to run, and prove the decision.

THE PROBLEM THIS SOLVES
    Not all testing is equally conspicuous. Ten thousand requests from a fuzzer, or a single
    unmistakable sqlmap payload, is the kind of thing that gets noticed, blocked, and reported.
    Fifteen hand-crafted requests while you reason about an auth flow looks like a user.

    Shipping everything to an air-gapped VM is maximally quiet but breaks the feedback loop: you
    cannot reason turn-by-turn about a response you will not see until the batch comes back. So
    the split is not by tool and not by machine — it is by how the traffic LOOKS to a defender.

TWO CLASSES

    BULK          High volume, or an unmistakable attack signature, or both. Scanners, fuzzers,
                  enumerators, automated exploit tooling. Always takes the isolated path.

    INTERACTIVE   A small number of hand-shaped requests whose next step depends on the last
                  response. Runs live so the loop stays closed.

WHAT ENFORCES THE SPLIT — and why a tool allow-list alone would not
    "Interactive" cannot simply mean "not in the scanner list", because `curl` inside a bash loop
    IS a scanner wearing a disguise. So classification is signature AND volume together:

      * a known bulk binary is BULK, always, whatever flags it carries
      * anything else starts INTERACTIVE but draws against a per-engagement request budget
      * exhaust the budget and it is no longer interactive BY DEFINITION — it is refused and told
        to go through the bulk path

    The budget is a counter on disk, not a promise in a docstring. That distinction is the entire
    point: a rule nothing counts is a rule that is not enforced.

Standard library only.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import time

# --------------------------------------------------------------------------- profiles
LINODE = "linode"                # DEFAULT: everything runs on the Linode executor
STAGED_HYBRID = "staged-hybrid"  # bulk ships to the air-gapped VM; interactive stays live
STAGED_STRICT = "staged-strict"  # everything ships; no live feedback loop at all
PROFILES = (LINODE, STAGED_HYBRID, STAGED_STRICT)

BULK = "bulk"
INTERACTIVE = "interactive"

STATE_DIR = os.path.expanduser("~/.config/offsec")
BUDGET_FILE = os.path.join(STATE_DIR, "interactive_budget.json")

# Per-engagement ceiling on interactive requests inside the window. Deliberately small: the moment
# work needs more than this it has stopped being hand-shaped and belongs on the isolated path.
INTERACTIVE_BUDGET = 50
BUDGET_WINDOW_SECONDS = 3600

# Binaries that are BULK no matter how they are invoked. Volume, signature, or both.
BULK_BINARIES = {
    "nuclei", "ffuf", "feroxbuster", "gobuster", "dirb", "dirsearch", "wfuzz",
    "sqlmap", "dalfox", "commix", "tplmap", "xsstrike",
    "masscan", "nmap", "naabu", "rustscan", "zmap",
    "amass", "subfinder", "assetfinder", "dnsx", "puredns", "shuffledns", "massdns",
    "katana", "hakrawler", "gospider", "gau", "waybackurls",
    "httpx", "arjun", "paramspider", "gowitness", "aquatone", "eyewitness",
    "nikto", "wpscan", "joomscan", "testssl.sh", "sslyze",
}

# Argument shapes that turn an otherwise-innocent binary into bulk work: a wordlist, a big
# iteration count, an injected fuzz marker. Signature, not volume.
BULK_ARG_PATTERNS = (
    r"-w\b", r"--wordlist", r"\bFUZZ\b", r"-iL\b", r"--list\b",
    r"-t\s*\d{2,}", r"--threads\s*\d{2,}", r"-c\s*\d{3,}",
)


class TrafficClassError(RuntimeError):
    pass


class BudgetExhausted(TrafficClassError):
    """Interactive budget spent — the work is no longer interactive by definition."""


# --------------------------------------------------------------------------- classification
def classify(command):
    """Classify a command string or argv list. Returns (class, reason).

    Errs toward BULK. Misclassifying bulk work as interactive puts noisy traffic on a live path;
    misclassifying interactive work as bulk merely costs convenience. Those are not symmetric, so
    anything ambiguous goes to the quiet path.
    """
    argv = shlex.split(command) if isinstance(command, str) else list(command)
    if not argv:
        raise TrafficClassError("empty command cannot be classified")

    # Step past env assignments and common wrappers so `env X=1 sudo nuclei` still classifies.
    idx = 0
    while idx < len(argv) and ("=" in argv[idx] and not argv[idx].startswith("-")
                               or argv[idx] in ("env", "sudo", "nice", "timeout", "nohup")):
        idx += 1
        if idx < len(argv) and argv[idx - 1] == "timeout":
            idx += 1                                  # skip timeout's duration argument
    if idx >= len(argv):
        raise TrafficClassError(f"no binary found in: {' '.join(argv)}")

    binary = os.path.basename(argv[idx])
    if binary in BULK_BINARIES:
        return BULK, f"{binary!r} is a bulk tool — always isolated, regardless of flags"

    rest = " ".join(argv[idx:])
    for pattern in BULK_ARG_PATTERNS:
        if re.search(pattern, rest):
            return BULK, (f"{binary!r} invoked with a bulk-work signature ({pattern}) — a "
                          f"wordlist or high thread count is a scanner whatever the binary is")

    # A loop or a pipeline that repeats a request is bulk however small each request looks.
    if isinstance(command, str) and re.search(r"\b(for|while)\b.+\bdo\b", command):
        return BULK, "shell loop detected — repeated requests are bulk regardless of the tool"

    return INTERACTIVE, f"{binary!r} with no bulk signature — treated as hand-shaped traffic"


def where_should_it_run(command, profile=LINODE):
    """Return (destination, traffic_class, reason).

    destination is one of: "executor" (the Linode), "staging" (the air-gapped VM via the staging
    repo), or "refused".
    """
    if profile not in PROFILES:
        raise TrafficClassError(f"unknown profile {profile!r}; expected one of {PROFILES}")
    klass, reason = classify(command)

    if profile == LINODE:
        return "executor", klass, f"{reason}; profile=linode runs everything on the executor"
    if profile == STAGED_STRICT:
        return "staging", klass, f"{reason}; profile=staged-strict ships everything"
    # staged-hybrid
    if klass == BULK:
        return "staging", klass, f"{reason}; bulk work is shipped to the isolated VM"
    return "executor", klass, (f"{reason}; interactive work stays live on the executor — this is a "
                               f"DELIBERATE, BUDGETED exception to full isolation")


# --------------------------------------------------------------------------- budget
def _load_budget():
    try:
        with open(BUDGET_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _save_budget(data):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = BUDGET_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    os.replace(tmp, BUDGET_FILE)
    os.chmod(BUDGET_FILE, 0o600)


def budget_status(engagement):
    data = _load_budget()
    now = time.time()
    stamps = [t for t in data.get(engagement, []) if t >= now - BUDGET_WINDOW_SECONDS]
    return {"engagement": engagement, "used": len(stamps), "limit": INTERACTIVE_BUDGET,
            "remaining": max(0, INTERACTIVE_BUDGET - len(stamps)),
            "window_minutes": BUDGET_WINDOW_SECONDS // 60}


def spend_interactive(engagement, count=1):
    """Draw against the interactive budget. Raises BudgetExhausted when it runs out.

    This is the mechanism behind the classification. Without it "interactive" is a label anyone can
    apply to a thousand curl calls in a loop.
    """
    data = _load_budget()
    now = time.time()
    stamps = [t for t in data.get(engagement, []) if t >= now - BUDGET_WINDOW_SECONDS]
    if len(stamps) + count > INTERACTIVE_BUDGET:
        raise BudgetExhausted(
            f"interactive budget for {engagement!r} is spent "
            f"({len(stamps)}/{INTERACTIVE_BUDGET} in the last "
            f"{BUDGET_WINDOW_SECONDS // 60} min). Work at this volume is no longer hand-shaped — "
            f"batch it and run it through the bulk path instead of continuing live.")
    stamps.extend([now] * count)
    data[engagement] = stamps
    _save_budget(data)
    return budget_status(engagement)


def reset_budget(engagement=None):
    """Clear the budget. Intended for a new engagement, not for continuing past the ceiling."""
    data = _load_budget()
    if engagement:
        data.pop(engagement, None)
    else:
        data = {}
    _save_budget(data)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(__doc__.strip())
        print(f"\nusage: {os.path.basename(__file__)} '<command>' [profile]")
        raise SystemExit(0)
    cmd = sys.argv[1]
    prof = sys.argv[2] if len(sys.argv) > 2 else LINODE
    dest, klass, why = where_should_it_run(cmd, prof)
    print(json.dumps({"command": cmd, "profile": prof, "class": klass,
                      "destination": dest, "reason": why}, indent=2))
