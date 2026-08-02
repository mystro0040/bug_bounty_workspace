#!/usr/bin/env python3
"""
scope_compiler.py — THE implementation of scope generation. One code path, whoever invokes it.

    python3 scope_compiler.py compile <engagement> [--update]
    python3 scope_compiler.py approve <engagement> --by <name>
    python3 scope_compiler.py verify  <engagement>
    python3 scope_compiler.py show    <engagement>

WHY THIS FILE EXISTS
    `/generate-scope` used to be a procedure written in prose inside a SKILL.md. Prose is not an
    implementation: an agent following it produces something *similar* to what another agent
    produces, and neither is guaranteed to match. That is exactly what happened on 2026-07-25 —
    a reimplementation omitted the per-TTP `commands:` block, which is the only thing carrying two
    of the four permanent constraints. The artifacts looked right and enforced less than they said.

    So the procedure now lives HERE, as executable code, and the skill calls it. "Generate the
    scope" means running this file, whether the operator types the slash command, an agent runs it,
    or the orchestrator dispatches it remotely. Same code, same output, no surprises.

WHERE THE HUMAN GATE ACTUALLY BELONGS
    On APPROVAL, not on generation.

    `compile` writes artifacts marked PENDING with `approved: false`. That profile is inert — the
    enforcement hook refuses everything until it is approved, so generating one changes nothing
    about what may run. Gating generation bought no safety; it only guaranteed that asking an agent
    to do it produced something different from doing it yourself.

    `approve` is the checkpoint. It requires an explicit operator name, refuses to run if the
    self-check fails, and refuses while any ASK_OPERATOR placeholder remains.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
import time

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml")

_located = os.path.abspath(__file__)                                # …/<ws>/global/scope/this file
WORKSPACE = os.path.dirname(os.path.dirname(os.path.dirname(_located)))
# Three levels, not two: the file lives at <workspace>/global/scope/, so stripping only two
# landed on <workspace>/global and every engagement lookup missed. Derive it once and assert it,
# rather than letting a wrong root produce "no engagement at …" for a path that plainly exists.
if not os.path.isdir(os.path.join(WORKSPACE, "engagements")):
    raise SystemExit(f"scope_compiler.py: cannot locate the workspace from {_located} "
                     f"(computed {WORKSPACE}, which has no engagements/ directory)")
ENG_ROOT = os.path.join(WORKSPACE, "engagements")
STATE = os.path.join(WORKSPACE, ".claude", "state", "active_engagement")
IDENTITY = os.path.join(WORKSPACE, "global", "operator-identity.md")

# Which TTP library to filter. Overridable so the pentest workspace can point at its own library
# instead of forking this file — one implementation, two knowledge bases.
def _machine_role():
    """`home` or `staging`, declared per machine at ~/.config/offsec/machine_role.

    Absent or unrecognised reads as `staging`. The failure worth preventing is a machine acquiring
    write access to the permanent library by accident; a machine being too cautious costs nothing.
    """
    try:
        with open(os.path.expanduser("~/.config/offsec/machine_role"), encoding="utf-8") as fh:
            for line in fh:
                v = line.split("#", 1)[0].strip().lower()
                if v:
                    return v if v in ("home", "staging") else "staging"
    except OSError:
        pass
    return "staging"


def _resolve_ttp_library():
    """Where the TTP library lives ON THIS MACHINE. Explicit, then repo, then bucket mirror.

    The master library is a separate git repo, so a machine that has the bucket but not the repo —
    the work machine — used to have no library at all and could not compile scope. The bucket now
    carries a WORKING mirror at `<bucket>/framework/ttps` (see framework/mirror_status.py for why
    that is not the old dead master-mirror), and this resolves to it automatically.

    Order matters. The repo wins where it exists, so home always compiles from the real master and
    can never accidentally build scope from a stale copy. The mirror is the fallback, not the
    default.
    """
    env = os.environ.get("OPSEC_TTP_LIBRARY")
    here = os.path.dirname(os.path.abspath(__file__))          # <root>/global/scope
    root = os.path.dirname(os.path.dirname(here))              # <root>
    repo = ("~/Workspace/Production_Ready/public/Offensive_Security/"
            "bug-bounty-execution-framework/ttps")
    mirror = os.path.join(root, "framework", "ttps")

    # A STAGING machine always works from the bucket mirror, even if the repo happens to be cloned
    # there. Without this the role file was half a mechanism: it stopped the mirror being stamped
    # but not the master being EDITED, so a `git clone` on the work machine would silently move
    # every TTP edit onto the permanent library. Nobody would ask approval for that, because from
    # the agent's side nothing looks different — it is doing ordinary work against a file that
    # quietly changed underneath it. Operator approval is the right gate for PROPAGATING; it
    # cannot be the gate for this, so the machine's declared role is.
    if _machine_role() != "home":
        candidates = [(env, "OPSEC_TTP_LIBRARY"),
                      (mirror, "the bucket's working mirror (this machine is staging)")]
    else:
        candidates = [(env, "OPSEC_TTP_LIBRARY"),
                      (repo, "the framework repo"),
                      (mirror, "the bucket's working mirror")]
    for path, why in candidates:
        if not path:
            continue
        full = os.path.expanduser(path)
        if os.path.isdir(full):
            return full, why
    tried = " | ".join(os.path.expanduser(p) for p, _ in candidates if p)
    raise SystemExit(f"scope_compiler.py: no TTP library found. Tried: {tried}. "
                     f"Set OPSEC_TTP_LIBRARY, clone the framework repo, or restore the bucket "
                     f"mirror at <bucket>/framework/ttps.")


FRAMEWORK, FRAMEWORK_SOURCE_IS = _resolve_ttp_library()


# ---------------------------------------------------------------- permanent constraints (Step 2c)
DOS_DENY = [r"hping3", r"slowloris", r"slowhttptest", r"\bt50\b", r"--flood", r"\bsiege\b",
            r"\bab\b.*-n\s*[0-9]{5,}", r"\bmhddos\b"]
DESTRUCTIVE_DENY = [r"--os-shell", r"--os-pwn", r"rm\s+-rf\s+/", r"\bmkfs\b", r"\bdd\s+if=.*of=/dev/"]
BRUTE_DENY = [r"\bhydra\b", r"\bmedusa\b", r"\bncrack\b", r"\bpatator\b", r"\bcrowbar\b"]
EVASION_DENY = [r"\btorsocks\b", r"\bproxychains\b"]

SCANNERS = {"ffuf", "nuclei", "sqlmap", "katana", "feroxbuster", "gobuster", "dirb", "dirsearch",
            "wfuzz", "dalfox", "arjun", "amass", "masscan", "nmap", "naabu", "nikto", "wpscan",
            "gowitness", "paramspider", "hakrawler", "gospider"}

RECON_SOURCES = ["crt.sh", "api.certspotter.com", "whois.radb.net", "github.com",
                 "api.github.com", "web.archive.org", "otx.alienvault.com", "urlscan.io"]

LOCAL_HELPERS = ["jq", "grep", "sed", "awk", "cat", "echo", "printf", "sort", "uniq", "tee",
                 "python3", "git", "gh", "sha256sum", "sha512sum", "file", "gpg", "wc", "head",
                 "tail", "tr", "cut", "xargs", "sleep", "date", "mkdir", "cp", "mv", "diff"]

TOOL_BINARIES = {"curl", "httpx", "dnsx", "subfinder", "assetfinder", "gau", "waybackurls",
                 "whois", "semgrep", "interactsh-client", "qsreplace", "gf"} | SCANNERS

# Rate flag per tool, so constraint 3 is expressed in the emitted command rather than asserted.
RATE_FLAG = {
    "ffuf": "-rate {r} -t 10", "nuclei": "-rl {r} -c 10", "feroxbuster": "--rate-limit {r}",
    "httpx": "-rate-limit {r}", "dnsx": "-rate-limit {r}", "katana": "-rate-limit {r}",
    "subfinder": "-rate-limit {r}", "naabu": "-rate {r}", "gobuster": "--delay 50ms",
}

# Capabilities a program must have for a technique to be relevant (Step 2b curation).
CAPABILITY_HINTS = {
    "mobile": ("apk", "android", "ios", "mobile", "frida", "objection", "jadx", "apktool"),
    "source": ("codeql", "semgrep", "source code", "repository clone", "git clone"),
    "cloud": ("aws ", "s3 bucket", "gcp", "azure", "iam role", "metadata endpoint"),
}


class ScopeError(RuntimeError):
    pass


# ---------------------------------------------------------------- helpers
def eng_dir(engagement):
    d = os.path.join(ENG_ROOT, engagement)
    if not os.path.isdir(d):
        raise ScopeError(f"no engagement at {d}")
    return d


def find_scope_file(d):
    for name in ("scope.md", "scope.txt"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.path.getsize(p) > 200:
            return p
    hits = sorted(glob.glob(os.path.join(d, "*scope*")))
    if len(hits) == 1 and os.path.getsize(hits[0]) > 200:
        return hits[0]
    raise ScopeError(f"no usable scope file in {d} — fill in scope.md before compiling")


def operator_handle(platform):
    """Constraint 4: resolve the handle from operator-identity.md. Never ask if it is on file."""
    if not os.path.isfile(IDENTITY):
        return None
    body = open(IDENTITY, encoding="utf-8").read()
    row = re.search(rf"\*\*{platform}\*\*\s*\|\s*`([^`]+)`", body, re.I)
    return row.group(1) if row else None


def load_tasks():
    """Every framework task that is bounty-safe, unlocked and non-destructive."""
    out = []
    for path in sorted(glob.glob(os.path.join(FRAMEWORK, "**", "*.yaml"), recursive=True)):
        doc = yaml.safe_load(open(path, encoding="utf-8"))
        if not isinstance(doc, dict):
            continue
        phase = doc.get("phase") or os.path.basename(os.path.dirname(path))
        for sec in (doc.get("sections") or []):
            for t in (sec.get("tasks") or []):
                pol = t.get("policy") or {}
                if pol.get("locked") or pol.get("destructive") or pol.get("bounty_safe") is False:
                    continue
                cmds = [(c.get("run") or "").strip() for c in (t.get("commands") or [])]
                cmds = [c for c in cmds if c and not c.lstrip().startswith("#")]
                bins = set()
                for c in cmds:
                    for tok in re.findall(r"[A-Za-z0-9_.\-]+", c):
                        if tok in TOOL_BINARIES:
                            bins.add(tok)
                out.append({"id": t.get("id"), "technique": t.get("name"), "phase": phase,
                            "intent": (t.get("purpose") or "").strip()[:220],
                            "poc_only": bool(pol.get("poc_only", True)),
                            "requires": pol.get("requires", "none"),
                            "raw_commands": cmds, "binaries": sorted(bins),
                            "blob": (t.get("name", "") + " " + (t.get("purpose") or "") + " "
                                     + " ".join(cmds)).lower(),
                            # Separate from `blob` on purpose. `blob` feeds CAPABILITY_HINTS, which
                            # EXCLUDES; this one feeds gating, which only ANNOTATES. Widening the
                            # first to include `requirements` would silently change what gets
                            # curated out, so the two stay apart.
                            "gate_blob": (t.get("name", "") + " " + (t.get("purpose") or "") + " "
                                          + (t.get("requirements") or "") + " "
                                          + " ".join(cmds)).lower()})
    return out


# Regexes, not substrings, and the reason is one word: "unauthenticated" CONTAINS "authenticated".
# A substring match tagged a read-only header-disclosure technique as needing a login because its
# own text said it needs no authentication. Anything matching the negative phrases is excluded first.
GATING_HINTS = {
    "authenticated_session": (r"(?<!un)authenticated\b", r"logged[- ]in", r"signed[- ]in",
                              r"\byour session\b", r"session cookie", r"captured (jwt|token)",
                              r"an account you own", r"valid session"),
    "two_test_accounts": (r"two test accounts", r"\baccount a\b", r"\baccount b\b",
                          r"second test account", r"cross[- ]account"),
    "oob_listener": (r"\boast\b", r"collaborator", r"interactsh", r"out-of-band interaction host",
                     r"callback host"),
    "local_source": (r"local copy of in-scope source", r"a local source copy", r"source tree",
                     r"\bcodeql\b", r"\bsemgrep\b", r"repository clone"),
    "target_supplied_artifact": (r"\bapk\b", r"\basar\b", r"desktop client", r"mobile app"),
}
_GATE_NEGATIVES = re.compile(
    r"no authentication|without authentication|unauthenticated|no account|"
    r"pre-auth|before any token exists|no credentials needed")


def gating(task):
    """Which prerequisites this technique needs. Informational only — never a filter."""
    blob = task["gate_blob"]
    out = []
    for gate, patterns in GATING_HINTS.items():
        if gate in ("authenticated_session", "two_test_accounts") and _GATE_NEGATIVES.search(blob):
            continue
        if any(re.search(p, blob) for p in patterns):
            out.append(gate)
    return sorted(out)


def relevant(task, caps, manual_only):
    """Step 2b curation — is this technique appropriate to THIS program's assets and rules?

    HARD RULE, do not change this without the operator saying so explicitly.
    Curation answers ONE question: does the PROGRAM permit this technique on these assets?
    It never answers "can we run it today". Whether an account exists, whether a listener is
    installed, whether source is checked out — none of that is an input here. A technique we
    cannot run yet is still approved; we simply do not run it until we can.

    The reason is concrete. Filtering on what we currently possess means every credential, tool
    or artifact that arrives later forces a scope regenerate, and every regenerate is a fresh
    approval, a recompiled wall, and a chance to lose hand-added entries. Scope should change
    when the PROGRAM changes, and at no other time. Gating is recorded by gating() instead.
    """
    if manual_only and (set(task["binaries"]) & SCANNERS):
        return False, "scanner on a manual-only program"
    for cap, hints in CAPABILITY_HINTS.items():
        if cap in caps:
            continue
        if any(h in task["blob"] for h in hints):
            return False, f"needs '{cap}' capability this program does not have"
    if task["requires"] == "program_approval":
        return False, "requires explicit per-program approval (Tier 2 — never auto-included)"
    return True, ""


PLACEHOLDER_RX = re.compile(r"(example\.com|target\.com|<[A-Za-z_]*(?:TARGET|target|domain|DOMAIN)[A-Za-z_]*>|\bTARGET\b)")

# Shell separators that start a NEW command. Splitting on "|" alone was not enough: a line like
#   ... | sort -u > custom.txt && ffuf -w custom.txt ...
# puts ffuf after a redirect that belongs to an entirely different command, so a check that only
# understood pipes reported a correctly-flagged ffuf as misplaced. A check that cries wolf gets
# ignored, which is worse than not having it — so emission and verification share this one splitter.
_SEPARATORS = re.compile(r"\|\||&&|[|;]")


def _split_outside_quotes(line, keep=False):
    """Split on shell separators, ignoring any that sit INSIDE quotes.

    A plain regex split is wrong for exactly the commands we care most about. A command-injection
    proof carries its separator inside the payload — `--data-urlencode "host=127.0.0.1; id"` — and
    splitting on that semicolon cuts the command in half, so the attribution header that follows
    looks like it belongs to a different process. That produced a false "header attached to the
    wrong process" on a real profile, and a check that flags correct behaviour gets ignored.

    Returns the pieces; with keep=True the separators are returned between them, so a caller can
    rejoin the line unchanged.
    """
    out, buf, quote, i = [], [], None, 0
    while i < len(line):
        ch = line[i]
        if quote:
            buf.append(ch)
            if ch == quote and (i == 0 or line[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        two = line[i:i + 2]
        if two in ("||", "&&"):
            out.append("".join(buf))
            if keep:
                out.append(two)
            buf, i = [], i + 2
            continue
        if ch in "|;":
            out.append("".join(buf))
            if keep:
                out.append(ch)
            buf, i = [], i + 1
            continue
        buf.append(ch)
        i += 1
    out.append("".join(buf))
    return out


def _command_segment(line, binary):
    """The sub-command that actually runs `binary`, and the part of it before any redirect."""
    for seg in _split_outside_quotes(line):
        if re.search(rf"(^|[\s/`]){re.escape(binary)}\s", seg):
            head = re.split(r"\s(?:\d?>>?|>)\s", seg)[0]
            return seg, head
    return "", ""


_SPLIT_KEEP = re.compile(r"(\|\||&&|[|;])")     # capturing → separators survive the rejoin


def _inject_all(line, task_binaries, cfg):
    """Flag EVERY sub-command that runs a network tool, not just the first one.

    A single TTP line often chains several tools:
        katana … | gau … | sort -u > custom.txt && ffuf …
        curl … -o t.txt; curl … -o f.txt; diff t.txt f.txt
    Flagging only the first match left `gau` and the second `curl` running unattributed and
    unthrottled — the constraint held for part of the command and quietly not for the rest.

    Separators are preserved through a capturing split, and leading whitespace inside a segment is
    kept, because re-joining with a normalising join silently produced `&&ffuf`.
    """
    rate = cfg["rate_value"]
    hname, hvalue = cfg["header"]
    # Quote-aware, for the same reason _command_segment is: a separator inside a payload string
    # (`--data-urlencode "host=127.0.0.1; id"`) is part of the argument, not a new command. A plain
    # regex split cut such a line in half and injected the header into the wrong piece.
    parts = _split_outside_quotes(line, keep=True)
    for idx in range(0, len(parts), 2):                 # even indices are command segments
        seg = parts[idx]
        binary = next((b for b in task_binaries
                       if re.search(rf"(^|[\s/`]){re.escape(b)}\s", seg)), None)
        if not binary or binary in ("whois", "semgrep"):
            continue
        # The program's ceiling must WIN over whatever the TTP library hardcoded. Two ways it
        # used to lose, both found by comparing the documented limit to the emitted commands:
        #
        #   dnsx  — RATE_FLAG is "-rate-limit", the library line carried "-rl 20". "-rate-limit"
        #           was absent, so we injected "-rate-limit 5" and produced
        #           `dnsx -rate-limit 5 … -rl 20`. The LATER flag wins at the CLI, so the
        #           effective rate was 20 while the profile documented 5.
        #   httpx — the library line already carried "-rate-limit 20", so the check saw the flag
        #           present and skipped entirely, leaving 20 untouched.
        #
        # Thirty commands across two engagements were running at 10–30 req/s under a profile that
        # said 5. Rewrite every alias to min(library, program) instead: clamping down never
        # exceeds the ceiling, and never raises a library value that was already gentler.
        seg = _clamp_rates(seg, binary, rate)
        head = re.split(r"\s(?:\d?>>?|>)\s", seg)[0]
        additions = []
        if binary in RATE_FLAG and not _has_rate_flag(head, binary):
            additions += RATE_FLAG[binary].format(r=rate).split()
        if hname not in head:
            additions += ["-H", f'"{hname}: {hvalue}"']
        parts[idx] = _inject(seg, binary, additions) if additions else seg
    return "".join(parts)


# Every spelling of "rate limit" each tool accepts. A tool's short and long forms are the SAME
# option, so checking only the long form is how `-rate-limit 5 … -rl 20` got emitted.
_RATE_ALIASES = {
    "dnsx":        ("-rate-limit", "-rl"),
    "httpx":       ("-rate-limit", "-rl"),
    "katana":      ("-rate-limit", "-rl"),
    "subfinder":   ("-rate-limit", "-rl"),
    "nuclei":      ("-rate-limit", "-rl"),
    "naabu":       ("-rate",),
    "ffuf":        ("-rate", "-rate-limit"),      # the library uses BOTH spellings
    "feroxbuster": ("--rate-limit",),
    "arjun":       ("--rate-limit",),
    # Below: tools that throttle with a PAUSE, not a rate. Listed so the self-check recognises a
    # throttled invocation, and excluded from clamping by _DELAY_TOOLS.
    "gobuster":    ("--delay",),
    "dalfox":      ("--delay",),
    "sqlmap":      ("--delay",),
}

# `--delay 50ms` is the INVERSE of a rate: forcing it down to the rate ceiling would make the
# tool run FASTER, which is the opposite of the intent. Clamp only flags whose number means
# requests-per-second.
#
# This list is not guesswork — it came from scanning every rate-ish flag the TTP library actually
# emits and diffing against this map. That audit found four gaps at once (arjun's --rate-limit,
# ffuf's second spelling, and dalfox/sqlmap's --delay). Re-run it when the library changes:
# grep the emitted commands for rate|rl|delay|throttle|qps and check each against this table.
_DELAY_TOOLS = {"gobuster", "dalfox", "sqlmap"}
_CLAMP_ALIASES = {k: v for k, v in _RATE_ALIASES.items() if k not in _DELAY_TOOLS}


def _has_rate_flag(text, binary):
    return any(re.search(rf"(?<![\w-]){re.escape(a)}(?=[\s=]|$)", text)
               for a in _RATE_ALIASES.get(binary, ()))


def _clamp_rates(segment, binary, ceiling):
    """Force every requests-per-second flag in this segment to at most the program's ceiling."""
    def repl(m):
        try:
            return f"{m.group(1)} {min(int(m.group(2)), ceiling)}"
        except ValueError:
            return m.group(0)
    for alias in _CLAMP_ALIASES.get(binary, ()):
        segment = re.sub(rf"(?<![\w-])({re.escape(alias)})[\s=]+(\d+)", repl, segment)
    return segment


def _inject(segment, binary, additions):
    """Insert flags immediately AFTER the binary token, inside its own pipeline segment.

    Appending to the end of the line looked fine and was wrong: a command like
        curl … | jq '.' > out.json
    became
        curl … | jq '.' > out.json -H "X-Bug-Bounty: …"
    where the header is an argument to the redirect target, not to curl. The flag was present in
    the string — which is exactly what the old self-check asked — and attached to nothing.

    Inserting right after the binary is safe for every tool here: all of them accept flags before
    their positional arguments.
    """
    lead = segment[:len(segment) - len(segment.lstrip())]
    tokens = segment.split()
    for i, tok in enumerate(tokens):
        if tok == binary or tok.endswith("/" + binary) or tok.lstrip("`") == binary:
            return lead + " ".join(tokens[:i + 1] + additions + tokens[i + 1:])
    return segment


def emit_commands(task, cfg):
    """Constraints 3 + 4 expressed IN the command, attached to every tool they govern."""
    host = (cfg["hosts"] or ["<in-scope-host>"])[0]
    out = []
    for raw in task["raw_commands"][:3]:
        cmd = PLACEHOLDER_RX.sub(host, raw)
        out.append(_inject_all(cmd, task["binaries"], cfg))
    return out


# ---------------------------------------------------------------- compile
# ---------------------------------------------------------------- automation stance gate
#
# WHY THIS EXISTS
#   A program page stated, verbatim, that it could not accept submissions found by using
#   automatic scanners. That sentence sat in the captured program data the whole time and never
#   reached `scope.md`, so the compiled lock allowed sqlmap, nuclei, ffuf, feroxbuster, katana,
#   gobuster, dalfox and amass against a program that would have thrown out anything they found.
#   A sibling engagement on the same platform carried the identical rule and enforced it
#   correctly — same rule, two sessions, two outcomes.
#
#   `manual_only` was, and still is, a value the caller supplies. Nothing checked it against what
#   the program actually said. That is a rule enforced by whoever remembered it, which is not
#   enforcement. This gate reads the captured program text — the source of truth — and refuses to
#   compile a scanner-enabled profile for a program whose own words forbid it.
#
#   Deliberately derived from the PROGRAM DATA, never from the compiled lock. A previous attempt
#   inferred manual-only from the lock's deny-list and wrongly stripped 23 scanner TTPs from a
#   program that explicitly permits automated scanning at a stated rate. The lock is downstream; reading it
#   to decide what the lock should say is circular.

# Unambiguous prohibitions. A hit here refuses the compile unless manual_only is set.
_AUTOMATION_BANNED = [
    r"do\s*(?:not|n't)\s+use\s+(?:any\s+)?automat(?:ed|ic)",
    r"cannot\s+accept\s+any\s+submissions?\s+found\s+by\s+using\s+automat(?:ed|ic)",
    r"automat(?:ed|ic)\s+(?:scanning|scanners?|tools?|testing)\s+is\s+(?:not\s+permitted|not\s+allowed|prohibited|forbidden)",
    r"(?:no|never\s+use)\s+automat(?:ed|ic)\s+scanners?",
    r"scanners?\s+are\s+(?:not\s+permitted|not\s+allowed|prohibited|forbidden)",
    r"prohibited[^.\n]{0,60}automat(?:ed|ic)\s+(?:scanning|scanners?)",
    r"automat(?:ed|ic)\s+scanners?[^.\n]{0,40}(?:prohibited|forbidden|not\s+allowed)",
]

# Mentions automation in a way that might matter but isn't a ban — e.g. "reports from automated
# scanners will be closed as Not Applicable", which restricts what counts as EVIDENCE,
# not whether you may run the tool. Surfaced loudly and recorded; never blocking, because treating
# every scanner mention as a ban would make the gate something operators learn to override.
_AUTOMATION_REVIEW = [
    r"automat(?:ed|ic)\s+scanners?",
    r"automat(?:ed|ic)\s+(?:scanning|tooling|testing)",
    r"\bscanners?\b",
]

_SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".zip", ".pdf",
             ".woff", ".woff2", ".css", ".js", ".xlsx"}


# Where captured program policy lives. Both spellings are in use — engagements set up from the
# vault get `_program-data/`, older ones use `program/`. Scan whichever exist
# rather than standardising them: renaming a closed engagement's directory to satisfy a checker
# is the checker bending the record, which is backwards.
_PROGRAM_DATA_DIRS = ("_program-data", "program")


def _program_data_lines(d):
    """Every readable line of captured program text, as (relative path, line no, text).

    Returns None when no program-data directory exists at all — distinct from an empty list,
    which means the directory exists but held nothing readable. The caller treats the two
    differently, and must.

    Saved-webpage furniture is skipped — it carries no program rules, and letting a minified
    bundle into the scan produces noise that buries a real hit.
    """
    roots = [os.path.join(d, name) for name in _PROGRAM_DATA_DIRS
             if os.path.isdir(os.path.join(d, name))]
    if not roots:
        return None
    out = []
    for root in roots:
        out.extend(_scan_root(root))
    return out


def _scan_root(root):
    out = []
    for dirpath, _, filenames in os.walk(root):
        for fn in sorted(filenames):
            if os.path.splitext(fn)[1].lower() in _SKIP_EXT or "_files" in dirpath:
                continue
            fp = os.path.join(dirpath, fn)
            try:
                if os.path.getsize(fp) > 4_000_000:      # a page dump, not a rules file
                    continue
                with open(fp, encoding="utf-8", errors="replace") as fh:
                    for n, line in enumerate(fh, 1):
                        line = line.strip()
                        if line:
                            out.append((os.path.relpath(fp, root), n, line))
            except OSError:
                continue
    return out


def detect_automation_stance(engagement):
    """Read the captured program text and report what it says about automated tooling.

    Returns {"verdict": "banned"|"unclear"|"no_program_data",
             "banned": [(file, line, text), ...], "review": [...]}
    """
    lines = _program_data_lines(eng_dir(engagement))
    if lines is None:
        return {"verdict": "no_program_data", "banned": [], "review": []}

    banned, review = [], []
    for rel, n, text in lines:
        low = text.lower()
        if any(re.search(p, low) for p in _AUTOMATION_BANNED):
            banned.append((rel, n, text[:300]))
        elif any(re.search(p, low) for p in _AUTOMATION_REVIEW):
            review.append((rel, n, text[:300]))
    return {"verdict": "banned" if banned else "unclear", "banned": banned, "review": review}


class AutomationStanceError(Exception):
    """Raised when the program's own words forbid what the requested profile would allow."""


class IdentificationHeaderError(Exception):
    """Raised when the configured attribution header is not the one the program asks for."""


# Every attribution-header spelling seen in the wild. They differ per program and per platform,
# and the difference is one word.
_HEADER_RE = re.compile(r"\bX-(?:HackerOne|Bug-?Bounty|Intigriti|BugBounty)[A-Za-z-]*", re.I)


def detect_identification_header(engagement):
    """Which attribution header does the captured program text actually ask for?

    Returns {"found": [names...], "lines": [(file, line, text)...]}. Empty `found` means the
    program data never names one — the compiler then trusts the config, because plenty of
    programs state the header only on a page that was never captured.
    """
    lines = _program_data_lines(eng_dir(engagement))
    if lines is None:
        return {"found": [], "lines": []}
    found, cites = {}, []
    for rel, n, text in lines:
        for m in _HEADER_RE.finditer(text):
            name = m.group(0)
            key = name.lower()
            if key not in found:
                found[key] = name
                cites.append((rel, n, text[:200]))
    return {"found": sorted(found.values()), "lines": cites}


def _enforce_identification_header(engagement, cfg_header_name):
    """Refuse a profile whose attribution header is not the one the program asks for.

    WHY: one program's page asked for a header the compiled lock did not carry — the lock had
    another platform's convention instead. Requests went out attributed, but under a header that
    program does not look for, and the finding's method section stated the wrong one. The header
    is a per-program value that differs by a single word between programs run in the same week
    (`X-HackerOne-Research` / `X-HackerOne-Researcher` / `X-HackerOne-Handle` / `X-Bug-Bounty`),
    which is precisely the kind of value that should not be held in anyone's head.

    Silence is NOT an error here, unlike the automation stance. A program that never states a
    header in its captured text has not contradicted the config, and refusing would punish
    incomplete capture rather than a real mismatch.
    """
    det = detect_identification_header(engagement)
    if not det["found"]:
        return det
    if any(h.lower() == (cfg_header_name or "").lower() for h in det["found"]):
        return det
    ev = "\n".join(f"    {f}:{n}  {t}" for f, n, t in det["lines"][:4])
    raise IdentificationHeaderError(
        f"{engagement}: the configured attribution header '{cfg_header_name}' does not match "
        f"what the program asks for.\n\n"
        f"  The program's text names: {', '.join(det['found'])}\n\n{ev}\n\n"
        f"  Set the correct header in the config and re-run. Traffic sent under the wrong header "
        f"is unattributed as far as the program is concerned, and any report claiming otherwise "
        f"is claiming something untrue.")


def _enforce_automation_stance(engagement, manual_only):
    """Refuse a scanner-enabled compile when the program prohibits automated scanners.

    Two refusals, both fail-closed:
      * the program text bans scanners and manual_only was not requested;
      * there is no captured program text at all, so the stance cannot be established.
    The second matters as much as the first — "I couldn't check" must not read the same as
    "I checked and it was fine."
    """
    stance = detect_automation_stance(engagement)

    if stance["verdict"] == "no_program_data":
        raise AutomationStanceError(
            f"cannot establish the automation stance for {engagement}: no _program-data/ "
            f"directory, so there is nothing to check the program's rules against.\n"
            f"Copy the captured program pages into {eng_dir(engagement)}/_program-data/ and "
            f"re-run. Refusing to compile a profile whose scanner permissions cannot be "
            f"verified against the program's own words.")

    if stance["verdict"] == "banned" and not manual_only:
        ev = "\n".join(f"    {f}:{n}  {t}" for f, n, t in stance["banned"][:5])
        raise AutomationStanceError(
            f"{engagement} PROHIBITS automated scanners, but this compile requested a "
            f"scanner-enabled profile (manual_only=false).\n\n"
            f"  The program's own words:\n{ev}\n\n"
            f"  Set manual_only: true in the config and re-run. If you believe this is a false "
            f"match, do not weaken the pattern — read the source line above, decide, and record "
            f"the decision in scope.md so the next session inherits it.")

    return stance


LEDGER_TEMPLATE = """# BREAKTHROUGH LEDGER — {name}

Append-only record of every successful fix, working bypass and reusable technique discovery made
during this engagement. Entries are promotion candidates: generalized technique flows back into the
master TTP library in a Tier-1 maintenance pass, engagement data never does.

When an entry IS promoted, record the master task id in backticks so `ttp_manager.py promote` can
see it. When it belongs somewhere other than the library — a config rule, a tool fix — say
NOT-A-LIBRARY-ITEM and where it went. An entry with neither shows as outstanding until it is settled.

Created automatically when this engagement's scope was compiled. It exists from day one so a
discovery has somewhere to go the moment it happens, rather than being reconstructed afterwards from
probe scripts — which is how eleven engagements' worth of technique was nearly lost.

---

_No entries yet. Add one the first time something here is fixed, bypassed or discovered. An empty
ledger at close-out means the discoveries were lost, not that there were none._
"""


def ensure_ledger(d):
    """Every engagement gets a breakthrough ledger, created here because every engagement is scoped.

    This is the hook that makes the discovery-to-master loop a mechanism rather than a habit. The
    rule existed in the config for weeks and two engagements in fifteen actually had a ledger, so
    the promotion pass had nothing to read. Creating it is not optional and is never skipped.
    """
    path = os.path.join(d, "BREAKTHROUGH_LEDGER.md")
    if os.path.isfile(path):
        return False
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(LEDGER_TEMPLATE.format(name=os.path.basename(d)))
    return True


def ensure_plan(d, engagement):
    """Every engagement gets `_PLAN.md` and `_COVERAGE.md`, for the same reason it gets a ledger.

    The anti-duplication mechanism. Without it a session's train of thought lives only in a
    transcript that is deliberately not carried across machines, so the next session re-derives what
    was already known and re-runs tests that were already run. Both happened on 2026-08-01.

    Delegates to `utilities/engagement/plan.py`, which owns the format. Import is local and failure
    is non-fatal: a missing planner must never stop a scope from compiling, because a scope that
    will not compile is a locked-down engagement and that is a far worse outcome than a missing
    plan file.
    """
    try:
        fw = _resolve_ttp_library()
        # returns (path, how) — take the path, not the tuple
        fw = fw[0] if isinstance(fw, (tuple, list)) else fw
        base = os.path.dirname(os.path.dirname(os.path.abspath(fw))) if fw else None
        for cand in ([os.path.join(base, "utilities")] if base else []) + [
                os.path.expanduser("~/Workspace/Production_Ready/public/Offensive_Security/"
                                   "bug-bounty-execution-framework/utilities")]:
            if os.path.isdir(os.path.join(cand, "engagement")):
                if cand not in sys.path:
                    sys.path.insert(0, cand)
                break
        from engagement import plan as _plan          # noqa: PLC0415
        made = []
        for f in (_plan.PLAN_FILE, _plan.COVERAGE_FILE):
            if not os.path.exists(os.path.join(d, f)):
                made.append(f)
        if made:
            _plan.main(["init", "--engagement", engagement])
        return made
    except Exception as exc:                                 # noqa: BLE001
        return ["(planner unavailable: %s)" % type(exc).__name__]


def compile_scope(engagement, cfg, update=False):
    d = eng_dir(engagement)
    ensure_ledger(d)
    scope_file = find_scope_file(d)
    sha = hashlib.sha256(open(scope_file, "rb").read()).hexdigest()
    approved_path = os.path.join(d, "approved_TTPs.yaml")

    if os.path.isfile(approved_path) and not update:
        prior = yaml.safe_load(open(approved_path, encoding="utf-8")) or {}
        if prior.get("source_scope_sha256") == sha:
            return {"engagement": engagement, "cached": True,
                    "note": "scope unchanged — existing profile still valid. Use --update to force."}

    caps = set(cfg.get("capabilities", ["web", "api", "dns"]))
    manual_only = cfg.get("manual_only", False)
    rate = cfg["rate_value"]

    # Before anything is written: does the program's own text permit what we're about to allow?
    # Raises AutomationStanceError and writes nothing if not.
    stance = _enforce_automation_stance(engagement, manual_only)
    _enforce_identification_header(engagement, cfg["header"][0])

    approved, excluded, gated = [], {}, {}
    for t in load_tasks():
        ok, why = relevant(t, caps, manual_only)
        if not ok:
            excluded[why] = excluded.get(why, 0) + 1
            continue
        entry = {k: t[k] for k in ("id", "technique", "phase", "intent", "poc_only", "binaries")}
        entry["commands"] = emit_commands(t, cfg)
        entry["source"] = "framework"
        # Annotation, not curation — see relevant().__doc__. These techniques ARE approved.
        g = gating(t)
        if g:
            entry["gated_by"] = g
            for k in g:
                gated[k] = gated.get(k, 0) + 1
        approved.append(entry)

    for t in load_tasks():
        ok, why = relevant(t, caps, manual_only)
        if not ok:
            excluded[why] = excluded.get(why, 0) + 1
            continue
        entry = {k: t[k] for k in ("id", "technique", "phase", "intent", "poc_only", "binaries")}
        entry["commands"] = emit_commands(t, cfg)
        entry["source"] = "framework"
        approved.append(entry)

    used = set()
    for t in approved:
        used |= set(t["binaries"])
    allowed = sorted(used | set(LOCAL_HELPERS) | set(cfg.get("extra_binaries", [])))

    denied = DOS_DENY + DESTRUCTIVE_DENY + BRUTE_DENY + EVASION_DENY + cfg.get("extra_denied", [])
    if manual_only:
        denied += [rf"\b{b}\b" for b in sorted(SCANNERS)]

    hname, hvalue = cfg["header"]
    profile = {
        "engagement": os.path.basename(engagement),
        "generated_by": "scope_compiler.py",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_scope_file": os.path.basename(scope_file),
        "source_scope_sha256": sha,
        "assets": {"hosts": cfg["hosts"] + RECON_SOURCES,
                   "wildcards": cfg.get("wildcards", []), "cidrs": [], "ips": [],
                   "endpoints": cfg.get("endpoints", []),
                   "out_of_scope": cfg.get("out_of_scope", [])},
        "program_rules": cfg["program_rules"],
        "operational_constraints": {
            "social_engineering": "forbidden",
            "cross_account_testing": "test_accounts_only",
            "test_accounts": cfg.get("test_accounts") or ["ASK_OPERATOR"],
            "dos": "banned",
            "rate_limit": cfg["rate_limit"],
            "automation": "manual_only" if manual_only else "rate_limited",
            # What the program text actually said, and where. Recorded so a later session can
            # audit the decision instead of re-deriving it — the drift this whole gate exists
            # to prevent. "verified_permitted" means the scan found no prohibition; it is not a
            # claim that a human read the policy.
            "automation_evidence": {
                "verdict": "prohibited_by_program" if stance["verdict"] == "banned"
                           else "verified_permitted",
                "checked_against": "_program-data/",
                "prohibition_lines": [f"{f}:{n}  {t}" for f, n, t in stance["banned"]],
                "mentions_for_review": [f"{f}:{n}  {t}" for f, n, t in stance["review"][:10]],
            },
            "identification_header": {"name": hname, "value": hvalue},
        },
        "curation": {"included": len(approved),
                     "excluded": [{"reason": k, "count": v} for k, v in sorted(excluded.items())],
                     # APPROVED techniques that cannot be RUN until something arrives. They are in
                     # the profile and stay there; this is the day-one answer to "what is locked and
                     # what would unlock the most". Getting the prerequisite NEVER needs a regenerate.
                     "gated_but_approved": [{"needs": k, "count": v}
                                            for k, v in sorted(gated.items(), key=lambda kv: -kv[1])]},
        "approved_ttps": approved,
        "approval": {"status": "PENDING_OPERATOR_REVIEW", "approved_by": None, "approved_at": None},
    }

    os.makedirs(os.path.join(d, ".scope_lock"), exist_ok=True)
    with open(approved_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(profile, fh, sort_keys=False, width=110, allow_unicode=True)

    enforcement = {"engagement": os.path.basename(engagement), "approved": False,
                   "source_scope_sha256": sha, "allowed_binaries": allowed,
                   "always_allowed_extra": [], "denied_patterns": denied,
                   "rate_ceiling": rate,
                   "assets": profile["assets"]}
    with open(os.path.join(d, ".scope_lock", "enforcement.json"), "w", encoding="utf-8") as fh:
        json.dump(enforcement, fh, indent=2)

    # The PLAN and COVERAGE ledger, seeded from the assets that were just compiled. Same reasoning
    # as ensure_ledger above and the same failure it prevents: the coverage matrix has been required
    # by global/CLAUDE.md 1B for weeks and a survey on 2026-08-02 found one in 3 of 15 engagements.
    # Created here because every engagement is scoped, so no engagement can start without somewhere
    # to record what has been exercised and where the thread was left.
    plan_made = ensure_plan(d, engagement)

    problems = self_check(engagement)
    return {"engagement": engagement, "cached": False, "ttps": len(approved),
            "plan_created": plan_made,
            "excluded": profile["curation"]["excluded"], "binaries": len(allowed),
            "denied_patterns": len(denied), "manual_only": manual_only,
            "automation_review": [f"{f}:{n}  {t}" for f, n, t in stance["review"][:10]],
            "self_check": "PASS" if not problems else problems}


# ---------------------------------------------------------------- Step 3c self-check
def self_check(engagement):
    """Every consistency rule the skill demands, as code. Returns [] when the artifacts are sound."""
    d = eng_dir(engagement)
    problems = []
    try:
        prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
        enf = json.load(open(os.path.join(d, ".scope_lock", "enforcement.json"), encoding="utf-8"))
    except Exception as exc:                                   # noqa: BLE001
        return [f"artifacts unreadable: {exc}"]

    if prof.get("source_scope_sha256") != enf.get("source_scope_sha256"):
        problems.append("source_scope_sha256 differs between the two artifacts")

    used = set()
    for t in prof.get("approved_ttps", []):
        used |= set(t.get("binaries") or [])
    missing = used - set(enf.get("allowed_binaries", []))
    if missing:
        problems.append(f"binaries invoked by approved TTPs but not allow-listed: {sorted(missing)}")

    # Read defensively. A profile predating a schema change is missing keys, and an unhandled
    # KeyError here reads to the caller as "the checker is broken" rather than "the profile is
    # broken" — so nobody investigates, and the check is fail-open in effect. Three engagements
    # crashed this way on `automation` before this was written; the missing field is now
    # reported as the problem it is.
    oc = prof.get("operational_constraints") or {}

    if "automation" not in oc:
        problems.append("operational_constraints.automation is missing — the profile predates the "
                        "automation stance field and its scanner posture is unrecorded. Recompile "
                        "to establish it against the program text.")
    elif oc["automation"] == "manual_only":
        leaked = set(enf.get("allowed_binaries", [])) & SCANNERS
        if leaked:
            problems.append(f"manual-only program still allows scanners: {sorted(leaked)}")

    # constraints 3 and 4 must be visible IN the commands, which is the only thing carrying them
    hdr = oc.get("identification_header") or {}
    if not hdr.get("name"):
        problems.append("operational_constraints.identification_header.name is missing — the "
                        "attribution header cannot be checked against the commands.")
    hname = hdr.get("name") or ""
    no_hdr, no_rate, misplaced = [], [], []
    for t in prof.get("approved_ttps", []):
        for c in (t.get("commands") or []):
            binary = next((b for b in (t.get("binaries") or [])
                           if re.search(rf"(^|[\s|/]){re.escape(b)}\s", c)), None)
            if not binary:
                continue
            # Same splitter emission uses, so the two can never disagree.
            _seg, head = _command_segment(c, binary)

            if binary not in ("whois", "semgrep"):
                if hname not in c:
                    no_hdr.append(t["id"])
                elif hname not in head:
                    misplaced.append(t["id"])          # present in the string, attached to nothing
            if binary in RATE_FLAG:
                # Accept ANY spelling the tool honours, not just the long form we happen to
                # inject. `-rl 5` and `-rate-limit 5` are the same option; a check that only
                # recognises one reports a correctly-limited command as unlimited, which teaches
                # you to ignore the check. Same naivety the injector had — it is what let
                # `-rate-limit 5 … -rl 20` ship.
                if not _has_rate_flag(c, binary):
                    no_rate.append(t["id"])
                elif not _has_rate_flag(head, binary):
                    misplaced.append(t["id"])
    if misplaced:
        problems.append(f"{len(set(misplaced))} TTP(s) carry the header/rate flag AFTER a pipe or "
                        f"redirect, where it applies to the wrong process — present in the string "
                        f"but attached to nothing")
    if no_hdr:
        problems.append(f"{len(set(no_hdr))} TTP(s) emit a web command without the "
                        f"{hname} header (constraint 4 unenforced)")
    if no_rate:
        problems.append(f"{len(set(no_rate))} TTP(s) emit a command without a rate flag "
                        f"(constraint 3 unenforced)")

    # default=str because YAML silently parses an unquoted `2026-07-20` into a datetime.date,
    # which json.dumps refuses. The scan below only needs the profile flattened to text to look
    # for placeholder strings, so stringifying is exactly right — and without it the checker
    # crashes on any profile whose scope file mentioned a bare date, which is the checker
    # failing rather than the profile.
    blob = json.dumps(prof, default=str)
    if "ASK_OPERATOR" in blob:
        problems.append("ASK_OPERATOR placeholder still present (handle or test accounts unset)")
    return problems


# ---------------------------------------------------------------- approve
def approve(engagement, by):
    """The human checkpoint. Refuses on a failing self-check or an unresolved placeholder."""
    d = eng_dir(engagement)
    problems = self_check(engagement)
    blocking = [p for p in problems if "ASK_OPERATOR" not in p]
    if blocking:
        raise ScopeError("refusing to approve — self-check failed:\n  " + "\n  ".join(blocking))

    ap = os.path.join(d, "approved_TTPs.yaml")
    prof = yaml.safe_load(open(ap, encoding="utf-8"))
    prof["approval"] = {"status": "APPROVED", "approved_by": by,
                        "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with open(ap, "w", encoding="utf-8") as fh:
        yaml.safe_dump(prof, fh, sort_keys=False, width=110, allow_unicode=True)

    ep = os.path.join(d, ".scope_lock", "enforcement.json")
    enf = json.load(open(ep, encoding="utf-8"))
    enf["approved"] = True
    with open(ep, "w", encoding="utf-8") as fh:
        json.dump(enf, fh, indent=2)

    warn = [p for p in problems if "ASK_OPERATOR" in p]
    return {"engagement": engagement, "approved_by": by, "status": "APPROVED",
            "warnings": warn,
            "note": "Approved but NOT set active. Setting the active engagement is a separate, "
                    "deliberate step so approving several profiles cannot silently arm one."}


def show(engagement):
    d = eng_dir(engagement)
    prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
    enf = json.load(open(os.path.join(d, ".scope_lock", "enforcement.json"), encoding="utf-8"))
    oc = prof["operational_constraints"]
    return {"engagement": prof["engagement"], "approval": prof["approval"]["status"],
            "enforcement_approved": enf["approved"], "ttps": len(prof["approved_ttps"]),
            "hosts": len(prof["assets"]["hosts"]), "wildcards": prof["assets"]["wildcards"],
            "automation": oc["automation"], "rate_limit": oc["rate_limit"],
            "header": f'{oc["identification_header"]["name"]}: {oc["identification_header"]["value"]}',
            "test_accounts": oc["test_accounts"],
            "allowed_binaries": len(enf["allowed_binaries"]),
            "denied_patterns": len(enf["denied_patterns"]),
            "curation": prof.get("curation", {}).get("excluded", []),
            "self_check": self_check(engagement) or "PASS"}


#: Tools that never put a request on the TARGET, so an attribution header on them is meaningless.
#: Two distinct reasons, kept apart because they are different arguments:
#:   * OFFLINE — reads and rewrites local files, sends nothing at all.
#:   * ELSEWHERE — talks to a third party or to our own listener, never the program's estate.
#: Requiring the header here is worse than pointless: it would send the program's name to an
#: unrelated service, and a check that flags correct behaviour teaches you to ignore the check.
OFFLINE_TOOLS = {"gf", "qsreplace", "semgrep", "whois"}
ELSEWHERE_TOOLS = {"gau", "waybackurls", "interactsh-client"}
_URL_HOST_RX = re.compile(r"https?://([A-Za-z0-9.-]+)")
#: Flags that hand a tool something to aim at — a host, a URL, a domain, or a file of them.
_TARGET_INPUT_RX = re.compile(r"(^|\s)-{1,2}(l|u|d|i|list|url|urls|target|targets|host|domain)"
                              r"(\s|=)")


#: Flags that hand a tool something to aim at — a host, a URL, a domain, or a file of them.
_TARGET_INPUT_RX = re.compile(r"(^|\s)-{1,2}(l|u|d|i|list|url|urls|target|targets|host|domain)"
                              r"(\s|=)")


def _no_target_traffic(binary, command):
    """True when this command cannot reach the program's own assets.

    Conservative on purpose: a false positive here is a nuisance, a false NEGATIVE means traffic
    going out unattributed. So a command is only exempted when it is definitively not target-bound.
    """
    if binary in OFFLINE_TOOLS or binary in ELSEWHERE_TOOLS:
        return True
    hosts = _URL_HOST_RX.findall(command)
    if hosts:
        # Every URL points at a recon source (crt.sh and friends) rather than the program.
        return all(any(src in h for src in RECON_SOURCES) for h in hosts)
    # No URL anywhere. Only exempt when the tool was ALSO given no target input: `httpx -l
    # targets.txt` names no host here yet reaches every host in that file, while a tool's own
    # maintenance call (`nuclei -update-templates`) takes no target and talks to its own project.
    seg, _head = _command_segment(command, binary)
    return not _TARGET_INPUT_RX.search(seg or command)


def audit_headers():
    """Re-verify EVERY compiled engagement's attribution header. A standing check, not a one-off.

    `_enforce_identification_header` runs at compile time, which covers the moment a profile is
    built and nothing after it. A program can update its policy, a profile can predate the check,
    and a handle can be edited by hand — none of which recompiles anything. This walks every
    compiled engagement and re-asks the question, so "is the header right" is answerable now rather
    than as of whenever the profile happened to be built.

    Four things are checked per engagement, because the header can be wrong in four ways:
      1. NAME vs the program's own captured text — programs on one platform differ by a word.
      2. PLATFORM PREFIX in the value vs the engagement's own platform path — a value carrying the
         other platform's name is the copy-paste failure this is most likely to catch.
      3. HANDLE in the value vs `operator-identity.md` for that platform.
      4. Every emitted web command actually carrying the header, attached to the right process.

    Returns a list of problem dicts. Empty means every compiled engagement is attributed correctly.
    """
    problems = []
    identity = {}
    if os.path.isfile(IDENTITY):
        for line in open(IDENTITY, encoding="utf-8", errors="replace"):
            cells = [c.strip().strip("*` ") for c in line.split("|")]
            if len(cells) >= 4 and cells[1] and cells[2] and not set(cells[2]) <= set("-: "):
                identity[cells[1].lower()] = cells[2]

    for dirpath, dirnames, filenames in os.walk(ENG_ROOT):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if "approved_TTPs.yaml" not in filenames:
            continue
        rel = os.path.relpath(dirpath, ENG_ROOT)
        try:
            prof = yaml.safe_load(open(os.path.join(dirpath, "approved_TTPs.yaml"),
                                       encoding="utf-8")) or {}
        except Exception as exc:                                  # noqa: BLE001 - report, never raise
            problems.append({"engagement": rel, "problem": f"profile unreadable: {exc}"})
            continue

        hdr = ((prof.get("operational_constraints") or {}).get("identification_header") or {})
        name, value = hdr.get("name"), hdr.get("value")
        if not name or not value:
            problems.append({"engagement": rel,
                             "problem": "no identification header recorded in the profile"})
            continue

        # 1. Against the program's own words.
        try:
            det = detect_identification_header(rel)
            if det["found"] and not any(h.lower() == name.lower() for h in det["found"]):
                problems.append({"engagement": rel, "problem": "header NAME does not match the "
                                 "program's text", "configured": name,
                                 "program_asks_for": det["found"]})
        except ScopeError:
            pass                                                  # no captured text; §2 covers it

        # 2. The platform prefix must match the engagement's own platform directory.
        parts = rel.replace(os.sep, "/").split("/")
        platform = parts[1] if parts and parts[0] == "programs" and len(parts) > 1 else None
        if platform and platform.lower() not in value.lower().replace(" ", ""):
            other = "intigriti" if platform.lower() == "hackerone" else "hackerone"
            if other in value.lower():
                problems.append({"engagement": rel,
                                 "problem": "header VALUE names the WRONG platform",
                                 "value": value, "engagement_platform": platform})

        # 3. The handle must be the one on file for that platform.
        want = identity.get((platform or "").lower())
        if want and want not in value:
            problems.append({"engagement": rel, "problem": "handle does not match "
                             "operator-identity.md", "value": value, "expected_handle": want})
        if "ASK_OPERATOR" in value or "<" in value:
            problems.append({"engagement": rel, "problem": "placeholder handle still in the header",
                             "value": value})

        # 4. Every command that actually reaches the TARGET carries it, on the right process.
        for t in (prof.get("approved_ttps") or []):
            for c in (t.get("commands") or []):
                for binary in (t.get("binaries") or []):
                    if binary not in TOOL_BINARIES or _no_target_traffic(binary, c):
                        continue
                    if not re.search(rf"(^|[\s/`]){re.escape(binary)}\s", c):
                        continue
                    _seg, head = _command_segment(c, binary)
                    if name not in c:
                        problems.append({"engagement": rel, "problem": "web command emits NO "
                                         "attribution header", "ttp": t["id"], "binary": binary})
                    elif name not in head:
                        problems.append({"engagement": rel, "problem": "header lands after a pipe "
                                         "or redirect, attached to the wrong process",
                                         "ttp": t["id"], "binary": binary})
    return problems


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("audit-headers", help="re-verify the attribution header on EVERY engagement")
    for name in ("compile", "approve", "verify", "show"):
        s = sub.add_parser(name)
        s.add_argument("engagement")
        if name == "compile":
            s.add_argument("--update", action="store_true")
            s.add_argument("--config", required=True, help="JSON file of per-program scope facts")
        if name == "approve":
            s.add_argument("--by", required=True)
    a = p.parse_args(argv)
    if a.cmd == "audit-headers":
        found = audit_headers()
        print(json.dumps({"engagements_checked": "all compiled",
                          "problems": found}, indent=2))
        return 1 if found else 0
    try:
        if a.cmd == "compile":
            cfg = json.load(open(os.path.expanduser(a.config), encoding="utf-8"))
            out = compile_scope(a.engagement, cfg, update=a.update)
        elif a.cmd == "approve":
            out = approve(a.engagement, a.by)
        elif a.cmd == "verify":
            out = {"engagement": a.engagement, "self_check": self_check(a.engagement) or "PASS"}
        else:
            out = show(a.engagement)
    except ScopeError as exc:
        print(f"\n[!] {exc}\n", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
