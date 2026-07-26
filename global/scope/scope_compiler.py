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
FRAMEWORK = os.path.expanduser(os.environ.get(
    "OPSEC_TTP_LIBRARY",
    "~/Workspace/Production_Ready/public/Offensive_Security/bug-bounty-execution-framework/ttps"))
if not os.path.isdir(FRAMEWORK):
    raise SystemExit(f"scope_compiler.py: TTP library not found at {FRAMEWORK} "
                     f"(set OPSEC_TTP_LIBRARY to override)")

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
                                     + " ".join(cmds)).lower()})
    return out


def relevant(task, caps, manual_only):
    """Step 2b curation — is this technique appropriate to THIS program's assets and rules?"""
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


def _command_segment(line, binary):
    """The sub-command that actually runs `binary`, and the part of it before any redirect."""
    for seg in _SEPARATORS.split(line):
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
    parts = _SPLIT_KEEP.split(line)
    for idx in range(0, len(parts), 2):                 # even indices are command segments
        seg = parts[idx]
        binary = next((b for b in task_binaries
                       if re.search(rf"(^|[\s/`]){re.escape(b)}\s", seg)), None)
        if not binary or binary in ("whois", "semgrep"):
            continue
        head = re.split(r"\s(?:\d?>>?|>)\s", seg)[0]
        additions = []
        if binary in RATE_FLAG:
            flag = RATE_FLAG[binary].format(r=rate)
            if flag.split()[0] not in head:
                additions += flag.split()
        if hname not in head:
            additions += ["-H", f'"{hname}: {hvalue}"']
        if additions:
            parts[idx] = _inject(seg, binary, additions)
    return "".join(parts)


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
def compile_scope(engagement, cfg, update=False):
    d = eng_dir(engagement)
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

    approved, excluded = [], {}
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
            "identification_header": {"name": hname, "value": hvalue},
        },
        "curation": {"included": len(approved),
                     "excluded": [{"reason": k, "count": v} for k, v in sorted(excluded.items())]},
        "approved_ttps": approved,
        "approval": {"status": "PENDING_OPERATOR_REVIEW", "approved_by": None, "approved_at": None},
    }

    os.makedirs(os.path.join(d, ".scope_lock"), exist_ok=True)
    with open(approved_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(profile, fh, sort_keys=False, width=110, allow_unicode=True)

    enforcement = {"engagement": os.path.basename(engagement), "approved": False,
                   "source_scope_sha256": sha, "allowed_binaries": allowed,
                   "always_allowed_extra": [], "denied_patterns": denied,
                   "assets": profile["assets"]}
    with open(os.path.join(d, ".scope_lock", "enforcement.json"), "w", encoding="utf-8") as fh:
        json.dump(enforcement, fh, indent=2)

    problems = self_check(engagement)
    return {"engagement": engagement, "cached": False, "ttps": len(approved),
            "excluded": profile["curation"]["excluded"], "binaries": len(allowed),
            "denied_patterns": len(denied), "manual_only": manual_only,
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

    if prof["operational_constraints"]["automation"] == "manual_only":
        leaked = set(enf.get("allowed_binaries", [])) & SCANNERS
        if leaked:
            problems.append(f"manual-only program still allows scanners: {sorted(leaked)}")

    # constraints 3 and 4 must be visible IN the commands, which is the only thing carrying them
    hname = prof["operational_constraints"]["identification_header"]["name"]
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
                flag = RATE_FLAG[binary].format(r=1).split()[0]
                if flag not in c:
                    no_rate.append(t["id"])
                elif flag not in head:
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

    blob = json.dumps(prof)
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


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("compile", "approve", "verify", "show"):
        s = sub.add_parser(name)
        s.add_argument("engagement")
        if name == "compile":
            s.add_argument("--update", action="store_true")
            s.add_argument("--config", required=True, help="JSON file of per-program scope facts")
        if name == "approve":
            s.add_argument("--by", required=True)
    a = p.parse_args(argv)
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
