#!/usr/bin/env python3
"""
test_scope_compiler.py — regression tests for scope generation.

Every check here corresponds to a bug that actually happened on 2026-07-25, in order:

  1. The procedure lived in prose, so a reimplementation dropped the per-TTP `commands:` block —
     the only thing carrying constraints 3 (rate limit) and 4 (identification header). The profile
     asserted both and enforced neither.
  2. Flags were appended to the END of the line, landing after pipes and redirects, so
     `curl … | jq . > out.json -H "X-Bug-Bounty: …"` passed a check that only asked "is the header
     in the string?". Present, and attached to nothing.
  3. Only the FIRST tool in a chained command got flagged, so `curl …; curl …` attributed one
     request and not the other.
  4. The self-check itself gave a false positive on `… > file && ffuf …` because it split on pipes
     but not on `&&`. A check that cries wolf gets ignored.

Isolated: temp engagement dirs, no network. Run: python3 test_scope_compiler.py
"""
import importlib.util
import json
import os
import shutil
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(HERE)
COMPILER = os.path.join(WORKSPACE, "global", "scope", "scope_compiler.py")

_PASS = _FAIL = 0


def chk(name, cond, extra=""):
    global _PASS, _FAIL
    ok = bool(cond)
    _PASS += ok
    _FAIL += not ok
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  -> " + str(extra)) if (extra and not ok) else ""))


def load_compiler():
    spec = importlib.util.spec_from_file_location("scope_compiler", COMPILER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SC = load_compiler()

BASE_CFG = {
    "hosts": ["app.example-target.com"],
    "wildcards": ["*.example-target.com"],
    "capabilities": ["web", "api", "dns"],
    "rate_limit": "<= 7 req/s", "rate_value": 7,
    "header": ["X-Bug-Bounty", "Testing-handle"],
    "program_rules": ["test program"],
    "out_of_scope": ["everything else"],
}


def temp_engagement(program_text="Program rules\n* Submit one vulnerability per report.\n"):
    """A throwaway engagement inside the real ENG_ROOT so the compiler's own paths apply.

    Ships a `_program-data/` directory by default. That is not scaffolding for its own sake:
    the compiler refuses to build a profile for an engagement whose automation stance cannot be
    established, so an engagement without captured program text is not a valid engagement. Pass
    `program_text` to plant specific policy language.
    """
    d = tempfile.mkdtemp(prefix="_scopetest-", dir=SC.ENG_ROOT)
    with open(os.path.join(d, "scope.md"), "w", encoding="utf-8") as fh:
        fh.write("# test scope\n" + ("in scope: app.example-target.com\n" * 30))
    os.makedirs(os.path.join(d, "_program-data"), exist_ok=True)
    with open(os.path.join(d, "_program-data", "info.txt"), "w", encoding="utf-8") as fh:
        fh.write(program_text)
    return os.path.basename(d), d


# =============================================================================
def test_pending_by_default():
    print("[compile] a fresh profile enforces nothing until approved")
    name, d = temp_engagement()
    try:
        SC.compile_scope(name, dict(BASE_CFG), update=True)
        import yaml
        prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
        enf = json.load(open(os.path.join(d, ".scope_lock", "enforcement.json"), encoding="utf-8"))
        chk("approval.status is PENDING", prof["approval"]["status"] == "PENDING_OPERATOR_REVIEW")
        chk("enforcement.approved is False", enf["approved"] is False)
        chk("approved_by is unset", prof["approval"]["approved_by"] is None)
        chk("the profile has TTPs", len(prof["approved_ttps"]) > 50, len(prof["approved_ttps"]))
        chk("scope hash matches across both artifacts",
            prof["source_scope_sha256"] == enf["source_scope_sha256"])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_constraints_are_carried_not_asserted():
    """Bugs 1 and 2: the flags must exist AND be attached to the tool they govern."""
    print("[compile] constraints 3 + 4 land on the right sub-command")
    name, d = temp_engagement()
    try:
        SC.compile_scope(name, dict(BASE_CFG), update=True)
        import yaml
        prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
        with_cmds = [t for t in prof["approved_ttps"] if t.get("commands")]
        chk("TTPs carry command strings at all", len(with_cmds) > 30, len(with_cmds))

        import re
        after_redirect = []
        for t in with_cmds:
            for c in t["commands"]:
                for b in (t.get("binaries") or []):
                    if not re.search(rf"(^|[\s|/`]){re.escape(b)}\s", c):
                        continue
                    seg, head = SC._command_segment(c, b)
                    if "X-Bug-Bounty" in c and b not in ("whois", "semgrep") \
                            and "X-Bug-Bounty" not in head:
                        after_redirect.append(t["id"])
        chk("no flag sits after a pipe or redirect", not after_redirect,
            sorted(set(after_redirect))[:4])
        chk("the compiler's own self-check agrees",
            [p for p in SC.self_check(name) if "ASK_OPERATOR" not in p] == [],
            SC.self_check(name))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_every_tool_in_a_chain_is_flagged():
    """Bug 3: a chained command must attribute EVERY request, not just the first."""
    print("[compile] chained commands flag every tool, not only the first")
    cfg = dict(BASE_CFG)
    line = 'curl -s "https://a/x" -o t.txt; curl -s "https://a/y" -o f.txt; diff t.txt f.txt'
    out = SC._inject_all(line, ["curl"], cfg)
    chk("both curls carry the header", out.count("X-Bug-Bounty") == 2, out)
    chk("the separator survives intact", "; curl" in out or ";curl" in out, out)

    line2 = 'katana -u https://a -silent | gau a | sort -u > w.txt && ffuf -w w.txt -u https://a/FUZZ'
    out2 = SC._inject_all(line2, ["katana", "gau", "ffuf"], cfg)
    for tool in ("katana", "gau", "ffuf"):
        seg, head = SC._command_segment(out2, tool)
        chk(f"{tool} is attributed in its own segment", "X-Bug-Bounty" in head, head[:70])
    chk("the && separator kept its spacing", "&&ffuf" not in out2, out2[-60:])
    chk("rate flags respect the program value",
        "-rate 7" in out2 or "-rate-limit 7" in out2, out2[:120])


def test_self_check_does_not_cry_wolf():
    """Bug 4: `> file && tool` is correct; a splitter that ignores && called it broken."""
    print("[verify] the self-check understands &&, ; and || — no false positives")
    line = 'sort -u > custom.txt && ffuf -H "X-Bug-Bounty: h" -w custom.txt -u https://a/FUZZ -rate 7'
    seg, head = SC._command_segment(line, "ffuf")
    chk("finds the ffuf segment after a redirect+&&", "ffuf" in seg, seg[:60])
    chk("and sees the header in its head", "X-Bug-Bounty" in head, head[:60])

    piped = 'curl -H "X-Bug-Bounty: h" -s https://a | jq .'
    _s, h = SC._command_segment(piped, "curl")
    chk("a piped command is judged on the curl segment", "X-Bug-Bounty" in h)


def test_manual_only_excludes_scanners():
    print("[compile] a manual-only program cannot run a scanner")
    name, d = temp_engagement()
    try:
        cfg = dict(BASE_CFG); cfg["manual_only"] = True
        res = SC.compile_scope(name, cfg, update=True)
        enf = json.load(open(os.path.join(d, ".scope_lock", "enforcement.json"), encoding="utf-8"))
        leaked = set(enf["allowed_binaries"]) & SC.SCANNERS
        chk("no scanner is allow-listed", not leaked, sorted(leaked))
        denied = " ".join(enf["denied_patterns"])
        chk("scanners are also in denied_patterns",
            all(b in denied for b in ("nuclei", "ffuf", "sqlmap")), denied[:100])
        chk("curation reports the exclusion",
            any("manual-only" in x["reason"] for x in res["excluded"]), res["excluded"])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_permanent_constraints_always_present():
    print("[compile] the four permanent constraints are not optional")
    name, d = temp_engagement()
    try:
        SC.compile_scope(name, dict(BASE_CFG), update=True)
        import yaml
        prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
        oc = prof["operational_constraints"]
        chk("social engineering forbidden", oc["social_engineering"] == "forbidden")
        chk("cross-account is test-accounts-only", oc["cross_account_testing"] == "test_accounts_only")
        chk("DoS banned", oc["dos"] == "banned")
        chk("rate limit recorded", "7" in str(oc["rate_limit"]))
        chk("ID header recorded", oc["identification_header"]["name"] == "X-Bug-Bounty")
        enf = json.load(open(os.path.join(d, ".scope_lock", "enforcement.json"), encoding="utf-8"))
        denied = " ".join(enf["denied_patterns"])
        for pat in ("hping3", "slowloris", "hydra", "torsocks", "--os-shell"):
            chk(f"deny-list mirrors the floor: {pat}", pat in denied)
        chk("locked / program_approval techniques are never auto-included",
            all("program_approval" not in str(t) for t in prof["approved_ttps"]))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_approve_is_the_gate():
    print("[approve] approval is the checkpoint, and it refuses broken artifacts")
    name, d = temp_engagement()
    try:
        SC.compile_scope(name, dict(BASE_CFG), update=True)
        # corrupt the artifacts so the self-check must fail
        enf_path = os.path.join(d, ".scope_lock", "enforcement.json")
        enf = json.load(open(enf_path, encoding="utf-8"))
        enf["source_scope_sha256"] = "0" * 64
        json.dump(enf, open(enf_path, "w", encoding="utf-8"), indent=2)
        try:
            SC.approve(name, "tester")
            chk("refuses to approve when the self-check fails", False, "approved anyway")
        except SC.ScopeError:
            chk("refuses to approve when the self-check fails", True)

        SC.compile_scope(name, dict(BASE_CFG), update=True)          # restore
        res = SC.approve(name, "tester")
        import yaml
        prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
        enf = json.load(open(enf_path, encoding="utf-8"))
        chk("approval records who and when", prof["approval"]["approved_by"] == "tester"
            and prof["approval"]["approved_at"])
        chk("enforcement flips to approved", enf["approved"] is True)
        chk("ASK_OPERATOR is surfaced as a warning, not silently ignored",
            any("ASK_OPERATOR" in w for w in res["warnings"]), res["warnings"])

        active = open(SC.STATE, encoding="utf-8").read().strip() if os.path.isfile(SC.STATE) else ""
        chk("approving does NOT set the engagement active", name not in active, active)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_caching():
    print("[compile] unchanged scope is cached; --update forces a rebuild")
    name, d = temp_engagement()
    try:
        SC.compile_scope(name, dict(BASE_CFG), update=True)
        again = SC.compile_scope(name, dict(BASE_CFG), update=False)
        chk("second compile is served from cache", again.get("cached") is True, again)
        forced = SC.compile_scope(name, dict(BASE_CFG), update=True)
        chk("--update rebuilds", forced.get("cached") is False, forced)

        with open(os.path.join(d, "scope.md"), "a", encoding="utf-8") as fh:
            fh.write("\nnew asset: another.example-target.com\n")
        changed = SC.compile_scope(name, dict(BASE_CFG), update=False)
        chk("a changed scope invalidates the cache", changed.get("cached") is False, changed)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_automation_stance_is_read_from_the_program_not_the_config():
    """The compiler must not take the caller's word for whether scanners are allowed.

    A program page said it could not accept submissions found by using automatic scanners. That
    sentence sat in the captured program data and never reached scope.md, so the compiled lock
    allowed sqlmap, nuclei, ffuf, feroxbuster, katana, gobuster, dalfox and amass. A sibling
    engagement carried the identical sentence and enforced it correctly. The difference was which
    session compiled it — which means it was enforced by memory, not by code.
    """
    print("[automation] a program that bans scanners cannot be compiled scanner-enabled")
    BANS = ("Program rules\n"
            "* Please do not use automatic scanners - be creative and do it yourself!\n"
            "* We cannot accept any submissions found by using automatic scanners.\n")

    # 1. The real defect: banned program + scanner-enabled request.
    name, d = temp_engagement(program_text=BANS)
    try:
        try:
            SC.compile_scope(name, dict(BASE_CFG))
            chk("REFUSES a scanner profile on a scanner-banning program", False, "it compiled")
        except SC.AutomationStanceError as exc:
            chk("REFUSES a scanner profile on a scanner-banning program", True)
            chk("the refusal quotes the program's own words",
                "automatic scanners" in str(exc), str(exc)[:200])
        chk("nothing was written on refusal",
            not os.path.isfile(os.path.join(d, "approved_TTPs.yaml")))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # 2. Same program, manual_only requested — permitted, and the evidence is recorded.
    name, d = temp_engagement(program_text=BANS)
    try:
        cfg = dict(BASE_CFG); cfg["manual_only"] = True
        res = SC.compile_scope(name, cfg)
        chk("the same program compiles fine as manual-only", res.get("cached") is False, res)
        prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
        ev = prof["operational_constraints"]["automation_evidence"]
        chk("the lock records WHY it is manual-only",
            ev["verdict"] == "prohibited_by_program", ev)
        chk("the lock cites the source line", any("automatic scanners" in l
            for l in ev["prohibition_lines"]), ev["prohibition_lines"])
        lock = json.load(open(os.path.join(d, ".scope_lock", "enforcement.json")))
        leaked = SC.SCANNERS & set(lock["allowed_binaries"])
        chk("no scanner reaches the enforcement lock", not leaked, sorted(leaked))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # 3. Negative control — a program that says nothing about scanners is NOT blocked.
    #    Without this, the test passes just as well if the gate refuses everything.
    name, d = temp_engagement()
    try:
        res = SC.compile_scope(name, dict(BASE_CFG))
        chk("a silent program is NOT blocked", res.get("cached") is False, res)
        prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
        chk("and is recorded as verified-permitted",
            prof["operational_constraints"]["automation_evidence"]["verdict"]
            == "verified_permitted")
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # 4. Unverifiable must not read as fine. An engagement with no captured program text has no
    #    establishable stance, and silence is the failure mode this whole gate exists to stop.
    d = tempfile.mkdtemp(prefix="_scopetest-", dir=SC.ENG_ROOT)
    try:
        with open(os.path.join(d, "scope.md"), "w", encoding="utf-8") as fh:
            fh.write("# test scope\n" + ("in scope: app.example-target.com\n" * 30))
        try:
            SC.compile_scope(os.path.basename(d), dict(BASE_CFG))
            chk("REFUSES when there is no program text to check against", False, "it compiled")
        except SC.AutomationStanceError:
            chk("REFUSES when there is no program text to check against", True)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_automation_stance_is_not_derived_from_the_lock():
    """Derive manual-only from the program rules, never from the compiled lock.

    A previous attempt inferred it from the lock's deny-list and wrongly stripped 23 scanner TTPs
    from a program that explicitly permits automated scanning. The lock is downstream
    of the decision; reading it to decide what the lock should say is circular, and the error is
    silent — an over-restricted profile still compiles and still looks correct.
    """
    print("[automation] the stance comes from program text, not from a prior lock")
    name, d = temp_engagement(
        program_text="Program rules\n* Automated scanning is permitted at <= 5 req/s.\n")
    try:
        # Compile manual-only first, so a deny-list full of scanners exists on disk.
        cfg = dict(BASE_CFG); cfg["manual_only"] = True
        SC.compile_scope(name, cfg)
        lock = json.load(open(os.path.join(d, ".scope_lock", "enforcement.json")))
        chk("setup: the first lock does deny scanners",
            any("nuclei" in p for p in lock["denied_patterns"]))

        # Now recompile WITHOUT manual_only. If the stance were read from the lock, this would
        # be refused or silently stay manual-only. It must not be.
        res = SC.compile_scope(name, dict(BASE_CFG), update=True)
        chk("a prior manual-only lock does not force the next compile", res["manual_only"] is False,
            res)
        lock2 = json.load(open(os.path.join(d, ".scope_lock", "enforcement.json")))
        chk("scanners are restored for a program that permits them",
            bool(SC.SCANNERS & set(lock2["allowed_binaries"])),
            sorted(SC.SCANNERS & set(lock2["allowed_binaries"])))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    for t in (test_pending_by_default, test_constraints_are_carried_not_asserted,
              test_every_tool_in_a_chain_is_flagged, test_self_check_does_not_cry_wolf,
              test_manual_only_excludes_scanners, test_permanent_constraints_always_present,
              test_automation_stance_is_read_from_the_program_not_the_config,
              test_automation_stance_is_not_derived_from_the_lock,
              test_approve_is_the_gate, test_caching):
        t()
    print(f"\n{_PASS}/{_PASS + _FAIL} passed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
