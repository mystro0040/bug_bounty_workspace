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
import re
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

    Exact's page says "We cannot accept any submissions found by using automatic scanners."
    That sentence sat in _program-data/ and never reached scope.md, so the compiled lock allowed
    sqlmap, nuclei, ffuf, feroxbuster, katana, gobuster, dalfox and amass. The sibling Intigriti
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
    from CLEAR, which explicitly permits automated scanning at <= 5 req/s. The lock is downstream
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


def test_program_rate_ceiling_beats_the_library():
    """The program's rate limit must win over whatever the TTP library hardcoded.

    It didn't, in two different ways, and both shipped:

      dnsx  — RATE_FLAG is "-rate-limit"; the library line carried "-rl 20". The long form was
              absent so the injector added "-rate-limit 5", producing
              `dnsx -rate-limit 5 … -rl 20`. The LATER flag wins at the CLI, so the effective
              rate was 20 under a profile documenting 5.
      httpx — the line already had "-rate-limit 20", the injector saw a rate flag and skipped,
              and 20 stood.

    Thirty commands per engagement were running at 10–30 req/s against live programs. The
    profile said 5 the whole time. Found by diffing the documented ceiling against the emitted
    commands rather than by reading either.
    """
    print("[rate] the program ceiling is enforced in the command, not just documented")
    cfg = dict(BASE_CFG); cfg["rate_value"] = 5

    # 1. Every alias and spelling gets clamped, including the short forms.
    for line, binary, flag in (
            ('dnsx -d a.com -rl 20 -silent', 'dnsx', '-rl 20'),
            ('httpx -l h.txt -rate-limit 20 -silent', 'httpx', '-rate-limit 20'),
            ('katana -list t.txt -rate-limit 15', 'katana', '-rate-limit 15'),
            ('nuclei -l t.txt -rl 30 -c 10', 'nuclei', '-rl 30'),
            ('ffuf -u https://a/FUZZ -w w.txt -rate 30', 'ffuf', '-rate 30'),
            ('ffuf -u https://a/FUZZ -w w.txt -rate-limit 30', 'ffuf', '-rate-limit 30'),
            ('arjun -u https://a/e --rate-limit 20', 'arjun', '--rate-limit 20'),
    ):
        out = SC._inject_all(line, [binary], cfg)
        rates = [int(m.group(1)) for m in re.finditer(r"--?(?:rate-limit|rate|rl)[\s=]+(\d+)", out)]
        chk(f"{binary}: `{flag}` clamped to <= 5", rates and max(rates) <= 5, (rates, out))

    # 2. No duplicate rate flag — the original bug produced two, and the later one won.
    out = SC._inject_all('dnsx -d a.com -rl 20 -silent', ['dnsx'], cfg)
    chk("no duplicate rate flag is emitted",
        len(re.findall(r"--?(?:rate-limit|rl)[\s=]+\d+", out)) == 1, out)

    # 3. A library value ALREADY gentler than the ceiling must not be raised to it.
    out = SC._inject_all('dnsx -d a.com -rl 2 -silent', ['dnsx'], cfg)
    chk("a gentler library rate is left alone, not raised", "-rl 2" in out, out)

    # 4. --delay is a PAUSE, not a rate. Clamping it down would speed the tool UP.
    for line, binary in (('gobuster dir -u https://a -w w.txt --delay 50ms', 'gobuster'),
                         ('dalfox url https://a --delay 100', 'dalfox'),
                         ('sqlmap -u https://a?x=1 --delay 2', 'sqlmap')):
        out = SC._inject_all(line, [binary], cfg)
        original = re.search(r"--delay\s+(\S+)", line).group(1)
        chk(f"{binary}: --delay {original} is preserved, not clamped",
            f"--delay {original}" in out, out)

    # 5. A command with no rate flag still gets one.
    out = SC._inject_all('httpx -l h.txt -silent', ['httpx'], cfg)
    chk("a missing rate flag is injected", "-rate-limit 5" in out, out)

    # 6. End to end: compile a real profile and assert nothing exceeds the ceiling. This is the
    #    check that would have caught the original bug; the unit checks above only pin the fix.
    name, d = temp_engagement()
    try:
        SC.compile_scope(name, cfg, update=True)
        prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
        over = [(t["id"], m.group(0))
                for t in prof["approved_ttps"] for c in (t.get("commands") or [])
                for m in re.finditer(r"--?(?:rate-limit|rate|rl)[\s=]+(\d+)", c)
                if int(m.group(1)) > 5]
        chk("NO emitted command exceeds the program ceiling", not over, over[:3])
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_access_state_is_never_a_curation_input():
    """Scope comes from what the PROGRAM permits, never from what we can reach today.

    The failure this guards against is subtle and expensive: filtering out the techniques we
    cannot run yet looks tidy, and it means every credential that arrives later forces a
    regenerate — a fresh approval, a recompiled wall, and a chance to lose hand-added entries.
    """
    print("[curation] techniques we cannot run YET are still approved")
    name, d = temp_engagement()
    try:
        SC.compile_scope(name, dict(BASE_CFG), update=True)
        import yaml
        prof = yaml.safe_load(open(os.path.join(d, "approved_TTPs.yaml"), encoding="utf-8"))
        reasons = " ".join(e["reason"] for e in prof["curation"]["excluded"]).lower()
        for word in ("auth", "account", "credential", "session", "listener"):
            chk("nothing excluded for lacking '%s'" % word, word not in reasons, reasons)

        ids = {t["id"] for t in prof["approved_ttps"]}
        for gated_id in ("idor-single-cross-read", "reconcile-identifier-spaces-first",
                         "jwt-alg-none-and-tamper"):
            chk("%s is approved despite needing a login" % gated_id, gated_id in ids)

        gates = {g["needs"]: g["count"] for g in prof["curation"]["gated_but_approved"]}
        chk("the gate is RECORDED so the blocker is visible on day one",
            gates.get("authenticated_session", 0) > 0 or gates.get("two_test_accounts", 0) > 0,
            gates)

        annotated = [t for t in prof["approved_ttps"] if t.get("gated_by")]
        chk("gated entries carry their prerequisite inline", annotated, len(annotated))
        chk("a read-only disclosure technique is NOT tagged as needing a login",
            all("authenticated_session" not in (t.get("gated_by") or [])
                for t in prof["approved_ttps"]
                if t["id"] == "decode-load-balancer-persistence-cookie"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_every_engagement_gets_a_ledger():
    """The discovery-to-master loop starts here, and it must not depend on anyone remembering."""
    print("[loop] compiling scope creates the breakthrough ledger")
    name, d = temp_engagement()
    ledger = os.path.join(d, "BREAKTHROUGH_LEDGER.md")
    try:
        chk("no ledger before compiling", not os.path.exists(ledger))
        SC.compile_scope(name, dict(BASE_CFG), update=True)
        chk("the ledger exists after compiling", os.path.exists(ledger))
        body = open(ledger, encoding="utf-8").read()
        chk("it tells the reader how to settle an entry",
            "NOT-A-LIBRARY-ITEM" in body and "backticks" in body)

        # An existing ledger is never clobbered — it is append-only and holds real work.
        with open(ledger, "a", encoding="utf-8") as fh:
            fh.write("\n## sentinel entry\n")
        SC.compile_scope(name, dict(BASE_CFG), update=True)
        chk("a second compile does NOT overwrite it",
            "sentinel entry" in open(ledger, encoding="utf-8").read())
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_separator_inside_a_payload_is_not_a_new_command():
    """A command-injection proof carries `;` or `|` INSIDE its payload. Splitting on it cuts the
    command in half, so the header that follows looks attached to a different process — which is
    how a correct lab profile got flagged as broken."""
    print("[parse] shell separators inside quotes are part of the argument, not a new command")
    cmd = ('curl -s "http://127.0.0.1:8000/lab/" --data-urlencode "host=127.0.0.1; id" '
           '-H "X-Bug-Bounty: HackerOne-mystro0040"')
    seg, head = SC._command_segment(cmd, "curl")
    chk("the whole command is one segment", "--data-urlencode" in seg and "-H" in seg, seg[:90])
    chk("the header is seen as attached to curl", "X-Bug-Bounty" in head, head[:90])

    piped = 'curl -s "https://h/?x=a|b" | jq .'
    seg2, head2 = SC._command_segment(piped, "curl")
    chk("a pipe inside a quoted value does not split", "?x=a|b" in seg2, seg2[:90])
    chk("but a REAL pipe still ends the segment", "jq" not in head2, head2[:90])

    joined = "".join(SC._split_outside_quotes(cmd, keep=True))
    chk("keep=True rejoins byte-identically", joined == cmd, joined[:90])

    # CONTROL: real separators outside quotes must still split, or _inject_all would stop
    # flagging the second tool in a chain — the exact bug the splitter was built to fix.
    parts = [p for p in SC._split_outside_quotes("katana -u https://h | gau h && ffuf -u https://h")
             if p.strip()]
    chk("CONTROL: three chained tools still split into three", len(parts) == 3, parts)


def _header_engagement(platform, header_name, header_value, ttps, program_text="Program rules\n"):
    """A minimal compiled-looking engagement, planted under the given platform directory.

    audit_headers() reads profiles off disk rather than compiling, which is the point — it has to
    catch a profile that is stale, hand-edited, or older than the compile-time check.
    """
    base = os.path.join(SC.ENG_ROOT, "programs", platform)
    os.makedirs(base, exist_ok=True)
    d = tempfile.mkdtemp(prefix="_hdrtest-", dir=base)
    os.makedirs(os.path.join(d, "_program-data"), exist_ok=True)
    with open(os.path.join(d, "_program-data", "info.txt"), "w", encoding="utf-8") as fh:
        fh.write(program_text)
    with open(os.path.join(d, "scope.md"), "w", encoding="utf-8") as fh:
        fh.write("in scope: app.example-target.com\n")
    prof = {
        "engagement": os.path.basename(d),
        "operational_constraints": {"identification_header": {"name": header_name,
                                                              "value": header_value}},
        "approved_ttps": ttps,
    }
    import yaml
    with open(os.path.join(d, "approved_TTPs.yaml"), "w", encoding="utf-8") as fh:
        yaml.safe_dump(prof, fh, sort_keys=False)
    rel = os.path.relpath(d, SC.ENG_ROOT)
    return rel, d


def _mine(rel):
    return [p for p in SC.audit_headers() if p["engagement"] == rel]


def test_header_audit_catches_a_wrong_header():
    """The check must FAIL on a bad profile. A clean run proves nothing otherwise."""
    print("[headers] the audit catches every way the header goes wrong")
    made = []
    try:
        # Wrong platform in the value — the copy-paste failure between two live engagements.
        rel, d = _header_engagement("hackerone/bounty", "X-Bug-Bounty",
                                    "Intigriti-mystro00040", [])
        made.append(d)
        probs = _mine(rel)
        chk("a HackerOne engagement carrying an Intigriti value is caught",
            any("WRONG platform" in p["problem"] for p in probs), probs)

        # Placeholder handle.
        rel, d = _header_engagement("hackerone/bounty", "X-Bug-Bounty", "HackerOne-ASK_OPERATOR", [])
        made.append(d)
        chk("a placeholder handle is caught",
            any("placeholder" in p["problem"] for p in probs2)
            if (probs2 := _mine(rel)) else False, _mine(rel))

        # Header NAME contradicting the program's own captured words.
        rel, d = _header_engagement(
            "hackerone/bounty", "X-Bug-Bounty", "HackerOne-mystro0040", [],
            program_text="All traffic must carry the X-HackerOne-Research header.\n")
        made.append(d)
        probs = _mine(rel)
        chk("a name the program does not ask for is caught",
            any("NAME does not match" in p["problem"] for p in probs), probs)

        # A target-bound command with no header at all.
        rel, d = _header_engagement(
            "hackerone/bounty", "X-Bug-Bounty", "HackerOne-mystro0040",
            [{"id": "t1", "binaries": ["curl"],
              "commands": ["curl -s https://app.example-target.com/"]}])
        made.append(d)
        probs = _mine(rel)
        chk("an unattributed request to the target is caught",
            any("NO attribution header" in p["problem"] for p in probs), probs)

        # Present in the string but attached to the wrong process.
        rel, d = _header_engagement(
            "hackerone/bounty", "X-Bug-Bounty", "HackerOne-mystro0040",
            [{"id": "t2", "binaries": ["curl"],
              "commands": ['curl -s https://app.example-target.com/ | jq . '
                           '> o.json -H "X-Bug-Bounty: HackerOne-mystro0040"']}])
        made.append(d)
        probs = _mine(rel)
        chk("a header landing after a redirect is caught",
            any("wrong process" in p["problem"] for p in probs), probs)
    finally:
        for d in made:
            shutil.rmtree(d, ignore_errors=True)


def test_header_audit_does_not_cry_wolf():
    """Controls. Flagging correct behaviour is how a check gets ignored."""
    print("[headers] traffic that never reaches the target is NOT flagged")
    made = []
    try:
        good = "HackerOne-mystro0040"
        for label, ttp in (
            ("a recon-source lookup",
             {"id": "r1", "binaries": ["curl"],
              "commands": ['curl -s "https://crt.sh/?q=%25.example-target.com&output=json"']}),
            ("an offline local tool",
             {"id": "r2", "binaries": ["gf"], "commands": ["cat urls.txt | gf ssrf | sort -u"]}),
            ("a third-party archive source",
             {"id": "r3", "binaries": ["gau"], "commands": ["gau --subs example-target.com"]}),
            ("our own out-of-band listener",
             {"id": "r4", "binaries": ["interactsh-client"], "commands": ["interactsh-client -v"]}),
            ("a tool updating its own templates",
             {"id": "r5", "binaries": ["nuclei"], "commands": ["nuclei -update-templates"]}),
        ):
            rel, d = _header_engagement("hackerone/bounty", "X-Bug-Bounty", good, [ttp])
            made.append(d)
            probs = [p for p in _mine(rel) if "header" in p["problem"]]
            chk("%s is not flagged" % label, not probs, probs)

        # And the positive control: a REAL target request in the same shape IS still required to
        # carry it, so the exemptions above narrowed the check rather than gutting it.
        rel, d = _header_engagement(
            "hackerone/bounty", "X-Bug-Bounty", good,
            [{"id": "r6", "binaries": ["curl"],
              "commands": ['curl -s "https://app.example-target.com/?q=1"']}])
        made.append(d)
        chk("CONTROL: a real target request with no header is still caught",
            any("NO attribution header" in p["problem"] for p in _mine(rel)), _mine(rel))
    finally:
        for d in made:
            shutil.rmtree(d, ignore_errors=True)



def test_a_staging_machine_never_edits_the_master_library():
    """The role decides WHICH library is editable, which operator approval cannot do.

    Approval is the right gate for propagating: a human decides when work goes to the repos. It
    cannot be the gate for this, because from the agent's side nothing looks different — it is
    doing ordinary TTP work against a file that quietly changed underneath it when someone cloned
    the repo. So the machine's declared role picks the library, and a staging machine gets the
    bucket mirror even when the repo is sitting right there on disk.
    """
    print("[role] a staging machine resolves to the mirror even with the repo present")
    import importlib.util

    def probe(role_text, tmp):
        os.makedirs(os.path.join(tmp, "engagements"), exist_ok=True)
        os.makedirs(os.path.join(tmp, "global", "scope"), exist_ok=True)
        mirror = os.path.join(tmp, "framework", "ttps", "04_V")
        os.makedirs(mirror, exist_ok=True)
        open(os.path.join(mirror, "a.yaml"), "w").write("title: T\nsections: []\n")
        repo = os.path.join(tmp, "fake_repo_ttps", "04_V")
        os.makedirs(repo, exist_ok=True)
        open(os.path.join(repo, "a.yaml"), "w").write("title: T\nsections: []\n")
        role = os.path.join(tmp, "machine_role")
        if role_text is not None:
            open(role, "w").write(role_text)
        src = open(COMPILER, encoding="utf-8").read()
        src = src.replace(
            'open(os.path.expanduser("~/.config/offsec/machine_role"), encoding="utf-8")',
            f"open({role!r}, encoding='utf-8')")
        src = src.replace(
            'repo = ("~/Workspace/Production_Ready/public/Offensive_Security/"\n'
            '            "bug-bounty-execution-framework/ttps")',
            f"repo = {os.path.dirname(repo)!r}")
        dst = os.path.join(tmp, "global", "scope", "probe.py")
        open(dst, "w", encoding="utf-8").write(src)
        os.environ.pop("OPSEC_TTP_LIBRARY", None)
        spec = importlib.util.spec_from_file_location("sc_role", dst)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m.FRAMEWORK, os.path.dirname(repo), os.path.join(tmp, "framework", "ttps")

    for role, expect_repo, label in (("home\n", True, "a HOME machine uses the repo"),
                                     ("staging\n", False, "a STAGING machine uses the mirror"),
                                     (None, False, "an UNDECLARED machine uses the mirror")):
        d = tempfile.mkdtemp(prefix="_roleres-")
        try:
            got, repo, mirror = probe(role, d)
            chk(label + (" even with the repo on disk" if not expect_repo else ""),
                got == (repo if expect_repo else mirror), got)
        finally:
            shutil.rmtree(d, ignore_errors=True)


def main():
    for t in (test_pending_by_default, test_constraints_are_carried_not_asserted,
              test_a_separator_inside_a_payload_is_not_a_new_command,
              test_a_staging_machine_never_edits_the_master_library,
              test_header_audit_catches_a_wrong_header, test_header_audit_does_not_cry_wolf,
              test_access_state_is_never_a_curation_input, test_every_engagement_gets_a_ledger,
              test_program_rate_ceiling_beats_the_library,
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
