#!/usr/bin/env python3
"""The opsec check — one command that verifies the protections are actually on, before testing.

    python3 QUICK-ACCESS/opsec_check.py           # local checks only, no network
    python3 QUICK-ACCESS/opsec_check.py --net     # + connection guard (makes outbound requests)
    python3 QUICK-ACCESS/opsec_check.py --gate    # + the full opsec pre-engagement gate (slow)
    python3 QUICK-ACCESS/opsec_check.py --json    # machine-readable

WHY THIS EXISTS AS CODE. Every one of these checks already existed, scattered across five tools and
a paragraph of documentation. Scattered checks get run selectively, and the one you skip is the one
that was failing — the scope wall sat correct-but-UNREGISTERED for six days because nothing ever
asked "is it registered?" in the same breath as "is it correct?".

THREE DESIGN RULES, all of which cost something and are worth it:

1. **UNKNOWN is not PASS.** A check that cannot determine its answer reports UNKNOWN and the run
   does not come back clean. "Could not tell" is the state that hides real failures.
2. **Every check says what it examined.** A clean verdict with no evidence is indistinguishable from
   a check that silently did nothing.
3. **The wall is tested by USE, not by inspection.** Reading settings.json proves the hook is
   listed. Only feeding it a command it must deny proves it works.

Exit code 0 only when nothing FAILED and nothing was UNKNOWN.
"""

import json
import os
import platform
import shutil
import subprocess
import sys

BUCKET = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOME = os.path.expanduser("~")

OK, WARN, FAIL, UNKNOWN = "OK", "WARN", "FAIL", "UNKNOWN"

results = []


def record(name, state, detail, examined=""):
    results.append({"check": name, "state": state, "detail": detail, "examined": examined})


def run(cmd, timeout=60, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **kw)
    except Exception as exc:                                  # noqa: BLE001 - reported, not raised
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


# ---------------------------------------------------------------------------------------------
# 1. The scope wall — registered AND firing
# ---------------------------------------------------------------------------------------------

def check_wall_registered():
    path = os.path.join(HOME, ".claude", "settings.json")
    if not os.path.exists(path):
        return record("wall registered", FAIL, "no ~/.claude/settings.json — the hook cannot be "
                      "registered at all", path)
    try:
        cfg = json.load(open(path, encoding="utf-8"))
    except Exception as exc:                                  # noqa: BLE001
        return record("wall registered", FAIL, "settings.json is not valid JSON: %s" % exc, path)

    hooks = json.dumps(cfg.get("hooks", {}))
    if "enforce_scope" not in hooks:
        return record("wall registered", FAIL,
                      "enforce_scope.py is NOT in settings.json hooks — nothing is gating Bash",
                      path)
    extra = "" if "ram_guard" in hooks else "  (ram_guard is not registered)"
    record("wall registered", OK, "enforce_scope.py is a registered PreToolUse hook" + extra, path)


def check_wall_fires():
    """Registration is not enforcement. Hand the hook something it MUST deny and require a denial."""
    hook = os.path.join(BUCKET, ".claude", "hooks", "enforce_scope.py")
    if not os.path.exists(hook):
        return record("wall fires", FAIL, "hook file is missing", hook)

    probe = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": "curl -s https://definitely-not-in-any-scope.invalid/"},
        "cwd": BUCKET,
    })
    env = dict(os.environ, CLAUDE_PROJECT_DIR=BUCKET)
    env.pop("AO_REMOTE_DISPATCH", None)
    p = run([sys.executable, hook], input=probe, env=env)

    out = (p.stdout or "").strip()
    if not out:
        return record("wall fires", FAIL,
                      "an out-of-scope request was ALLOWED — the wall is not enforcing", hook)
    try:
        decision = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
    except Exception:                                         # noqa: BLE001
        return record("wall fires", UNKNOWN,
                      "the hook produced output that could not be parsed: %s" % out[:120], hook)
    if decision.lower() == "deny":
        return record("wall fires", OK,
                      "an out-of-scope request was DENIED (tested by use, not by inspection)", hook)
    record("wall fires", FAIL, "an out-of-scope request returned '%s', not deny" % decision, hook)


# ---------------------------------------------------------------------------------------------
# 2. Engagement posture
# ---------------------------------------------------------------------------------------------

def check_engagement():
    pinned = os.environ.get("AO_ENGAGEMENT")
    pointer = os.path.join(BUCKET, ".claude", "state", "active_engagement")
    src = "$AO_ENGAGEMENT" if pinned else pointer

    eng = pinned
    if not eng and os.path.exists(pointer):
        eng = open(pointer, encoding="utf-8").read().strip()
    if not eng:
        return record("engagement loaded", WARN,
                      "no engagement is selected — fine for framework work, not for testing", src)

    lock = os.path.join(BUCKET, "engagements", eng, ".scope_lock", "enforcement.json")
    if not os.path.exists(lock):
        return record("engagement loaded", FAIL,
                      "'%s' is selected but has NO compiled scope lock — locked down until "
                      "/generate-scope runs" % eng, lock)
    try:
        prof = json.load(open(lock, encoding="utf-8"))
    except Exception as exc:                                  # noqa: BLE001
        return record("engagement loaded", FAIL, "scope lock is unreadable: %s" % exc, lock)

    # assets is a DICT of categories, not a list. Counting the dict would count the six category
    # names and call it "6 in-scope assets" — a number that looks like evidence and is not.
    assets = prof.get("assets") or {}
    in_scope = sum(len(assets.get(k) or [])
                   for k in ("hosts", "wildcards", "cidrs", "ips", "endpoints"))
    binaries = prof.get("allowed_binaries") or []

    if not in_scope:
        return record("engagement loaded", FAIL,
                      "'%s' has a scope lock with NO in-scope assets — nothing is authorised" % eng,
                      lock)
    if str(prof.get("approved", "")).lower() not in ("true", "1", "yes"):
        return record("engagement loaded", WARN,
                      "'%s' scope lock is NOT approved — it enforces nothing until it is" % eng,
                      lock)

    rate = prof.get("rate_ceiling")
    rate_note = ", rate ceiling %s req/s" % rate if rate else ", NO rate ceiling recorded"
    record("engagement loaded", OK,
           "%s — %d in-scope assets, %d approved binaries%s" % (eng, in_scope, len(binaries),
                                                               rate_note), lock)


# ---------------------------------------------------------------------------------------------
# 3. Execution location — is testing traffic going to leave this machine?
# ---------------------------------------------------------------------------------------------

def check_execution_mode():
    sys.path.insert(0, os.path.join(BUCKET, "global"))
    try:
        from execution import settings as S                   # noqa: PLC0415 - optional dependency
    except Exception as exc:                                  # noqa: BLE001
        return record("execution location", UNKNOWN,
                      "could not load execution settings: %s" % exc,
                      os.path.join(BUCKET, "global", "execution", "settings.py"))
    try:
        mode = S.resolve_mode()
    except Exception as exc:                                  # noqa: BLE001
        return record("execution location", UNKNOWN, "resolve_mode() raised: %s" % exc, "settings.py")

    where = os.path.join(BUCKET, "global", "execution", "settings.py")
    if mode == "remote":
        return record("execution location", OK,
                      "resolves to REMOTE — network tools must be dispatched, nothing routes "
                      "automatically", where)
    if getattr(S, "raw_local_active", lambda: False)():
        return record("execution location", FAIL,
                      "RAW_LOCAL_ACK is ACTIVE — the global ISP rate cap is OFF", where)
    record("execution location", WARN,
           "resolves to '%s' — testing traffic would leave THIS machine" % mode, where)


def check_remote_artifacts():
    tool = os.path.join(BUCKET, "global", "execution", "remote_data.py")
    if not os.path.exists(tool):
        return record("remote artifacts", UNKNOWN, "remote_data.py not found", tool)
    p = run([sys.executable, tool, "status"], timeout=90)
    if p.returncode != 0 or not (p.stdout or "").strip():
        return record("remote artifacts", UNKNOWN,
                      "status did not return cleanly: %s" % (p.stderr or "")[:120], tool)
    try:
        d = json.loads(p.stdout)
    except Exception:                                         # noqa: BLE001
        return record("remote artifacts", UNKNOWN, "status output was not JSON", tool)

    outstanding = d.get("outstanding", 0)
    stranded = (d.get("by_status") or {}).get("stranded", 0)
    open_ssh = d.get("ssh_master_open")
    note = "; ssh master still open" if open_ssh else ""
    if stranded:
        return record("remote artifacts", FAIL,
                      "%d STRANDED artifact(s) left on the executor%s" % (stranded, note), tool)
    if outstanding:
        return record("remote artifacts", WARN,
                      "%d artifact(s) still on the executor%s" % (outstanding, note), tool)
    record("remote artifacts", OK, "nothing outstanding, nothing stranded" + note, tool)


# ---------------------------------------------------------------------------------------------
# 4. This machine — nothing scanning here, no key here
# ---------------------------------------------------------------------------------------------

RECON_TOOLS = ["dnsx", "httpx", "ffuf", "nuclei", "katana", "subfinder", "gobuster",
               "sqlmap", "feroxbuster", "masscan", "nmap", "amass", "puredns"]


def check_nothing_scanning_locally():
    if not shutil.which("pgrep"):
        return record("nothing scanning here", UNKNOWN,
                      "pgrep is unavailable on this platform (%s) — could not verify"
                      % platform.system(), "pgrep")
    running = []
    for tool in RECON_TOOLS:
        # -x exact-name so this cannot match its own command line (see GOTCHA-pgrep-matches-itself)
        if run(["pgrep", "-x", tool], timeout=10).returncode == 0:
            running.append(tool)
    examined = "%d tool names checked by exact process name" % len(RECON_TOOLS)
    if running:
        return record("nothing scanning here", FAIL,
                      "RUNNING LOCALLY: %s" % ", ".join(running), examined)
    record("nothing scanning here", OK, "no recon tool is running on this machine", examined)


def check_no_api_key_here():
    """The operator's own machine runs the subscription and must hold no Anthropic API key."""
    found = []
    if os.environ.get("ANTHROPIC_API_KEY"):
        found.append("ANTHROPIC_API_KEY is set in the environment")
    for path in ("/etc/ai-orchestrator/anthropic.env",
                 os.path.join(HOME, ".config", "ai-orchestrator", "anthropic.env")):
        if os.path.exists(path):
            found.append(path)
    runtime = os.path.join(HOME, "ai-orchestrator", "orchestrator", "api_runtime")
    if os.path.isdir(runtime):
        found.append("%s exists — the cloud-only module is present here" % runtime)

    examined = "env var + 2 key paths + the api_runtime module"
    if found:
        return record("no API key on this machine", FAIL,
                      "credential separation is broken: " + "; ".join(found), examined)
    record("no API key on this machine", OK,
           "no API key, no key file, no api_runtime — subscription side is clean", examined)


def check_ram():
    try:
        info = {}
        for line in open("/proc/meminfo", encoding="utf-8"):
            k, _, v = line.partition(":")
            info[k] = int(v.split()[0])
        avail_mb = info["MemAvailable"] // 1024
    except Exception:                                         # noqa: BLE001
        return record("RAM headroom", UNKNOWN,
                      "MemAvailable is unreadable on this platform (%s)" % platform.system(),
                      "/proc/meminfo")
    examined = "MemAvailable"
    if avail_mb < 1024:
        return record("RAM headroom", FAIL,
                      "%d MB available — below the 1 GB safety buffer" % avail_mb, examined)
    if avail_mb < 2048:
        return record("RAM headroom", WARN, "%d MB available — thin" % avail_mb, examined)
    record("RAM headroom", OK, "%d MB available" % avail_mb, examined)


# ---------------------------------------------------------------------------------------------
# 5. Context and identity
# ---------------------------------------------------------------------------------------------

def check_portable_context():
    installer = os.path.join(HOME, "Workspace", "workspace-manager", "claude", "portable",
                             "install_portable_context.py")
    if not os.path.exists(installer):
        return record("operating context", UNKNOWN,
                      "the portable context installer was not found at the expected path", installer)
    p = run([sys.executable, installer, "--check"], timeout=60)
    if p.returncode == 0:
        return record("operating context", OK,
                      "installed machine-wide — every session loads the rules", installer)
    record("operating context", WARN,
           "NOT installed — a session may start without the operating context", installer)


def check_attribution_identity():
    path = os.path.join(BUCKET, "global", "operator-identity.md")
    if not os.path.exists(path):
        return record("attribution identity", WARN,
                      "operator-identity.md is absent — the attribution header would have to be "
                      "asked for", path)
    # Look at the TABLE ROWS, not the whole file: the prose legitimately mentions ASK_OPERATOR as
    # the fallback, and matching that would flag a correctly-filled file forever.
    platforms = []
    for line in open(path, encoding="utf-8", errors="replace"):
        cells = [c.strip().strip("*` ") for c in line.split("|")]
        if len(cells) < 4 or not cells[1] or cells[1].lower() in ("platform", ""):
            continue
        if set(cells[2]) <= set("-: ") or not cells[2]:
            continue
        if "ASK_OPERATOR" in cells[2] or "<" in cells[2]:
            return record("attribution identity", WARN,
                          "%s still has a placeholder handle" % cells[1], path)
        platforms.append(cells[1])

    if not platforms:
        return record("attribution identity", WARN,
                      "no platform handle rows found in operator-identity.md", path)
    record("attribution identity", OK,
           "handles on file for %s — verify the exact header form against the live program policy"
           % ", ".join(platforms), path)


def check_attribution_header_matches_program():
    """The header is right FOR THIS PROGRAM — a hard check, re-run every session.

    Not the same question as check_attribution_identity, which only asks whether a handle is on
    file. This one re-verifies each compiled engagement's header against the program's own captured
    words, against the platform the engagement actually belongs to, and against the handle on file,
    and confirms every target-bound command carries it attached to the right process.

    It FAILS rather than warns. Traffic sent under a header the program does not look for is
    unattributed as far as they are concerned, some programs make a missing header
    reward-impacting, and a report claiming otherwise is claiming something untrue. The compile-time
    check covers the moment a profile is built; a program can change its policy afterwards and
    nothing recompiles, which is exactly the gap this closes.
    """
    compiler = os.path.join(BUCKET, "global", "scope", "scope_compiler.py")
    if not os.path.exists(compiler):
        return record("attribution header", UNKNOWN, "scope_compiler.py not found", compiler)
    p = run([sys.executable, compiler, "audit-headers"], timeout=180)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode == 0:
        return record("attribution header", OK,
                      "every compiled engagement's header matches its program, platform and handle",
                      compiler)
    try:
        problems = json.loads(p.stdout).get("problems", [])
    except Exception:                                             # noqa: BLE001
        return record("attribution header", UNKNOWN,
                      "the audit did not return a readable result", compiler)
    first = problems[0] if problems else {}
    record("attribution header", FAIL,
           "%d problem(s) — e.g. %s: %s" % (len(problems), first.get("engagement", "?"),
                                            first.get("problem", "?")), compiler)


def check_ttp_mirror():
    """Is the bucket's working TTP library in sync, and did the other machine change it?

    WARN, never FAIL, in both directions. A mirror changed at work is the system working as
    designed — it means an upgrade is waiting to come home — and a mirror behind master is a
    refresh owed, not an unsafe condition. Neither should stop testing.

    UNKNOWN when there is no provenance stamp, because "I cannot tell whether this diverged" is
    exactly the state that let the previous mirror rot unnoticed.
    """
    tool = os.path.join(BUCKET, "framework", "mirror_status.py")
    if not os.path.exists(tool):
        return record("TTP mirror", UNKNOWN, "framework/mirror_status.py not found", tool)
    p = run([sys.executable, tool], timeout=120)
    out = ((p.stdout or "") + (p.stderr or "")).strip().splitlines()
    first = out[0] if out else ""
    if p.returncode == 0:
        return record("TTP mirror", OK, "in sync with the master library", tool)
    if p.returncode == 1:
        return record("TTP mirror", WARN,
                      "CHANGED away from home — an upgrade is waiting for review. "
                      "Run `mirror_status.py --diff` and read framework/UPGRADES-FROM-WORK.md",
                      tool)
    if p.returncode == 2:
        return record("TTP mirror", WARN,
                      "behind the master library — refresh it from master and re-stamp", tool)
    record("TTP mirror", UNKNOWN, first[:120] or "state could not be determined", tool)


def check_ttp_promotion_loop():
    """Are engagement discoveries actually reaching the master library?

    This is the visible end of the discovery-to-master loop. It is a WARN, never a FAIL: an
    unpromoted lesson is a debt, not an unsafe condition, and it must not stop testing. It exists
    because the loop was policy-only for weeks and quietly did not happen.
    """
    mgr = os.path.join(HOME, "Workspace", "Production_Ready", "public", "Offensive_Security",
                       "bug-bounty-execution-framework", "utilities", "ttp_manager",
                       "ttp_manager.py")
    engagements = os.path.join(BUCKET, "engagements")
    if not (os.path.exists(mgr) and os.path.isdir(engagements)):
        return record("TTP promotion loop", UNKNOWN,
                      "ttp_manager.py or the engagements directory was not found", mgr)
    p = run([sys.executable, mgr, "promote", "--engagements", engagements], timeout=120)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode == 0:
        return record("TTP promotion loop", OK,
                      "every engagement has a ledger and every entry reached the master library",
                      mgr)
    if p.returncode == 2:
        missing = len([ln for ln in out.splitlines() if ln.strip().startswith("programs/")])
        return record("TTP promotion loop", WARN,
                      "%d ledger item(s) outstanding — run `ttp_manager.py promote` and settle them"
                      % missing, mgr)
    record("TTP promotion loop", UNKNOWN, "the promotion check did not run cleanly", mgr)


def check_engagement_plan():
    """Can the ACTIVE engagement be resumed by a session that has none of this conversation?

    WARN, never FAIL — an unrecorded plan is a debt, not an unsafe condition, and it must never
    stop testing. It is checked every session because the artifact it guards is the one that rots
    silently: the coverage matrix was required by global/CLAUDE.md 1B for weeks and a survey on
    2026-08-02 found one in 3 of 15 engagements, while two engagements had grown a 15 KB `_STATUS.md`
    doing the job instead.

    What it is really asking: if this session ended right now, would the next one repeat work?
    """
    # Resolved the same way check_engagement does: the session pin wins over the shared pointer.
    eng = os.environ.get("AO_ENGAGEMENT")
    pointer = os.path.join(BUCKET, ".claude", "state", "active_engagement")
    if not eng and os.path.exists(pointer):
        eng = open(pointer, encoding="utf-8").read().strip()
    if not eng:
        return record("engagement plan", UNKNOWN, "no active engagement to check", "")
    d = os.path.join(BUCKET, "engagements", eng)
    planner = os.path.join(HOME, "Workspace", "Production_Ready", "public", "Offensive_Security",
                           "bug-bounty-execution-framework", "utilities", "engagement", "plan.py")
    missing = [f for f in ("_PLAN.md", "_COVERAGE.md") if not os.path.exists(os.path.join(d, f))]
    if missing:
        return record("engagement plan", WARN,
                      "%s missing for %s — run `plan.py init --engagement %s`"
                      % (", ".join(missing), eng, eng), planner)
    if not os.path.exists(planner):
        # WARN, not UNKNOWN, and the distinction is the point. `clean` is
        # `no FAIL and no UNKNOWN`, so an UNKNOWN here BLOCKS the session from starting — which is
        # exactly what this check's own contract says it must never do. The state is reachable
        # through the normal workflow, not a corner case: `_PLAN.md` and `_COVERAGE.md` travel in
        # the bucket, while plan.py lives in the framework repo, so any machine holding the bucket
        # without that repo (a configuration §2C-MIRROR exists to support) lands here.
        #
        # UNKNOWN-is-not-a-pass still holds for every SAFETY check, and must. But it earns its keep
        # by hiding a real failure, and the failure hidden here is "I could not tell whether your
        # notes are tidy". Blocking an engagement on that teaches the operator to route around the
        # opsec check, which costs far more than the check was ever worth.
        return record("engagement plan", WARN,
                      "plan.py not found — cannot verify the plan is consistent (the plan files "
                      "are present). Coverage is unverified this session, not known-bad.", planner)
    p = run([sys.executable, planner, "check", "--engagement", eng], timeout=60)
    out = ((p.stdout or "") + (p.stderr or "")).strip()
    if p.returncode == 0:
        rows = [ln for ln in out.splitlines() if "coverage rows exercised" in ln]
        return record("engagement plan", OK,
                      rows[0].split(":", 1)[-1].strip() if rows
                      else "plan and coverage present and consistent", planner)
    first = next((ln.strip() for ln in out.splitlines() if ln.strip().startswith("[!]")), out[:120])
    return record("engagement plan", WARN, first, planner)


# ---------------------------------------------------------------------------------------------
# Optional, opt-in
# ---------------------------------------------------------------------------------------------

def check_connection_guard():
    guard = os.path.join(HOME, "Workspace", "workspace-manager", "claude", "utils",
                         "connection_guard", "connection_guard.py")
    if not os.path.exists(guard):
        return record("connection guard", UNKNOWN, "connection_guard.py not found", guard)
    p = run([sys.executable, guard], timeout=120)
    out = (p.stdout or "") + (p.stderr or "")
    if p.returncode == 0:
        return record("connection guard", OK, "connection is clear to work from", guard)
    tail = [ln for ln in out.splitlines() if ln.strip()][-1:] or [""]
    record("connection guard", FAIL, "guard did not clear: %s" % tail[0][:120], guard)


def check_opsec_gate():
    priv = os.path.join(HOME, "Workspace", "Production_Ready", "private", "Offensive_Operations",
                        "opsec-private")
    core = os.path.join(HOME, "Workspace", "Production_Ready", "public", "Offensive_Security",
                        "opsec-core")
    cfg = os.path.join(priv, "opsec.config.json")
    if not (os.path.isdir(priv) and os.path.isdir(core) and os.path.exists(cfg)):
        return record("pre-engagement gate", UNKNOWN, "opsec-private/opsec-core not both present",
                      priv)
    env = dict(os.environ, PYTHONPATH=core)
    p = run([sys.executable, os.path.join(core, "opsec.py"), "--config", cfg, "check", "--all"],
            timeout=420, cwd=priv, env=env)
    out = (p.stdout or "") + (p.stderr or "")
    if "CLEAR" in out and p.returncode == 0:
        return record("pre-engagement gate", OK, "[SOFT+HARD] CLEAR", cfg)
    record("pre-engagement gate", FAIL,
           "did not come back CLEAR — stop and fix it, that is what it is for", cfg)


# ---------------------------------------------------------------------------------------------

CHECKS = [
    check_wall_registered,
    check_wall_fires,
    check_engagement,
    check_execution_mode,
    check_remote_artifacts,
    check_nothing_scanning_locally,
    check_no_api_key_here,
    check_ram,
    check_portable_context,
    check_attribution_identity,
    check_attribution_header_matches_program,
    check_ttp_mirror,
    check_ttp_promotion_loop,
    check_engagement_plan,
]

GLYPH = {OK: "  OK  ", WARN: " WARN ", FAIL: " FAIL ", UNKNOWN: " ???  "}


def main(argv):
    want_net = "--net" in argv
    want_gate = "--gate" in argv
    as_json = "--json" in argv

    checks = list(CHECKS)
    if want_net:
        checks.append(check_connection_guard)
    if want_gate:
        checks.append(check_opsec_gate)

    for fn in checks:
        try:
            fn()
        except Exception as exc:                              # noqa: BLE001
            # A check that crashes has not passed. Fail closed, loudly, by name.
            record(fn.__name__, FAIL, "the check itself raised: %s" % exc, "")

    counts = {state: sum(1 for r in results if r["state"] == state)
              for state in (OK, WARN, FAIL, UNKNOWN)}
    clean = counts[FAIL] == 0 and counts[UNKNOWN] == 0

    if as_json:
        print(json.dumps({"clean": clean, "counts": counts, "results": results}, indent=1))
        return 0 if clean else 1

    print("\nOPSEC CHECK")
    print("=" * 78)
    for r in results:
        print("[%s] %-26s %s" % (GLYPH[r["state"]], r["check"], r["detail"]))
        if r["examined"]:
            print("       %s" % r["examined"])
    print("=" * 78)
    print("%d ok · %d warn · %d fail · %d unknown   (%d checks run)"
          % (counts[OK], counts[WARN], counts[FAIL], counts[UNKNOWN], len(results)))

    if not want_net:
        print("\nnot run: connection guard (--net, makes outbound requests)")
    if not want_gate:
        print("not run: full pre-engagement gate (--gate, slow)")

    if clean:
        print("\nCLEAR." + ("" if counts[WARN] == 0 else "  Warnings above are worth reading."))
    else:
        print("\nNOT CLEAR — %d failed, %d could not be determined." % (counts[FAIL], counts[UNKNOWN]))
        print("An UNKNOWN is not a pass. Resolve it before testing.")
    return 0 if clean else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
