#!/usr/bin/env python3
"""Wall parser regression suite. Run: python3 testing/test_wall_parser.py

WHY THIS EXISTS
On 2026-07-28 the scope wall was registered GLOBALLY for the first time (see
`_NEEDS-REVIEW/04` — before that it was only loaded in bucket-rooted sessions, which is to say
almost never). It immediately began evaluating ordinary shell instead of only offensive tool
invocations, and its command parser was not written for that. Within minutes it had blocked:

    if [ -f x ]; then …        -> "'[' is NOT in the approved allow-list"
    while read l; do …; done < f -> "'<' is NOT in the approved allow-list"
    for t in testing/*.py; do  -> "'*.py;' is NOT in the approved allow-list"
    timeout 60 <cmd>           -> "'60' is NOT in the approved allow-list"
    python3 - <<'PY' … PY      -> "sources targets from a file the hook could not read"
    python3 -m orchestrator.cli-> "Target 'orchestrator.cli' is OUTSIDE the approved asset scope"
    R=$(cmd | grep -E '^(a|b)')-> "'$L' is NOT in the approved allow-list"

Every one fails CLOSED, so nothing unsafe happened. But friction on a safety control is not
harmless — a wall that cries wolf is a wall people start routing around, and the `timeout` case
blocked the framework's OWN documented pattern (global/CLAUDE.md §2F-NET says `timeout 2h <cmd>`).

So this suite is built around one question: **did narrowing what is PARSED narrow what is DENIED?**
Every fix here touches parsing only. The MUST-DENY half is the proof that no decision moved.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, ".claude/hooks/enforce_scope.py")
sys.path.insert(0, os.path.join(REPO, ".claude/hooks"))
import enforce_scope as E  # noqa: E402


def build_fixture():
    """A self-contained workspace with ONE approved engagement.

    Earlier this suite ran against whatever engagement happened to be approved in the surrounding
    bucket. That passed here and failed in a clean checkout of the public repo, where no engagement
    exists and every command falls to Phase-1 lockdown — so the suite was really testing the ambient
    state, not the parser. A fixture makes it answer the same way anywhere, which matters because a
    fresh clone (a new VPS, a new machine) is exactly where you most want to know the wall works.
    """
    root = tempfile.mkdtemp(prefix="wall-parser-")
    os.makedirs(os.path.join(root, "global"))
    with open(os.path.join(root, "global", "CLAUDE.md"), "w", encoding="utf-8") as fh:
        fh.write("- **HARD_BOUNDARIES** (safety valve): `true`\n")
    os.makedirs(os.path.join(root, ".claude", "state"))
    lock = os.path.join(root, "engagements", "programs", "synthetic", ".scope_lock")
    os.makedirs(lock)
    with open(os.path.join(lock, "enforcement.json"), "w", encoding="utf-8") as fh:
        json.dump({
            "engagement": "synthetic", "approved": True,
            "source_scope_sha256": "0" * 64,
            # python3/ls/git allowed so ordinary work is testable; curl/httpx/nuclei allowed as
            # BINARIES so that when they are denied it is the LOCATION wall doing it, not a
            # missing allow-list entry. That distinction is the whole point of the suite.
            "allowed_binaries": ["python3", "ls", "git", "curl", "httpx", "nuclei", "echo",
                                 "timeout", "bash", "sudo", "grep", "read", "true"],
            "always_allowed_extra": [], "denied_patterns": [r"\bhydra\b"],
            "assets": {"hosts": ["acme.example"], "wildcards": [], "cidrs": [], "ips": []},
            "rate_ceiling": 10,
        }, fh)
    with open(os.path.join(root, ".claude", "state", "active_engagement"), "w",
              encoding="utf-8") as fh:
        fh.write("programs/synthetic\n")
    # The location wall reads execution mode live from settings.py — copy the real one so the
    # remote/local decision under test is the actual shipped logic, not a stub.
    src_exec = os.path.join(REPO, "global", "execution")
    if os.path.isdir(src_exec):
        shutil.copytree(src_exec, os.path.join(root, "global", "execution"),
                        ignore=shutil.ignore_patterns("__pycache__"))
    return root


FIXTURE = build_fixture()

# Built at runtime so this file never contains a literal offensive command line.
CURL = "cur" + "l"
EVIL = "https://" + "evil.example.com/"
HEREDOC = "python3 - <<'PY'\nimport collections, os.path\nprint(collections.Counter)\nPY"

passed = failed = 0


def check(name, ok, extra=""):
    global passed, failed
    if ok:
        passed += 1
        print("  PASS  " + name)
    else:
        failed += 1
        print("  FAIL  " + name + (("  -> " + str(extra)) if extra else ""))


def decide(cmd, project_root="/home/primaryu"):
    """Run the real hook exactly as Claude Code would, from a session rooted OUTSIDE the workspace."""
    env = dict(os.environ, CLAUDE_PROJECT_DIR=project_root)
    env.pop("AO_ENGAGEMENT", None)          # the fixture's pointer decides, not the shell's
    p = subprocess.run([sys.executable, HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd},
                                         "cwd": FIXTURE}),
                       capture_output=True, text=True, env=env)
    out = p.stdout.strip()
    if not out:
        return "allow", ""
    o = json.loads(out)["hookSpecificOutput"]
    return o["permissionDecision"], o.get("permissionDecisionReason", "")


# ─────────────────────────────────────────────────────────────────────────────
# 1. Ordinary shell must not be mistaken for offensive tooling
# ─────────────────────────────────────────────────────────────────────────────
print("\n-- benign shell is allowed --")
for name, cmd in [
    ("plain ls", "ls -la"),
    ("if/then conditional", 'if [ -f x ]; then ls; fi'),
    ("while loop with a redirect", "while read l; do ls; done < f"),
    ("for loop over a glob", "for t in testing/*.py; do ls $t; done"),
    ("heredoc with dotted identifiers", HEREDOC),
    ("timeout wrapping python3", "timeout 60 python3 script.py"),
    ("timeout 2h — the CLAUDE.md §2F-NET pattern", "timeout 2h python3 script.py"),
    ("python3 -m module.path", "python3 -m orchestrator.cli auth-status"),
    ("substitution containing parentheses", "R=$(python3 x.py | grep -E '^(OK|FAILED)')"),
    ("arithmetic expansion", "echo $((1 + 2))"),
    # Archive/package filenames are dotted tokens that look exactly like hostnames. Before these
    # were added to FILE_EXT, `node-v24.18.1-linux-x64.tar.xz` was read as a target and an approved
    # download was refused - twice on 2026-07-29.
    ("archive filename is not a hostname", "grep pattern node-v24.18.1-linux-x64.tar.xz"),
    ("wheel filename", "ls dist/pkg-1.2.3-py3-none-any.whl"),
    ("signature + checksum files", "ls release.tar.zst release.sig release.asc"),
    ("package files", "ls build/app.deb build/app.rpm build/app.apk"),
]:
    d, why = decide(cmd)
    check(name, d == "allow", why[:70])

# ─────────────────────────────────────────────────────────────────────────────
# 2. THE HALF THAT MATTERS — every real violation still denied
# ─────────────────────────────────────────────────────────────────────────────
print("\n-- real violations are still denied (parsing changed, decisions did not) --")
for name, cmd in [
    ("network tool run directly", CURL + " -s " + EVIL),
    ("hidden behind timeout", "timeout 60 " + CURL + " -s " + EVIL),
    ("hidden behind timeout 2h", "timeout 2h httpx -u https://acme.test"),
    ("hidden behind sudo", "sudo " + CURL + " " + EVIL),
    ("inside a for loop", "for h in a b; do " + CURL + " " + EVIL + "; done"),
    ("inside an if block", 'if true; then ' + CURL + " " + EVIL + '; fi'),
    ("inside bash -c", 'bash -c "' + CURL + " " + EVIL + '"'),
    ("inside a command substitution", "R=$(" + CURL + " " + EVIL + ")"),
    ("inside a substitution WITH parens", "R=$(" + CURL + " " + EVIL + " | grep -E '^(a|b)')"),
    ("inside backticks", "R=`" + CURL + " " + EVIL + "`"),
    ("inside an UNBALANCED substitution", "R=$(" + CURL + " " + EVIL),
    ("nested substitution", "R=$(echo $(" + CURL + " " + EVIL + "))"),
    ("deny-listed binary", "hydra -l a -P b ssh://x"),
]:
    d, why = decide(cmd)
    check(name, d == "deny", "ALLOWED — " + why[:60])

# ─────────────────────────────────────────────────────────────────────────────
# 3. The scrubs must not swallow a real destination
# ─────────────────────────────────────────────────────────────────────────────
print("\n-- narrowing the parse must not hide a real target --")
check("module scrub keeps a host later in the same command",
      E.extract_destinations("python3 -m orchestrator.cli && " + CURL + " " + EVIL)
      == {"evil.example.com"},
      E.extract_destinations("python3 -m orchestrator.cli && " + CURL + " " + EVIL))
check("another tool's -m is still inspected",
      "target.example.com" in E.extract_destinations("sometool -m target.example.com"))
check("module path itself yields no destination",
      E.extract_destinations("python3 -m orchestrator.cli auth-status") == set())
check("substitution body binaries are extracted",
      CURL in E.candidate_binaries("R=$(" + CURL + " x | grep -E '^(a)')"))

# ─────────────────────────────────────────────────────────────────────────────
# 4. The wall must be reachable from a session started anywhere (_NEEDS-REVIEW/04)
# ─────────────────────────────────────────────────────────────────────────────
print("\n-- the wall decides identically wherever the session started --")
for name, cmd, want in [("network tool", CURL + " " + EVIL, "deny"), ("plain ls", "ls -la", "allow")]:
    outside, _ = decide(cmd, project_root="/home/primaryu")
    inside, _ = decide(cmd, project_root=FIXTURE)
    check("%s: same decision from ~ and from the workspace" % name,
          outside == inside == want, "outside=%s inside=%s" % (outside, inside))

print("\n" + "=" * 78)
print("%d passed, %d failed" % (passed, failed))
print("=" * 78)
sys.exit(1 if failed else 0)
