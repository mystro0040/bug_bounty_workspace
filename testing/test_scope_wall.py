#!/usr/bin/env python3
"""
test_scope_wall.py — regression tests for the PreToolUse scope-enforcement hook.

The scope wall is the single most safety-critical piece in the workspace: it is what keeps scanning
in-scope and keeps abusive/anonymizing/destructive commands from ever running (the thing that could
get the ISP account cut off). Captured from the 2026-07-23 arsenal audit.

SELF-CONTAINED: it builds a synthetic engagement + scope-lock in a TEMP dir and drives the real hook
(../.claude/hooks/enforce_scope.py) over the actual stdin JSON contract. No live bucket state, no
network, no writes outside the temp dir. Run directly:  python3 test_scope_wall.py  (exit 0 = pass).

Covers: .claude/hooks/enforce_scope.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, ".claude", "hooks", "enforce_scope.py")

_PASS = _FAIL = 0


def chk(name, cond, extra=""):
    global _PASS, _FAIL
    ok = bool(cond)
    _PASS += ok
    _FAIL += not ok
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  -> " + str(extra)) if (extra and not ok) else ""))


def make_project(tmp, engagement="programs/test/acme", approved=True, corrupt=False):
    """Build a minimal project dir the hook will accept: an active-engagement pointer + a scope-lock
    with acme.example in scope and a small allowed-binary set."""
    os.makedirs(os.path.join(tmp, ".claude", "state"), exist_ok=True)
    with open(os.path.join(tmp, ".claude", "state", "active_engagement"), "w") as fh:
        fh.write(engagement)
    lock = os.path.join(tmp, "engagements", engagement, ".scope_lock")
    os.makedirs(lock, exist_ok=True)
    prof = os.path.join(lock, "enforcement.json")
    if corrupt:
        open(prof, "w").write("{ this is not valid json")
        return
    json.dump({
        "engagement": engagement,
        "approved": approved,
        "allowed_binaries": ["curl", "httpx", "dnsx", "nuclei", "ffuf", "gobuster", "nmap"],
        "denied_patterns": [],
        "assets": {"hosts": ["acme.example"], "wildcards": ["*.acme.example"],
                   "cidrs": [], "ips": []},
    }, open(prof, "w"))


def decide(cmd, project_dir, engagement="programs/test/acme"):
    env = dict(os.environ, CLAUDE_PROJECT_DIR=project_dir)
    if engagement is None:
        env.pop("AO_ENGAGEMENT", None)
    else:
        env["AO_ENGAGEMENT"] = engagement
    payload = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": cmd}, "cwd": project_dir}
    p = subprocess.run([sys.executable, HOOK], input=json.dumps(payload),
                       text=True, capture_output=True, env=env, timeout=30)
    try:
        out = json.loads(p.stdout or "{}").get("hookSpecificOutput", {})
        return out.get("permissionDecision", "?")
    except ValueError:
        return f"NONJSON(rc={p.returncode})"


def expect(want, cmd, note, project_dir, engagement="programs/test/acme"):
    d = decide(cmd, project_dir, engagement)
    chk(f"[{d:<5}] {note}", (d == "deny") == (want == "deny"), d)


def main():
    if not os.path.isfile(HOOK):
        print(f"  SKIP  hook not present at {HOOK}")
        return 0
    tmp = tempfile.mkdtemp(prefix="scopewall-")
    try:
        make_project(tmp)

        print("[HARD FLOOR] denied no matter what the profile says")
        for cmd, n in [("hydra -l a -P p ssh://acme.example", "credential brute force"),
                       ("medusa -h acme.example -M ssh", "medusa"),
                       ("ncrack acme.example", "ncrack"),
                       ("hping3 --flood acme.example", "DoS flood"),
                       ("slowloris acme.example", "slowloris"),
                       ("ab -n 100000 -c 500 https://acme.example/", "apachebench flood")]:
            expect("deny", cmd, n, tmp)

        print("[ANON/EVASION] forbidden (ISP + Anthropic-account risk)")
        for cmd, n in [("torsocks curl https://acme.example", "torsocks"),
                       ("proxychains4 nmap acme.example", "proxychains"),
                       ("sudo openvpn --config us.ovpn", "openvpn"),
                       ("wg-quick up wg0", "wireguard"),
                       ("tor & curl https://acme.example", "bare tor")]:
            expect("deny", cmd, n, tmp)

        print("[DESTRUCTIVE/SYSTEM]")
        for cmd, n in [("rm -rf /", "rm -rf /"), ("sudo shutdown -h now", "shutdown"),
                       ("mkfs.ext4 /dev/sda1", "mkfs"), (":(){ :|:& };:", "fork bomb"),
                       ("pkill -f httpx", "pkill (kills sibling engagement)"),
                       ("killall nuclei", "killall")]:
            expect("deny", cmd, n, tmp)

        print("[RATE CEILING] the ISP protection")
        for cmd, n in [("httpx -u https://acme.example -rate 500", "-rate 500"),
                       ("dnsx -l t.txt -rl 1000", "-rl 1000"),
                       ("nuclei -u https://acme.example --rate-limit 300", "--rate-limit 300"),
                       ("ffuf -u https://acme.example/FUZZ -w w -t 200", "-t 200"),
                       ("gobuster dir -u https://acme.example --threads 400", "--threads 400")]:
            expect("deny", cmd, n, tmp)

        print("[GENTLE] must NOT be blocked")
        expect("allow", "httpx -u https://acme.example -rate 10", "-rate 10 in-scope", tmp)
        expect("allow", "ffuf -u https://acme.example/FUZZ -w w -t 5", "-t 5 in-scope", tmp)
        expect("allow", "curl https://acme.example/robots.txt", "curl in-scope", tmp)
        expect("allow", "httpx -u https://api.acme.example", "wildcard subdomain in-scope", tmp)

        print("[OUT OF SCOPE] denied")
        for cmd, n in [("curl https://google.com", "out-of-scope host"),
                       ("nmap -sV 8.8.8.8", "out-of-scope IP"),
                       ("httpx -u https://evil.example.org", "unrelated domain")]:
            expect("deny", cmd, n, tmp)

        print("[FAIL-CLOSED] no/!bad engagement, corrupt or unapproved profile")
        empty = tempfile.mkdtemp(prefix="scopewall-empty-")
        os.makedirs(os.path.join(empty, ".claude", "state"))
        expect("deny", "httpx -u https://acme.example", "no engagement resolvable", empty, engagement=None)
        expect("deny", "curl https://acme.example", "unknown engagement", tmp, engagement="programs/ghost")
        corrupt = tempfile.mkdtemp(prefix="scopewall-corrupt-")
        make_project(corrupt, corrupt=True)
        expect("deny", "httpx -u https://acme.example", "corrupt enforcement.json", corrupt)
        shutil.rmtree(empty, ignore_errors=True)
        shutil.rmtree(corrupt, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{_PASS}/{_PASS + _FAIL} passed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
