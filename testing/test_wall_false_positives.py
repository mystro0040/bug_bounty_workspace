#!/usr/bin/env python3
"""test_wall_false_positives.py — the wall must block the right things AND only those.

A wall that denies ordinary local work does not merely waste time. It teaches agents to tiptoe:
there is already a note in this bucket telling the next session which barewords to avoid and to
use a different tool for writing files. An agent in the habit of routing AROUND the wall is one
judgement away from routing around it when it is right.

So this file has two halves, and the second keeps the first honest:

  FALSE POSITIVES — ordinary local commands that must be allowed.
  STILL BLOCKED   — every real refusal, re-proved. If a fix here ever weakens one of these, the
                    fix is wrong. Several are fail-OPEN regressions found previously by reading
                    the parser, so they are pinned deliberately.

Verified 2026-08-03 against the real parser rather than assumed. Of the four denials reported that
day, one was a parsing defect, one was a missing safe binary, one was a target-list-flag
misfire, and one was the wall behaving correctly.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(HERE)
HOOK = os.path.join(WORKSPACE, ".claude", "hooks", "enforce_scope.py")
sys.path.insert(0, os.path.join(WORKSPACE, ".claude", "hooks"))
import enforce_scope as es  # noqa: E402

_PASS = _FAIL = 0


def chk(name, cond, extra=""):
    global _PASS, _FAIL
    ok = bool(cond)
    _PASS += ok
    _FAIL += not ok
    print(("  PASS  " if ok else "  FAIL  ") + name + (("  -> " + str(extra)) if (extra and not ok) else ""))


def sandbox(allowed=("curl", "find", "python3", "nuclei", "httpx"), hosts=("acme.example",)):
    root = tempfile.mkdtemp(prefix="wallfp-")
    eng = os.path.join(root, "engagements", "programs", "synthetic", ".scope_lock")
    os.makedirs(eng)
    os.makedirs(os.path.join(root, ".claude", "state"))
    json.dump({"engagement": "synthetic", "approved": True, "source_scope_sha256": "0" * 64,
               "allowed_binaries": list(allowed), "always_allowed_extra": [],
               "denied_patterns": [r"\bhydra\b"], "rate_ceiling": 10,
               "assets": {"hosts": list(hosts), "wildcards": [], "cidrs": [], "ips": [],
                          "endpoints": [], "out_of_scope": []}},
              open(os.path.join(eng, "enforcement.json"), "w"))
    open(os.path.join(root, ".claude", "state", "active_engagement"), "w").write("programs/synthetic")
    return root


def decide(root, command):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": root})
    env = dict(os.environ, AO_ENGAGEMENT="programs/synthetic", CLAUDE_PROJECT_DIR=root)
    p = subprocess.run([sys.executable, HOOK], input=payload, env=env,
                       capture_output=True, text=True, timeout=30)
    try:
        o = json.loads(p.stdout)["hookSpecificOutput"]
        return o["permissionDecision"], o.get("permissionDecisionReason", "")
    except (ValueError, KeyError):
        return "MALFORMED", (p.stdout or p.stderr)[:200]


def test_arguments_are_not_binaries():
    print("[fp] an ARGUMENT that looks like a program name is not a program name")
    # `\(` returns the parser to command position; the `-name` flag after it left `expect` set, so
    # the NEXT token was read as a program. Measured: parsed as ['find', 'info*'].
    bins = es.candidate_binaries('find . -type f \\( -name "info*" -o -name "page*" \\)')
    chk("find's -name glob is not parsed as a binary", "info*" not in bins, sorted(bins))
    chk("find itself still is", "find" in bins, sorted(bins))

    bins = es.candidate_binaries('find . \\( -name "a*" \\) -o \\( -iname "b*" \\)')
    chk("neither glob in a two-clause find", not ({"a*", "b*"} & bins), sorted(bins))

    root = sandbox()
    try:
        d, why = decide(root, 'find . -type f \\( -name "info*" -o -name "page*" \\)')
        chk("and the hook allows it end to end", d == "allow", (d, why[:110]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_read_only_local_utilities():
    print("[fp] the read-only local utilities the config REQUIRES must be usable")
    root = sandbox()
    try:
        # global/CLAUDE.md 2F-LOCAL: "Check the input first. du -sh <dir> / wc -c <file>."
        # The wall denying the command the config mandates is the same defect as the ulimit gap.
        for cmd in ["du -sh /home/me/dir",
                    "( ulimit -v 2000000; du -sh /home/me/x )",
                    "df -h /home",
                    # §2F-STOP: "Verify before you report stopped" needs process inspection.
                    "ps -eo pid,etime,comm",
                    "pgrep -a python3",
                    "free -m",
                    "uptime"]:
            d, why = decide(root, cmd)
            chk(f"allowed: {cmd[:38]}", d == "allow", (d, why[:100]))

        # But the ACTING counterparts must stay blocked — killing by name can destroy a
        # parallel engagement's hours-long run (§2F-PARALLEL).
        for cmd in ["pkill -x dnsx", "killall httpx"]:
            d, why = decide(root, cmd)
            chk(f"still DENIED: {cmd[:28]}", d == "deny", (d, why[:90]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_list_flag_on_a_local_tool():
    print("[fp] --list on a local tool is not a file full of targets")
    root = sandbox()
    try:
        # `--list` sits in TARGET_LIST_FLAGS for naabu's sake. On any command where another token
        # follows it, the next token was captured as a target-list FILE, failed to resolve, and the
        # whole command was denied fail-closed. Both real cases: `--list 2>&1 | tail` and
        # `( ulimit -v N; ... --list )`.
        for cmd in ["python3 workspace.py test --list",
                    "( ulimit -v 2000000; python3 workspace.py test --list )",
                    "python3 tool.py --list ; echo done"]:
            d, why = decide(root, cmd)
            chk(f"allowed: {cmd[:44]}", d == "allow", (d, why[:110]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_still_blocked():
    print("[blocked] every real refusal, re-proved — a fix that weakens one of these is wrong")
    root = sandbox()
    try:
        cases = [
            ("nuclei -u https://out-of-scope.example", "out-of-scope host"),
            ("hydra -l a -P b acme.example", "hard-floor deny pattern"),
            ("somestrangebinary --go", "binary not in the allow-list"),
            ("echo hi; somestrangebinary --go", "binary after a semicolon (was a fail-open hole)"),
            ("ls | somestrangebinary", "binary after a pipe"),
            ("( somestrangebinary )", "binary inside a subshell"),
            ("bash -c 'somestrangebinary --go'", "binary hidden inside bash -c"),
            ("rm -rf /home/me/thing", "rm is destructive and not allow-listed"),
        ]
        for cmd, label in cases:
            d, why = decide(root, cmd)
            chk(f"still DENIED — {label}", d == "deny", (d, why[:90]))

        # A genuine target-list file must still be verified against scope.
        listing = os.path.join(root, "targets.txt")
        open(listing, "w").write("out-of-scope.example\n")
        d, why = decide(root, f"httpx -l {listing}")
        chk("still DENIED — out-of-scope host inside a target-list FILE", d == "deny",
            (d, why[:110]))

        ok_list = os.path.join(root, "ok.txt")
        open(ok_list, "w").write("acme.example\n")
        d, why = decide(root, f"httpx -l {ok_list}")
        chk("allowed — in-scope host inside a target-list file", d == "allow", (d, why[:110]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_hostname_containing_a_shell_name():
    print("[fp] a HOSTNAME that contains a shell's name is not a shell invocation")
    # `\bsh\b` matched the `sh` inside `crt.sh`, so the bash -c unwrapper fired on an ordinary
    # curl and took whatever followed the next ` -c ` as an inner command. crt.sh is one of the
    # framework's own approved recon sources, so this broke passive CT enumeration everywhere.
    bins = es.candidate_binaries(
        "curl -s 'https://crt.sh/?q=x' -o ct_a.json; wc -c ct_*.json")
    chk("the file after `wc -c` is not parsed as a binary", "ct_*.json" not in bins, sorted(bins))
    chk("curl and wc still are", {"curl", "wc"} <= bins, sorted(bins))

    # crt.sh is a recon SOURCE, so a real engagement carries it in hosts (scope_compiler adds it
    # via recon_sources_for). The synthetic sandbox has to as well, or this tests the asset wall
    # rather than the parser.
    root = sandbox(hosts=("acme.example", "crt.sh"))
    try:
        d, why = decide(root, "curl -s 'https://crt.sh/?q=%25.acme.example&output=json' "
                              "-o ct.json; wc -c ct_*.json")
        chk("and a real CT query dispatches", d == "allow", (d, why[:120]))
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print("[blocked] but a genuine shell wrapper is STILL unwrapped and checked")
    for wrapper in ["bash -c 'somestrangebinary --go'",
                    "sh -c 'somestrangebinary'",
                    "/bin/sh -c 'somestrangebinary'",
                    "ls | bash -c 'somestrangebinary'",
                    "( sh -c 'somestrangebinary' )"]:
        bins = es.candidate_binaries(wrapper)
        chk(f"still unwrapped: {wrapper[:38]}", "somestrangebinary" in bins, sorted(bins))


def test_versioned_filenames_are_not_hosts():
    print("[fp] a versioned FILENAME is not a hostname")
    # `podman load -i servu-ready-v15.5.1.104.img` was denied for "targeting" the image file.
    # Software-target engagements ship versioned images, so dotted filenames are normal there —
    # and that engagement's whole asset list is localhost, so nothing about it is network work.
    for cmd, fname in [
        ("podman load -i servu-ready-v15.5.1.104.img", "servu-ready-v15.5.1.104.img"),
        ("podman save -o base-12.4.img debian:12-slim", "base-12.4.img"),
        ("python3 -c 'x' disk-1.2.3.qcow2", "disk-1.2.3.qcow2"),
    ]:
        dests = es.extract_destinations(cmd)
        chk(f"{fname} is not a destination", fname not in dests, sorted(dests))

    print("[blocked] but a real host in the same shape is STILL a destination")
    for cmd, host in [
        ("curl https://out-of-scope.example/x", "out-of-scope.example"),
        ("httpx -u api.out-of-scope.example", "api.out-of-scope.example"),
    ]:
        dests = es.extract_destinations(cmd)
        chk(f"{host} IS still a destination", host in dests, sorted(dests))


def test_end_of_options_still_checked():
    print("[blocked] `--` must NOT hide the command after it")
    # The parser fix clears `expect` on a flag seen in command position. A bare `--` is the
    # end-of-options marker and the token AFTER it can be a real command, so it must stay
    # expect-preserving or the fix becomes a fail-open hole.
    bins = es.candidate_binaries("env -- somestrangebinary --go")
    chk("a binary after `--` is still parsed", "somestrangebinary" in bins, sorted(bins))
    bins = es.candidate_binaries("timeout 60 -- somestrangebinary")
    chk("and after `timeout 60 --`", "somestrangebinary" in bins, sorted(bins))


def main():
    for fn in [test_arguments_are_not_binaries,
               test_read_only_local_utilities,
               test_list_flag_on_a_local_tool,
               test_hostname_containing_a_shell_name,
               test_versioned_filenames_are_not_hosts,
               test_still_blocked,
               test_end_of_options_still_checked]:
        fn()
        print()
    print(f"{_PASS} passed, {_FAIL} failed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
