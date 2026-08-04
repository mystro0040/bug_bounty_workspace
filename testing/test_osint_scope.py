#!/usr/bin/env python3
"""test_osint_scope.py — reading a vendor's manual and testing their host are different permissions.

THE HOLE THIS CLOSED. An agent regularly needs to read something that is not a target: the
vendor's documentation for the product under test, an advisory, a public repo the operator points
it at. The only way to permit that used to be adding the host to `assets.hosts` — which authorises
the ENTIRE engagement allow-list against it.

A real engagement here did precisely that: the vendor's documentation and download hosts sat in its
host list, alongside a sentence in `out_of_scope` saying they were "ONLY to read manuals" and "not
a thing to test". Nothing enforced that sentence. Driven against the live wall, a vulnerability
scanner and a content fuzzer aimed at the vendor's documentation site were both ALLOWED. It was
policy with no mechanism, which is this workspace's characteristic failure.

So the checks below come in pairs, and the SECOND of each pair is the one that matters:

    it FIRES        — a scanner, a fuzzer, or a write request aimed at an OSINT source is refused,
                      even though the engagement's allow-list contains that tool.
    it STAYS QUIET  — an ordinary read of that same host is allowed, a real in-scope target is
                      completely unaffected, and an engagement with no OSINT sources behaves
                      exactly as it did before this existed.

The third of those is the regression that would hurt most: 16 live engagements have no
osint_sources, and none of them may change behaviour.

Pure stdlib, no network, temp dirs only.  Run:  python3 testing/test_osint_scope.py
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
sys.path.insert(0, os.path.join(WORKSPACE, "global", "scope"))

_PASS = _FAIL = 0


def chk(name, cond, extra=""):
    global _PASS, _FAIL
    ok = bool(cond)
    _PASS += ok
    _FAIL += not ok
    print(("  PASS  " if ok else "  FAIL  ") + name
          + (("  -> " + str(extra)) if (extra and not ok) else ""))


def sandbox(hosts=("acme.example",), osint=(), allowed=("curl", "wget", "nuclei", "ffuf", "python3")):
    root = tempfile.mkdtemp(prefix="osint-")
    eng = os.path.join(root, "engagements", "programs", "synthetic", ".scope_lock")
    os.makedirs(eng)
    os.makedirs(os.path.join(root, ".claude", "state"))
    with open(os.path.join(eng, "enforcement.json"), "w", encoding="utf-8") as fh:
        json.dump({
            "engagement": "synthetic",
            "approved": True,
            "source_scope_sha256": "0" * 64,
            "allowed_binaries": list(allowed),
            "always_allowed_extra": [],
            "denied_patterns": [],
            "assets": {"hosts": list(hosts), "wildcards": [], "cidrs": [], "ips": [],
                       "endpoints": [], "osint": list(osint), "out_of_scope": []},
        }, fh)
    with open(os.path.join(root, ".claude", "state", "active_engagement"), "w") as fh:
        fh.write("programs/synthetic")
    return root


def decide(root, command):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": root})
    env = dict(os.environ, AO_ENGAGEMENT="programs/synthetic", CLAUDE_PROJECT_DIR=root)
    proc = subprocess.run([sys.executable, HOOK], input=payload, env=env,
                          capture_output=True, text=True, timeout=30)
    try:
        out = json.loads(proc.stdout)["hookSpecificOutput"]
    except (ValueError, KeyError):
        return "MALFORMED", (proc.stdout or proc.stderr)[:300]
    return out["permissionDecision"], out.get("permissionDecisionReason", "")


DOCS = "docs.vendor.example"


def test_reading_is_permitted():
    print("[osint] the capability exists at all — an OSINT source can be READ")
    root = sandbox(osint=(DOCS,))
    try:
        d, why = decide(root, f"curl -s https://{DOCS}/manual/install.html")
        chk("a plain GET of the documentation is allowed", d == "allow", (d, why[:160]))

        d, why = decide(root, f"wget -q https://{DOCS}/guide.pdf")
        chk("wget of a document is allowed", d == "allow", (d, why[:160]))

        d, why = decide(root, f"curl -I https://{DOCS}/")
        chk("a HEAD request is allowed", d == "allow", (d, why[:160]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_testing_is_refused():
    print("[osint] it FIRES — the same host may not be TESTED, whatever the allow-list says")
    root = sandbox(osint=(DOCS,))
    try:
        # Every tool below IS in this engagement's approved allow-list. That is the whole point:
        # the refusal has to come from what the host IS, not from what the tool is.
        for cmd, label in [
            (f"nuclei -u https://{DOCS}", "a vulnerability scanner"),
            (f"ffuf -u https://{DOCS}/FUZZ -w list.txt", "a content fuzzer"),
            (f"curl -X POST -d 'a=1' https://{DOCS}/api", "a POST with a body"),
            (f"curl -X DELETE https://{DOCS}/thing", "a DELETE"),
            (f"curl -F file=@x.txt https://{DOCS}/upload", "a form upload"),
            (f"python3 -c \"import requests; requests.post('https://{DOCS}/x')\"",
             "a non-GET request in python"),
        ]:
            d, why = decide(root, cmd)
            chk(f"{label} against an OSINT source is DENIED", d == "deny", (d, why[:140]))

        d, why = decide(root, f"nuclei -u https://{DOCS}")
        chk("the refusal explains it is a source, not a target",
            "OSINT SOURCE" in why, why[:200])
        chk("the refusal says reading is still fine",
            "READ" in why.upper(), why[:200])
        chk("the refusal tells the operator the legitimate route (a scope change)",
            "generate-scope" in why, why[:240])
        chk("and explicitly says not to reword the command",
            "reword" in why.lower(), why[:240])
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_real_targets_are_untouched():
    print("[osint] it STAYS QUIET — a genuine in-scope target is completely unaffected")
    root = sandbox(hosts=("acme.example",), osint=(DOCS,))
    try:
        d, why = decide(root, "nuclei -u https://acme.example")
        chk("a scanner still runs against the real target", d == "allow", (d, why[:160]))
        d, why = decide(root, "ffuf -u https://acme.example/FUZZ -w list.txt")
        chk("a fuzzer still runs against the real target", d == "allow", (d, why[:160]))
        d, why = decide(root, "curl -X POST -d 'a=1' https://acme.example/api")
        chk("a POST still runs against the real target", d == "allow", (d, why[:160]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_no_osint_sources_changes_nothing():
    print("[osint] it STAYS QUIET — 16 live engagements have no osint_sources and must not change")
    root = sandbox(hosts=("acme.example",), osint=())
    try:
        for cmd in ["nuclei -u https://acme.example",
                    "ffuf -u https://acme.example/FUZZ -w w.txt",
                    "curl -X POST -d x=1 https://acme.example/a",
                    "curl -s https://acme.example/"]:
            d, why = decide(root, cmd)
            chk(f"unchanged: {cmd[:38]}", d == "allow", (d, why[:120]))

        d, why = decide(root, f"curl -s https://{DOCS}/")
        chk("an unlisted host is still refused by the ordinary asset wall", d == "deny",
            (d, why[:120]))
        chk("and refused as an ASSET problem, not an OSINT one",
            "asset scope" in why.lower(), why[:160])
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_host_that_is_both():
    print("[osint] a host that is BOTH a target and a doc source is governed by the real scope")
    root = sandbox(hosts=(DOCS,), osint=(DOCS,))
    try:
        d, why = decide(root, f"nuclei -u https://{DOCS}")
        chk("the program authorised it as a target, so testing it is allowed",
            d == "allow", (d, why[:160]))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_compiler_validation():
    print("[osint] the compiler refuses grants that would be wider than they look")
    import scope_compiler as sc

    def raises(cfg):
        try:
            sc.osint_sources_for(cfg)
            return False
        except sc.ScopeError:
            return True

    chk("a URL is refused (the wall matches hosts; a path would be ignored)",
        raises({"osint_sources": ["https://docs.vendor.example/manual"]}))
    chk("a wildcard is refused (it would grant a whole domain unreviewed)",
        raises({"osint_sources": ["*.vendor.example"]}))
    chk("a non-list is refused", raises({"osint_sources": "docs.vendor.example"}))
    chk("an empty entry is refused", raises({"osint_sources": ["  "]}))

    chk("absent means none — no engagement gains a grant by upgrading",
        sc.osint_sources_for({}) == [])
    chk("hosts are normalised and de-duplicated",
        sc.osint_sources_for({"osint_sources": ["Docs.Vendor.Example", "docs.vendor.example"]})
        == ["docs.vendor.example"])


def test_compiled_profile_keeps_them_separate():
    print("[osint] compiled output keeps OSINT out of hosts — merging would re-open the hole")
    import scope_compiler as sc
    cfg = {"osint_sources": ["docs.vendor.example"]}
    osint = sc.osint_sources_for(cfg)
    chk("osint_sources_for returns them", osint == ["docs.vendor.example"])
    # The real guarantee: the compiler writes them under assets.osint, never appended to hosts.
    src = open(os.path.join(WORKSPACE, "global", "scope", "scope_compiler.py")).read()
    merged = 'cfg["hosts"] + recon_sources_for(cfg) + osint_sources_for(cfg)'
    chk("the compiler does NOT fold osint into hosts", merged not in src,
        "folding them together silently re-creates the exact hole this closes")
    chk("the compiler emits a separate assets.osint key", '"osint": osint_sources_for(cfg)' in src)


def main():
    for fn in [test_reading_is_permitted,
               test_testing_is_refused,
               test_real_targets_are_untouched,
               test_no_osint_sources_changes_nothing,
               test_host_that_is_both,
               test_compiler_validation,
               test_compiled_profile_keeps_them_separate]:
        fn()
        print()
    print(f"{_PASS} passed, {_FAIL} failed")
    return 1 if _FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
