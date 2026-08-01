#!/usr/bin/env python3
"""
PreToolUse enforcement hook — Phase 2 "Absolute Boundary" (binary + asset destination).

Blocks any Bash command that either (a) invokes a binary NOT in the active engagement's
approved allow-list, or (b) targets a destination (URL host / IP) OUTSIDE the engagement's
approved asset boundaries — and always blocks anything matching the deny-list. Dependency-free
(Python 3 stdlib only): reads the hook payload from stdin as JSON and the compiled engagement
profile from `.scope_lock/enforcement.json`, and returns a PreToolUse permission decision on
stdout.

Design notes:
  * Fail CLOSED. Any parse error, missing state, or uncertainty => deny.
  * Enforcement operates on the *actual binary* and the *actual destination* about to be hit
    (what software can truly see), not on abstract "techniques". /generate-scope compiles the
    approved TTP objects + scope into the flat allow-lists this hook checks.
  * Basic read-only/navigation builtins are always allowed so the operator can inspect scope
    files and set up an engagement even before a scope is approved. Offensive tooling is not.
  * Asset enforcement only applies to commands that invoke a non-safe (offensive) binary, so
    benign local commands that merely mention a URL string aren't blocked.

State / inputs (under CLAUDE_PROJECT_DIR = workspace root):
  .claude/state/active_engagement                 -> name of the loaded engagement folder
  engagements/<name>/.scope_lock/enforcement.json -> compiled profile (see keys below)

enforcement.json shape (all keys optional; missing => empty):
  {
    "engagement": "acme",
    "approved": true,
    "allowed_binaries": ["sqlmap", "ffuf", "curl", ...],
    "denied_patterns": ["--os-shell", "rm\\s+-rf\\s+/", ...],
    "always_allowed_extra": ["nuclei", ...],
    "assets": {
      "hosts":     ["example.com", "api.example.com"],
      "wildcards": ["*.example.com"],
      "cidrs":     ["10.0.0.0/24"],
      "ips":       ["203.0.113.10"]
    }
  }
"""

import ipaddress
import json
import os
import re
import shlex
import sys

HOOK_EVENT = "PreToolUse"

DEFAULT_SAFE = {
    "cd", "ls", "pwd", "echo", "printf", "cat", "head", "tail", "wc", "sort", "uniq",
    "cut", "tr", "grep", "egrep", "fgrep", "diff", "file", "stat", "basename", "dirname",
    "realpath", "readlink", "mkdir", "touch", "cp", "mv", "tee", "test", "true",
    "false", "date", "which", "type", "less", "more", "tree", "column", "nl", "tac",
    # local, non-network utilities needed to set up / inspect an engagement and run
    # /generate-scope (hashing the scope file, local text munging, reading the framework repo).
    "sha256sum", "shasum", "md5sum", "sed", "awk", "git",
    # VERIFICATION tools. Read-only, local, and target-independent: they inspect a file that is
    # already on disk and cannot reach a target. They are here rather than in a scope-lock because
    # the allow-list is compiled from approved TTPs, and "scan the thing I just downloaded" is not a
    # TTP — so without this it could never appear on any engagement, and the one safety step the
    # operator specifically asked for was the one step that could not run.
    # Deliberately NOT included: `freshclam` (fetches signature updates) and `gpg` (--recv-keys hits
    # a keyserver). Both can reach the network, so they stay an operator action. `gpgv` verifies
    # against a local keyring only.
    "clamscan", "gpgv", "sha512sum", "b2sum", "cksum",
    # Shell builtins that ARE commands: local, non-network, and unavoidable in ordinary scripting.
    # They live here rather than in a skip list so they are recognised and allowed — skipping them
    # would leave a command with no identifiable binary, which fails closed. `[` and `[[` are the
    # test builtin; without them every `if [ -f x ]` was denied.
    "[", "[[", ":", "read", "local", "declare", "shift", "return", "break", "continue",
    "unset", "export", "set", "eval_", "printf", "sleep", "seq", "xargs", "env",
}

INTRODUCERS = {"sudo", "env", "xargs", "nohup", "nice", "time", "watch", "command", "then",
               "do", "exec", "-exec", "-execdir", "-ok", "timeout", "stdbuf", "setsid",
               # Shell KEYWORDS. Without these, `if [ -f x ]; then …` had `if` read as a program
               # name and denied as "not in the approved allow-list" — an ordinary conditional
               # blocked as though it were offensive tooling. They introduce a command; they are
               # never themselves one.
               "if", "elif", "else", "fi", "while", "until", "done",
               "esac", "function", "{", "}", "!", "coproc"}

#: `for x in a b c` / `select` / `case x in` are followed by a VARIABLE and a WORD LIST, not by a
#: command. Treating them as plain introducers made `for t in testing/*.py; do …` read the glob as
#: a program name. So they suppress binary-detection until the keyword that genuinely introduces
#: one — `do` or `then` — arrives. `;` does not end the suppression, because in `for … ; do` the
#: semicolon sits in the middle of the construct rather than between two commands.
LIST_KEYWORDS = {"for", "select", "case"}
RESUME_KEYWORDS = {"do", "then"}

#: Shell builtins that are not programs and can never be offensive tooling. `[` is the one that
#: actually bit: `if [ -f x ]; then …` denied with "'[' is NOT in the approved allow-list".
#: They are skipped rather than allow-listed — a builtin is not a binary, so it does not belong in
#: an engagement's binary allow-list in the first place.
#: ONLY pure syntax — tokens that terminate a construct and are never a command in their own right.
#: Deliberately narrow. An earlier version also listed `echo`, `test`, `read` and friends here, which
#: was wrong in a way worth recording: those ARE commands, so skipping them left `echo $((1 + 2))`
#: with no binary at all, and "could not identify the command's binary" is a fail-CLOSED deny. The
#: skip list must contain only things that can never be the command; anything that can belongs in
#: DEFAULT_SAFE, where it is recognised and allowed rather than made invisible.
SHELL_BUILTINS = {"]", "]]"}

#: Redirection operators. The token AFTER one is a FILENAME, never a command — `while read l;
#: do …; done < f` was denying because `<` was read as a program and then `f` as another.
REDIRECT_RE = re.compile(r"^(?:\d?)(?:<{1,3}|>{1,2}|&>|>&|<>)$")

#: Tokens that follow an introducer but cannot possibly be a program name — a duration or a count.
#: `timeout 60 curl …` previously read `60` as the binary and denied it, which blocked the
#: framework's OWN documented pattern (`timeout 2h <cmd>`, global/CLAUDE.md §2F-NET). The wall and
#: the manual disagreed, and the wall was wrong.
NON_BINARY_ARG_RE = re.compile(r"^\d+(?:\.\d+)?[smhdSMHD]?$")

#: A heredoc body is DATA being written, not a command line. Parsing it as one made every inline
#: `python3 - <<'PY' … PY` a minefield: `collections.Counter` was read as a hostname and denied as
#: an out-of-scope target.
#:
#: Stripping it costs no real protection. A destination inside a heredoc is only ever contacted
#: once the resulting script RUNS — and at that point the command line is `python3 script.py`, in
#: which the hook can already see nothing. The gap existed either way; this only stops the wall
#: firing on text that was never a command. The HARD FLOOR still scans the untouched original.
HEREDOC_RE = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1\s*\n.*?^\s*\2\s*$",
                        re.DOTALL | re.MULTILINE)


#: `python -m <module>` / `python3 -m <module>`. The operand is an import path, which is shaped
#: identically to a hostname (`orchestrator.cli`, `http.server`, `json.tool`). Matched only with
#: python as the program so another tool's `-m` flag keeps being inspected normally.
PY_MODULE_RE = re.compile(r"\bpython[0-9.]*\s+(?:-[A-Za-z]+\s+)*-m\s+[A-Za-z_][\w.]*")

#: The VALUE of a Cookie header. Session blobs routinely embed version strings (`1.0.1.1` in
#: Cloudflare's `__cf_bm`) that are shaped exactly like IPv4 addresses, so scanning them for
#: destinations denies legitimate replay of a captured authenticated request. Only the value is
#: removed — the URL the tool actually connects to is still inspected, which is what scope is
#: about: a cookie cannot change where the connection goes.
#: Alongside Cookie: `Origin` and `Referer`. All three are request METADATA describing the caller,
#: never the destination — curl connects to the URL, and no header value can change that. Testing
#: CORS requires sending an Origin the target does not own (that IS the test), and reading it as a
#: target denied a standard, non-destructive preflight against an in-scope host.
#:
#: Scoped deliberately to these three rather than all headers: a header like `X-Forwarded-For` can
#: still legitimately reveal a host worth noticing, and narrowing the parse further than necessary
#: is how a wall stops seeing things.
OPAQUE_HEADERS = ("Cookie", "Origin", "Referer")
COOKIE_HEADER_RE = re.compile(
    r"""(?:-H|--header)\s+(?P<q>['"])\s*(?:%s)\s*:.*?(?P=q)""" % "|".join(OPAQUE_HEADERS),
    re.IGNORECASE | re.DOTALL)


def strip_heredoc_bodies(cmd):
    """Replace heredoc bodies with the delimiter alone, keeping the command line itself intact."""
    try:
        return HEREDOC_RE.sub(lambda m: "<<" + m.group(2) + "\n", cmd)
    except (re.error, RecursionError):
        return cmd

OPERATOR_RE = re.compile(r"^(\||\|\||&&|&|;|\(|\))$")
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# shell wrappers that hide the real binary inside a quoted string argument
# (`bash -c "sqlmap ..."`, `eval "nmap ..."`) — without unwrapping these, only the
# wrapper ('bash'/'eval') would be seen and the offensive binary would slip past.
SHELL_C_RE = re.compile(r"\b(?:bash|sh|zsh|dash|ksh|ash)\b[^\n]*?\s-c\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))")
EVAL_RE = re.compile(r"\beval\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))")

# flags by which common offensive tooling reads its target list FROM A FILE (invisible on
# the command line): nmap -iL, httpx/nuclei -l/-list, subfinder -dL, etc.
TARGET_LIST_FLAGS = {"-iL", "-l", "-list", "--list", "-dL", "--targets", "--target-list"}

URL_RE = re.compile(r"https?://([^/\s\"'`>|\\]+)", re.I)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
FQDN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
# extensions that make a dotted token a filename, not a hostname
FILE_EXT = {"txt", "js", "json", "yaml", "yml", "md", "html", "htm", "php", "xml", "csv",
            "log", "sh", "conf", "cfg", "ini", "env", "png", "jpg", "jpeg", "gif", "svg",
            "pdf", "zip", "gz", "tar", "py", "go", "rb", "bak", "old", "map", "ts", "css",
            "pem", "key", "crt", "sql", "db", "bin", "exe", "dll",
            # Archive/package/signature extensions. Without these, `node-v24.18.1-linux-x64.tar.xz`
            # is read as a hostname and an approved download is denied - which happened repeatedly
            # on 2026-07-29 and blocked a toolchain install twice.
            # `so` is deliberately absent: it is Somalia's ccTLD, and a real host could end in it.
            "xz", "tgz", "zst", "lz", "tbz", "whl", "wasm", "sig", "asc", "lock",
            "deb", "rpm", "apk", "jar", "war", "iso", "dmg", "msi", "node",
            # JS/TS module extensions. Same defect as the archive block above, found the same way:
            # `node harness.mjs` was denied because `mjs` was read as a TLD. These are unavoidable
            # when a PoC targets a JS/TS codebase, which is most of this workspace's source-audit
            # work. None is a real TLD.
            "mjs", "cjs", "mts", "cts", "tsx", "jsx", "vue", "svelte",
            # The framework's OWN encrypted-artifact extension (ENC_SUFFIX in
            # execution/remote_data.py). Every result pulled home from the executor is
            # `<name>.cms`, so reading one was denied with "cms is outside the approved
            # asset scope" - the filename was parsed as an FQDN. Not a real TLD.
            "cms"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}

# Non-negotiable HARD FLOOR — enforced in EVERY mode (even soft-boundary / autonomous), for EVERY
# engagement, and NOT removable by editing enforcement.json. This is what makes autonomous
# self-adding safe: no matter what a scope profile says or an agent adds, these are never allowed.
#   * DoS / flooding / stress          * credential brute-forcing / stuffing   * destructive/system
HARDCODED_DENY = [
    r"\bhping3\b", r"\bslowloris\b", r"\bt50\b", r"--flood\b", r"\bsiege\b", r"\btorshammer\b",
    r"\bgoldeneye\b", r"\bmhddos\b", r"\bhulk\b", r"\bab\b\s+[^\n]*-n\s*\d{5,}",
    r"\bhydra\b", r"\bmedusa\b", r"\bpatator\b", r"\bncrack\b", r"\bthc-hydra\b", r"\bbrutespray\b",
    # Anonymizing / location-changing connections — FORBIDDEN (WAF/detection evasion + Anthropic-account-flag risk):
    r"\btorsocks\b", r"\bproxychains(?:-ng|4)?\b", r"(?:^|[\s;&|])tor(?:\s|$)", r"\bopenvpn\b", r"\bwg-quick\b", r"\bproxifier\b",
    r"\brm\s+-rf\s+/(?:\s|$|\*)", r"\bmkfs\b", r"\bdd\b[^\n]*of=/dev/",
    r"\b(?:shutdown|reboot|halt|poweroff)\b", r":\(\)\s*\{\s*:\s*\|", r"\bmkfs\.\w+\b",
    # Rate / concurrency HARD CEILING — block abusively fast scans in software, regardless of
    # engagement or instruction. Gentle testing uses single/double-digit rates & threads; a 3-digit+
    # request rate or thread count (100+) is bombardment. The per-engagement gentle default and the
    # program's own limit are enforced above this; this is only the un-crossable floor.
    r"-rate\s+\d{3,}", r"-rl\s+\d{3,}", r"--rate-limit[=\s]\d{3,}",
    r"--threads[=\s]\d{3,}", r"-t\s+\d{3,}",
]


def emit(decision, reason=""):
    out = {"hookSpecificOutput": {"hookEventName": HOOK_EVENT, "permissionDecision": decision}}
    if reason:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
    sys.stdout.write(json.dumps(out))
    sys.exit(0)


#: What makes a directory a workspace root: `engagements/` (where the scope locks the hook reads
#: actually live) PLUS at least one of `global/` or `.claude/`.
#:
#: The pairing is deliberate. `engagements/` alone would be too loose — matching a directory that
#: merely shares the name would send the hook looking for scope locks that do not exist, and a
#: workspace with no readable lock denies EVERYTHING (Phase-1 lockdown), including `python3`. That
#: is not a hypothetical: it happened while building this, and it locks the operator out of their
#: own machine. `global/` alone would be far too loose in the other direction. Requiring
#: `engagements/` and one corroborating sibling matches every real workspace and every test
#: fixture, and matches a home directory not at all.
WORKSPACE_ANCHOR = "engagements"
WORKSPACE_CORROBORATORS = ("global", ".claude")

#: Written by the operator to say "this machine has a workspace, and it is here." Read when the
#: session was not started inside one. See resolve_workspace_root() for why this exists.
WORKSPACE_REGISTRY = "~/.config/offsec/workspace_root"


def _is_workspace(path):
    try:
        if not os.path.isdir(os.path.join(path, WORKSPACE_ANCHOR)):
            return False
        return any(os.path.exists(os.path.join(path, c)) for c in WORKSPACE_CORROBORATORS)
    except (OSError, TypeError):
        return False


def _walk_up(start, limit=12):
    """Yield start and each parent, bounded so a pathological path cannot spin."""
    cur = os.path.abspath(start) if start else None
    for _ in range(limit):
        if not cur:
            return
        yield cur
        parent = os.path.dirname(cur)
        if parent == cur:
            return
        cur = parent


def resolve_workspace_root(payload):
    """Find the workspace this command belongs to, however the session was started.

    WHY THIS EXISTS — a real failure, found 2026-07-28.
    Claude Code loads hooks from the SESSION's project root and exports it as CLAUDE_PROJECT_DIR.
    Before this function, the hook trusted that value directly. A session started at ~ therefore
    looked for the workspace in ~, did not find it, and fell through to Phase-1 lockdown — which
    LOOKS safe, and is, but only because it denies everything including `python3`.

    Worse in the other direction: because the hooks were registered only inside the workspace, a
    session started anywhere else never invoked this file at all. `curl` to an arbitrary host ran
    from the operator's home line with nothing in the way. The wall was correct and simply not
    plugged in — every test of its LOGIC passed while it protected nothing.

    So the root must be resolved from where the WORK is, not from where the session began:

        1. CLAUDE_PROJECT_DIR, if it really is a workspace
        2. walking up from the command's own cwd  (the common case: session at ~, work in the bucket)
        3. walking up from this process's cwd
        4. the registry file — the operator declaring the workspace for the whole machine, which is
           what makes a globally-registered hook protect a session started anywhere
        5. failing all of that, the old value, so behaviour is unchanged where no workspace exists

    Returns (root, how) — `how` is carried into denial messages so a block is explicable.
    """
    env_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if env_dir and _is_workspace(env_dir):
        return env_dir, "CLAUDE_PROJECT_DIR"

    for cand in _walk_up((payload or {}).get("cwd")):
        if _is_workspace(cand):
            return cand, "command cwd"

    try:
        for cand in _walk_up(os.getcwd()):
            if _is_workspace(cand):
                return cand, "process cwd"
    except OSError:
        pass

    reg = os.path.expanduser(WORKSPACE_REGISTRY)
    try:
        if os.path.isfile(reg):
            with open(reg, encoding="utf-8") as fh:
                declared = os.path.expanduser(fh.read().strip())
            if declared and _is_workspace(declared):
                return declared, "workspace registry"
    except OSError:
        pass

    return (env_dir or (payload or {}).get("cwd") or os.getcwd()), "unresolved"


def load_profile(project_dir):
    # Engagement selection, in priority order — enables PARALLEL work on DIFFERENT engagements
    # in DIFFERENT terminals without them sharing one pointer:
    #   1. $AO_ENGAGEMENT — a per-terminal env var. The hook subprocess inherits the launching
    #      shell's environment, so `AO_ENGAGEMENT=programs/... claude …` pins THAT session to THAT
    #      engagement's scope-lock, isolated from any other terminal.
    #   2. the shared pointer file .claude/state/active_engagement (single-session default).
    # Fail-closed: no valid selection => (None, None) => locked down. Path traversal is rejected so
    # the name can only ever SELECT a scope-lock inside engagements/ — it can never widen or escape scope.
    name = (os.environ.get("AO_ENGAGEMENT") or "").strip() or None
    if not name:
        pointer = os.path.join(project_dir, ".claude", "state", "active_engagement")
        try:
            with open(pointer, encoding="utf-8") as fh:
                name = next((ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")), None)
        except OSError:
            return None, None
    if not name:
        return None, None
    if os.path.isabs(name) or ".." in name.replace("\\", "/").split("/"):
        return None, None                                   # never escape the engagements/ tree
    path = os.path.join(project_dir, "engagements", name, ".scope_lock", "enforcement.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return name, json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        # selected but profile unreadable => treat as locked (fail-closed), but signal name
        return name, {}


# ---- program rate ceiling ------------------------------------------------------------------
# Duplicated from scope_compiler._RATE_ALIASES rather than imported: this hook must run standalone
# from a bare `python3 enforce_scope.py` with no package on the path. Keep the two in step — if a
# tool gains a rate flag in the compiler, add it here too, or the wall silently stops covering it.
#
# A tool's short and long forms are the SAME option, so checking only one is how `-rate-limit 5 …
# -rl 20` once got through with an effective rate of 20.
_RATE_ALIASES = {
    "dnsx":        ("-rate-limit", "-rl"),
    "httpx":       ("-rate-limit", "-rl"),
    "katana":      ("-rate-limit", "-rl"),
    "subfinder":   ("-rate-limit", "-rl"),
    "nuclei":      ("-rate-limit", "-rl"),
    "naabu":       ("-rate",),
    "ffuf":        ("-rate", "-rate-limit"),
    "feroxbuster": ("--rate-limit",),
    "arjun":       ("--rate-limit",),
}

# `--delay` is the INVERSE of a rate — a SMALLER number means FASTER. Comparing it against a
# requests-per-second ceiling would be backwards, so these are deliberately NOT covered here.
# Stated rather than silently omitted: a gap you can see is a gap someone can close.
_DELAY_TOOLS = ("gobuster", "dalfox", "sqlmap")


def rate_violation(command, ceiling):
    """Return (binary, flag, value) for the first rate flag exceeding the program's ceiling.

    Scans the WHOLE command, not just the first segment. A chained
    `httpx -rl 5 … && nuclei -rl 80 …` must not pass because its first half is compliant — that
    is exactly how a constraint ends up holding for part of a command and quietly not the rest.
    """
    if not ceiling or ceiling <= 0:
        return None
    for binary, aliases in _RATE_ALIASES.items():
        if not re.search(rf"(^|[\s/`;&|]){re.escape(binary)}(\s|$)", command):
            continue
        for alias in aliases:
            for m in re.finditer(rf"(?<![\w-]){re.escape(alias)}[\s=]+(\d+)", command):
                try:
                    value = int(m.group(1))
                except ValueError:
                    continue
                if value > ceiling:
                    return binary, alias, value
    return None


# --------------------------------------------------------------------- execution location
#
# THE GAP THIS CLOSES (measured 2026-07-27, same shape as the rate-ceiling gap the night before):
#
#   The operator's rule is "no tools running on my home network" — stated as being the same tier
#   as scope itself. The framework documented it in CLAUDE.md §2F-NET and remote_exec.py, in both
#   cases as a RULE THE AGENT FOLLOWS: "nothing routes automatically; a tool you invoke through
#   Bash runs HERE, on the home IP, no matter what the mode says."
#
#   Nothing enforced it. With an engagement resolving to `remote`, a hand-typed
#   `httpx -u https://<in-scope-host> -rl 5` was ALLOWED by this wall — in-scope host, compliant
#   rate — and would have run from the operator's residential line. The wall checked WHAT and HOW
#   FAST. It never checked WHERE FROM.
#
#   That is the third time the same pattern has appeared: confident prose describing a protection
#   that no code implements. Scope had a wall. Rate got one. Location now has one.
#
# HOW A LEGITIMATE REMOTE DISPATCH GETS THROUGH:
#   remote_exec.run_remote() validates the BARE tool command against this hook before it builds the
#   SSH invocation — deliberately, so offloading can never become a way around the asset wall. That
#   means the dispatcher's own pre-flight check looks identical to an agent typing the command
#   directly. It signals itself with AO_REMOTE_DISPATCH=1 in the hook's ENVIRONMENT.
#
#   Why an env var is sound here, stated plainly rather than assumed: this hook runs as a subprocess
#   of the harness, so its environment is set by the harness and by run_remote — NOT by the command
#   being validated. An agent writing `AO_REMOTE_DISPATCH=1 httpx ...` puts that text in the command
#   STRING, which this hook reads as data; it does not become a variable in this process. Shell
#   state does not persist between Bash calls either. It is a signal, not a cryptographic proof, and
#   its integrity rests on that separation — which is why it is documented instead of quietly relied on.
#
# THE DELIBERATE OFF SWITCH:
#   settings.EXECUTE_MODE = "local". That is a specific, typed statement that tools should run here,
#   which is exactly the "unless I tell you otherwise, and I should be sure I'm telling you" the
#   operator asked for. Lowering HARD_BOUNDARIES does NOT lift this, for the same reason it does not
#   lift the rate ceiling: shields-down relaxes constraints we chose for ourselves, and this one is
#   the operator's standing instruction about their own home network.

_NETWORK_BINARIES = frozenset({
    # active scanners / probers — these put packets on a target
    "httpx", "dnsx", "nuclei", "ffuf", "feroxbuster", "gobuster", "naabu", "nmap", "masscan",
    "katana", "sqlmap", "dalfox", "arjun", "wpscan", "gowitness", "interactsh-client", "puredns",
    "massdns", "wfuzz", "dirb", "nikto", "testssl.sh", "sslscan", "hydra", "amass",
    # passive / aggregator tools — these do NOT touch the target, they query third-party indexes.
    # Included anyway because the operator's rule is about tools running on their home network, not
    # only about target traffic, and a simple rule that matches what they said beats a clever one
    # that needs a footnote. Same call as the rate ceiling. If it becomes annoying, removing these
    # is a one-line change and a deliberate one.
    "subfinder", "assetfinder", "gau", "waybackurls", "whois",
    # general HTTP clients, only when actually aimed at something (see location_violation)
    "curl", "wget",
})

# A command that STARTS with one of these is transport, not a local scan: it is how work reaches
# the executor. The asset wall still inspects the destination, so this is not a bypass.
_TRANSPORT_BINARIES = frozenset({"ssh", "scp", "rsync", "sftp"})

# Hosts that distribute TOOLCHAINS and PACKAGES. Fetching from one of these is PROVISIONING, not
# testing: it tells an observer "this machine installs Node", never "this machine is interested in
# <target>". Sending it to the executor would also be pointless - it would put the binary on a box
# that is not the one that needs it.
#
# This closes a real conflation. Without it, "no testing traffic from my machine" gets read as "this
# machine may not reach the internet at all", so the agent concludes it cannot obtain a tool it needs
# and stops. That is not what the rule says.
#
# HARD-CODED and target-independent BY DESIGN: never read from an engagement, never widened at
# runtime, exact authority match only - `nodejs.org.evil.com` does not qualify.
#
# DELIBERATELY NOT HERE:
#   github.com / raw.githubusercontent.com / gitlab.com - cloning a repo reveals WHICH target you
#     are interested in. That is target-linked traffic even though the host is generic.
#   NVD / GHSA / MITRE / vendor advisory hosts - target-linked for the same reason. Those go through
#     the SS2F-WEB advisory allow-list, which is a separate decision.
#
# Scope is untouched: this affects only WHERE a fetch may run, never WHETHER the host is in scope.
# A provisioning host still has to be in the engagement's assets to be reachable at all.
_PROVISIONING_HOSTS = frozenset({
    "nodejs.org",
    "registry.npmjs.org",
    "pypi.org", "files.pythonhosted.org",
    "proxy.golang.org", "sum.golang.org",
    "crates.io", "static.crates.io",
    "rubygems.org",
    "deb.debian.org", "security.debian.org", "archive.ubuntu.com", "ports.ubuntu.com",
})


def _url_authorities(seg):
    """Every non-loopback URL authority in a segment: lowercased, userinfo/port/trailing dot stripped.

    Returns [] when the segment carries no scheme'd URL at all - a local file read or a bare loopback
    call - which is why `curl -o out.json somefile` is not treated as network work.
    """
    hosts = []
    for auth in re.findall(r"https?://([^/\s\"'`>|\\]+)", seg, re.I):
        host = auth.rsplit("@", 1)[-1]                      # drop user:pass@
        if host.startswith("["):                            # bracketed IPv6 literal
            host = host[1:host.index("]")] if "]" in host else host[1:]
        else:
            host = host.split(":", 1)[0]                    # drop :port
        host = host.rstrip(".").lower()
        if host in ("localhost", "::1", "0.0.0.0") or host.startswith("127."):
            continue
        hosts.append(host)
    return hosts


def _is_engagement_target(host, profile):
    """True when this host is in the engagement's scope as a TARGET, not merely approved egress.

    Guards the one case where the provisioning exemption would be wrong: a program whose asset IS a
    package registry (GitHub and npm both run bounty programs). `assets.hosts` cannot answer this -
    it is overloaded, holding both real targets and operator-approved egress hosts like nodejs.org -
    but a program that owns a registry would carry it as a wildcard/apex, which is unambiguous.
    """
    assets = (profile or {}).get("assets") or {}
    for entry in (assets.get("wildcards") or []):
        apex = str(entry).lstrip("*").lstrip(".").rstrip(".").lower()
        if apex and (host == apex or host.endswith("." + apex)):
            return True
    return False


def execution_is_remote(project_dir):
    """True / False / None(unknown) — does execution resolve to a remote executor?

    Read live from settings.py rather than frozen into the scope-lock, because the executor is a
    machine-level fact that can change without recompiling any engagement. A stale copy in the lock
    would be a second source of truth, and the wrong one.
    """
    exec_dir = os.path.join(project_dir, "global")
    if not os.path.isdir(os.path.join(exec_dir, "execution")):
        return None
    saved = list(sys.path)
    try:
        sys.path.insert(0, exec_dir)
        from execution import settings as _S      # noqa: PLC0415
        return _S.resolve_mode() == "remote"
    except Exception:                              # noqa: BLE001 — see comment in main()
        return None
    finally:
        sys.path[:] = saved


def location_violation(command, is_remote, profile=None):
    """Return the offending binary when a network tool would run HERE but should run on the executor.

    Returns None when: execution is local or unknown, the dispatcher is calling, the command is a
    transport invocation, no network-facing binary is present, or a curl/wget fetch is aimed only at
    toolchain-distribution hosts (see _PROVISIONING_HOSTS).
    """
    if is_remote is not True:
        return None
    if os.environ.get("AO_REMOTE_DISPATCH") == "1":
        return None

    segs = [s.strip() for s in _segments(command) if s.strip()]
    for seg in segs:
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        if not toks:
            continue
        # skip leading VAR=value assignments and `sudo`/`env` wrappers to find the real binary
        idx = 0
        while idx < len(toks) and (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", toks[idx])
                                   or toks[idx] in ("sudo", "env", "nohup", "setsid")):
            idx += 1
        if idx >= len(toks):
            continue
        binary = os.path.basename(toks[idx])
        if binary in _TRANSPORT_BINARIES:
            return None                            # the whole command is a dispatch; let it through
        if binary in _NETWORK_BINARIES:
            # curl/wget are general-purpose; only flag them when aimed at a real remote destination,
            # so reading a local file or hitting localhost is not swept up.
            if binary in ("curl", "wget"):
                hosts = _url_authorities(seg)
                if not hosts:
                    continue                       # local file, loopback, or no URL at all
                # Provisioning is not testing traffic. Exempt only when EVERY destination in the
                # command is a toolchain host AND none of them is this engagement's actual target.
                if all(
                    h in _PROVISIONING_HOSTS and not _is_engagement_target(h, profile)
                    for h in hosts
                ):
                    continue
            return binary
    return None


def split_command_substitutions(cmd):
    """Return (bodies, scrubbed) for every `$( … )` and `` ` … ` `` span, handling NESTED parens.

    Replaces a pair of regexes that both used `\\$\\(([^()]*)\\)` — a body that cannot contain a
    parenthesis. Any substitution holding one (`$(grep -E '^(OK|FAILED)' f)`, an arithmetic
    expression, a nested call) matched NEITHER, with two consequences:

      * the inner command was never extracted, so the binary running inside it was never checked —
        a real coverage hole, not a cosmetic one;
      * the span was not scrubbed either, so its raw fragments were tokenised as program names and
        denied. `python3 $L "…"` was refused as a binary called `$L`.

    Balanced scanning fixes both at once: MORE commands actually get checked, and fewer ordinary
    ones get blocked. `bodies` feeds the recursive binary check; `scrubbed` keeps the outer parse
    from tripping over the fragments.
    """
    bodies, out, i, n = [], [], 0, len(cmd)
    while i < n:
        if cmd.startswith("$((", i):
            # ARITHMETIC expansion, not a command substitution. Nothing inside it is ever executed,
            # so it contributes no binaries — `$((1 + 2))` was yielding a program named "(1".
            depth, j = 0, i + 1
            while j < n:
                if cmd[j] == "(":
                    depth += 1
                elif cmd[j] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            out.append(" ")
            i = (j + 1) if j < n else n
            continue
        if cmd.startswith("$(", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if cmd.startswith("$(", j):
                    depth += 1
                    j += 2
                    continue
                if cmd[j] == "(":
                    depth += 1
                elif cmd[j] == ")":
                    depth -= 1
                    if not depth:
                        break
                j += 1
            if depth == 0:                      # balanced: take the body, drop the span
                bodies.append(cmd[i + 2:j])
                out.append(" ; ")
                i = j + 1
                continue
            # Unbalanced. Do NOT silently pass the remainder through as ordinary tokens —
            # an unparseable command is exactly where fail-closed belongs.
            bodies.append(cmd[i + 2:])
            out.append(" ; ")
            break
        if cmd[i] == "`":
            j = cmd.find("`", i + 1)
            if j == -1:
                bodies.append(cmd[i + 1:])
                out.append(" ; ")
                break
            bodies.append(cmd[i + 1:j])
            out.append(" ; ")
            i = j + 1
            continue
        out.append(cmd[i])
        i += 1
    return bodies, "".join(out)


def extract_subcommands(cmd):
    """The inner command text of every substitution, so its binaries are checked too."""
    return split_command_substitutions(cmd)[0]


def candidate_binaries(cmd):
    # A heredoc body is data, not a command line — see HEREDOC_RE. The hard floor still scans the
    # untouched original in main(); this only narrows what is PARSED as a program name.
    cmd = strip_heredoc_bodies(cmd)
    bins = set()
    sub_bodies, sub_scrubbed = split_command_substitutions(cmd)
    for sub in sub_bodies:
        if sub.strip() and sub != cmd:
            bins |= candidate_binaries(sub)
    # unwrap `bash -c "..."` / `sh -c '...'` / `eval "..."` so a binary hidden inside the
    # quoted payload is still checked, not just the wrapper.
    for m in list(SHELL_C_RE.finditer(cmd)) + list(EVAL_RE.finditer(cmd)):
        inner = m.group(1) or m.group(2) or m.group(3) or ""
        if inner and inner != cmd:
            bins |= candidate_binaries(inner)
    scrubbed = sub_scrubbed          # balanced-scanned above; the bodies were checked separately
    try:
        tokens = shlex.split(scrubbed, comments=False, posix=True)
    except ValueError:
        tokens = re.split(r"\s+", scrubbed)
    expect = True
    suppress = False          # inside a `for … in …` word list, where nothing is a command
    skip_next = False         # the operand of a redirection: a filename, never a command
    for tok in tokens:
        if not tok:
            continue
        # shlex does not treat `;` as a separator, so `ls;` arrives as a single token and was
        # denied as a program named "ls;". Strip it, process the real token, and let the semicolon
        # do its job of introducing the next command.
        ends_command = tok.endswith(";")
        if ends_command:
            tok = tok.rstrip(";")
            if not tok:
                expect = True
                continue
        if skip_next:
            skip_next = False
            if ends_command:
                expect = True
            continue
        if REDIRECT_RE.match(tok):
            skip_next = True
            continue
        if tok in SHELL_BUILTINS:
            expect = False
            continue
        if tok in RESUME_KEYWORDS:
            suppress = False
            expect = True
            continue
        if tok in LIST_KEYWORDS:
            suppress = True
            expect = False
            continue
        if suppress:
            continue
        if OPERATOR_RE.match(tok):
            expect = True
            continue
        if tok in INTRODUCERS:
            expect = True
            continue
        if not expect:
            continue
        if ASSIGN_RE.match(tok):
            continue
        if tok.startswith("-"):
            continue
        if NON_BINARY_ARG_RE.match(tok):
            # A duration or count belonging to the introducer (`timeout 60 …`), not a program.
            # Stay in `expect` so the REAL binary after it is still checked — skipping the token
            # must not skip the command.
            continue
        bins.add(os.path.basename(tok))
        expect = ends_command      # a trailing `;` means the NEXT token starts a new command
    return bins


def extract_destinations(cmd):
    """URL hosts + bare IPv4s + FQDN tokens (excluding filenames).

    Heredoc bodies are excluded — see HEREDOC_RE for why that costs no real coverage.
    """
    cmd = strip_heredoc_bodies(cmd)
    # `python3 -m orchestrator.cli` — a MODULE PATH, not a hostname. It is shaped exactly like an
    # FQDN and was denied as an out-of-scope target, which blocked the framework's own CLI.
    # Scrubbed narrowly: only the operand of `-m`, and only when python is the program, so a real
    # host passed to some other tool's `-m` flag is still seen.
    cmd = PY_MODULE_RE.sub(" ", cmd)
    # A COOKIE VALUE is an opaque session blob, never a destination. Cloudflare's `__cf_bm` and
    # `cf_clearance` embed version strings like `1.0.1.1` and `1.2.1.1`, which match the IPv4
    # pattern exactly — so replaying a captured authenticated request was denied for "targeting"
    # 1.0.1.1. Only the cookie VALUE is removed; the rest of the command, including the URL curl
    # actually connects to, is still fully inspected.
    cmd = COOKIE_HEADER_RE.sub(" -H Cookie:<redacted> ", cmd)
    dests = set()
    for host in URL_RE.findall(cmd):
        host = host.split("@")[-1]          # strip userinfo
        host = host.split(":")[0]           # strip port
        if host:
            dests.add(host.lower())
    for ip in IPV4_RE.findall(cmd):
        dests.add(ip)
    # A URL's PATH/QUERY is NOT a destination — the command connects to the AUTHORITY, which the
    # URL_RE pass above already captured. Re-scanning the whole URL with FQDN_RE misread the dotted
    # FILENAME as a second target host: the approved download
    #     https://nodejs.org/dist/v24.18.1/node-v24.18.1-linux-x64.tar.xz
    # was DENIED for "targeting node-v24.18.1-linux-x64.tar.xz" (the trailing `.xz` slips past
    # FILE_EXT). Strip whole scheme'd URLs before the FQDN pass so only BARE (schemeless) fqdn tokens
    # are host-checked. This does NOT weaken the wall: any scheme-prefixed host — even inside a query
    # string — is still caught by the URL_RE pass above, and bare out-of-scope FQDNs are still caught
    # by the loop below. It only stops a filename in a URL path from being read as a target host.
    cmd_fqdn = re.sub(r"https?://[^\s\"'`>|\\]+", " ", cmd, flags=re.I)
    for tok in FQDN_RE.findall(cmd_fqdn):
        t = tok.lower()
        if t in dests:
            continue
        if t.rsplit(".", 1)[-1] in FILE_EXT:
            continue
        dests.add(t)
    return dests


def _resolve_existing(path, project_dir):
    """Resolve a possibly-relative path to an existing file (cwd or project root), else None."""
    for base in (None, project_dir):
        cand = os.path.expanduser(path if base is None else os.path.join(base, path))
        if os.path.isfile(cand):
            return cand
    return None


def file_fed_targets(command, project_dir, limit=262144):
    """Destinations pulled from a target-list FILE or STDIN that never appear on the command line.

    Returns (dests, unresolved). `unresolved` is True when the command sources targets from a
    file/stdin the hook could not read — the caller must then fail closed, because the asset
    boundary cannot be verified for invisible targets (e.g. `nmap -iL out.txt`, `httpx < list`)."""
    # Heredoc bodies first: `python3 - <<'PY' … PY` was matching the stdin-redirect regex below,
    # capturing the delimiter `'PY'` as a target-list FILE, failing to resolve it, and denying with
    # "sources targets from a file the hook could not read". A heredoc supplies literal text, not a
    # list of destinations.
    command = strip_heredoc_bodies(command)
    dests, files, unresolved = set(), [], False
    try:
        toks = shlex.split(command, comments=False, posix=True)
    except ValueError:
        toks = command.split()
    for i, t in enumerate(toks):
        if t in TARGET_LIST_FLAGS and i + 1 < len(toks):
            files.append(toks[i + 1])
        elif "=" in t and t.split("=", 1)[0] in TARGET_LIST_FLAGS:
            files.append(t.split("=", 1)[1])
    # stdin redirect: `tool < file`. The lookarounds exclude `<<` — that is a HEREDOC introducing
    # literal text, not a file of targets. Without them, `python3 - <<'PY'` captured the delimiter
    # `'PY'` as a target-list file, failed to resolve it, and denied every inline script.
    files += re.findall(r"(?<!<)<(?!<)\s*([^\s;&|<>]+)", command)
    # `cat file | tool` — the file's contents become the tool's stdin
    for m in re.finditer(r"\b(?:cat|type)\s+([^|;&<>]+?)\s*\|", command):
        try:
            files += shlex.split(m.group(1))
        except ValueError:
            unresolved = True
    for f in files:
        if f in ("-", "/dev/stdin") or f.startswith("$") or "*" in f or "?" in f:
            unresolved = True                       # stdin dash / variable / glob => can't verify
            continue
        real = _resolve_existing(f, project_dir)
        if not real:
            unresolved = True
            continue
        try:
            with open(real, encoding="utf-8", errors="ignore") as fh:
                dests |= extract_destinations(fh.read(limit))
        except OSError:
            unresolved = True
    return dests, unresolved


def assets_nonempty(assets):
    return any(assets.get(k) for k in ("hosts", "wildcards", "cidrs", "ips"))


def read_hard_boundaries(project_dir):
    """Read the HARD_BOUNDARIES safety valve from the workspace config.

    The operator flips this in `global/CLAUDE.md` §0 CONFIG (a single, clearly marked line
    whose value is backticked, e.g. `HARD_BOUNDARIES ... `true``). `true` (default) = the hook
    enforces the hard wall; `false` = shields down, enforcement deferred to the CLAUDE.md policy
    (soft boundaries). Missing/unparseable => True (fail-closed to hard)."""
    for rel in (os.path.join("global", "CLAUDE.md"), "CLAUDE.md"):
        try:
            with open(os.path.join(project_dir, rel), encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        # 1) Authoritative CONFIG line only: the **bolded** token with a backticked value.
        #    Prose/warnings/comments that merely mention the token (even with a backticked
        #    `false`) are NOT bolded, so they can't flip the flag — closing the "stray earlier
        #    line disables the wall" hole. Value must be backticked on the same line.
        m = re.search(r"\*\*HARD_BOUNDARIES\*\*[^\n]*?`(true|false)`", text, re.I)
        if m:
            return m.group(1).lower() == "true"
        # 2) Fallback: no bolded config line found — take the LAST backticked value (the real
        #    config sits below any prose), still requiring the value be backticked.
        vals = re.findall(r"HARD_BOUNDARIES[^\n]*?`(true|false)`", text, re.I)
        if vals:
            return vals[-1].lower() == "true"
    return True


def load_production_paths(project_dir):
    """Registered production-tool roots (expanded, normalized) that are read-only in an engagement."""
    try:
        with open(os.path.join(project_dir, ".claude", "production_tools.json"), encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    paths = []
    for t in data.get("production_tools") or []:
        raw = t.get("path")
        if raw:
            paths.append(os.path.expanduser(raw).rstrip("/"))
    return [p for p in paths if p]


def _normalize_paths(command):
    """Expand ~ / $HOME so a prod path written with a shell shorthand is still detected.

    The registered prod paths are stored fully expanded, so a command that says
    `~/Workspace/.../tool.py` or `$HOME/...` would otherwise never substring-match. Normalizing
    the command to the same absolute form closes that bypass."""
    home = os.path.expanduser("~")
    c = command.replace("${HOME}", home).replace("$HOME", home)
    c = re.sub(r"(?<![\w/])~(?=/)", home, c)          # leading-~ path component
    return c


def _segments(command):
    """Split on shell separators so a write in one command isn't attributed to a read in another.
    The `(?<!>)` guard keeps the `>|` clobber-redirect operator intact instead of splitting it."""
    return re.split(r"&&|\|\||(?<!>)[;&|\n]", command)


def _copy_writes_prod(seg, p):
    """True if a cp/install/ln/rsync in this segment writes ONTO prod `p`.

    The approved sandbox-copy workflow (`cp -r <prod> <sandbox>`) has prod as the SOURCE only —
    that is allowed. Prod appearing as a destination (or any non-source position) is a write."""
    m = re.search(r"\b(?:cp|install|rsync|ln)\b(.*)$", seg)
    if not m or p not in m.group(1):
        return False
    args = [t for t in m.group(1).split() if not t.startswith("-")]
    # allow only when prod is exclusively the source (first path arg)
    if args and p in args[0] and not any(p in a for a in args[1:]):
        return False
    return True


def production_write_violation(command, prod_paths):
    """Return a production path the command tries to MUTATE IN PLACE, or None.

    Enforces Tier-0 read-only on registered production tools: blocks in-place edits, redirection
    into (incl. `>|`, `&>`, fd redirects), sed `w`, cp/install/ln/rsync ONTO the path, removal,
    permission changes, or a mutating git op targeting a production path — after ~/$HOME expansion.
    Reads and `cp <prod> <engagement-sandbox>` (the approved sandbox-copy workflow) are deliberately
    NOT blocked; only writes back onto production are.

    Residual limitation: each Bash call is evaluated in isolation, so a `cd <prod>` in a *separate*
    prior call followed by a bare-filename edit cannot be linked here. The sandbox-copy workflow
    (never operate in the prod dir) is the operating-policy backstop for that case."""
    norm = _normalize_paths(command)
    for p in prod_paths:
        if p not in norm:
            continue
        esc = re.escape(p)
        for seg in _segments(norm):
            if p not in seg:
                continue
            if re.search(r"sed\s+-[a-z]*i", seg):                       # in-place stream edit
                return p
            if re.search(r"\bsed\b", seg) and re.search(r"[wW]\s+['\"]?" + esc, seg):  # sed w file
                return p
            if re.search(r"\btruncate\b", seg):
                return p
            if re.search(r"\bdd\b[^\n]*\bof=", seg):
                return p
            if re.search(r"[&\d]*>{1,2}\|?\s*['\"]?" + esc, seg):       # redirect INTO (>, >>, >|, &>)
                return p
            if re.search(r"\btee\b[^|]*" + esc, seg):                   # tee INTO the path
                return p
            if re.search(r"\b(rm|rmdir|shred|unlink|chmod|chown|chgrp|mv)\b[^\n]*" + esc, seg):
                return p
            if re.search(r"git\b[^\n]*-C\s+['\"]?" + esc +
                         r"[^\n]*\b(commit|add|push|reset|checkout|rm|clean|merge|rebase)\b", seg):
                return p
            if _copy_writes_prod(seg, p):                              # cp/install/ln/rsync ONTO prod
                return p
    return None


def dest_allowed(dest, assets):
    if dest in LOCAL_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(dest)
        is_ip = True
    except ValueError:
        ip, is_ip = None, False
    if is_ip:
        if dest in (assets.get("ips") or []):
            return True
        if dest in (assets.get("hosts") or []):
            return True
        for cidr in (assets.get("cidrs") or []):
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    d = dest.lower()
    for h in (assets.get("hosts") or []):
        if d == h.lower():
            return True
    for w in (assets.get("wildcards") or []):
        w = w.lower()
        base = w[2:] if w.startswith("*.") else w
        # STRICT: `*.example.com` covers SUBDOMAINS, not the bare apex `example.com`.
        #
        # This used to read `if d == base or d.endswith("." + base)`, which quietly made every
        # wildcard cover its own apex. That was more permissive than three separate things that
        # all say otherwise:
        #
        #   * CLAUDE.md §1B — "A wildcard (*.example.com) -> SUBDOMAINS are in scope"
        #   * Hard rule #1  — "When in doubt, it is out of scope"
        #   * the scope files themselves — programs list bare hosts ALONGSIDE wildcards
        #     (Epic has 13 explicit hosts next to 30 wildcards). Two notations are used because
        #     they mean two different things; collapsing them discards the program's own wording.
        #
        # Measured 2026-07-28: 44 apexes across 5 engagements were reachable ONLY through this
        # behaviour. None had actually been contacted, so the exposure was prospective — but the
        # wall was authorising targets no program had listed.
        #
        # An apex IS in scope when the program lists it: it then appears in assets["hosts"] and is
        # matched by the exact-host loop above. This does not remove anything a program granted;
        # it stops inferring a grant that was never made.
        if d.endswith("." + base):
            return True
    return False


def main():
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        emit("deny", "Enforcement hook could not parse the tool payload. Blocked (fail-closed).")

    if payload.get("tool_name") != "Bash":
        emit("allow")

    command = (payload.get("tool_input") or {}).get("command", "")
    if not command.strip():
        emit("allow")

    # HARD FLOOR — applies in EVERY mode (even soft-boundary / autonomous), for every engagement,
    # and cannot be removed by editing any scope file. DoS, credential brute-forcing, and
    # destructive/system-altering actions never run. This is what keeps autonomous mode legitimate.
    for pat in HARDCODED_DENY:
        try:
            if re.search(pat, command, re.I):
                emit("deny", "Blocked by a HARD-CODED, always-on ban (DoS / credential brute-forcing "
                             "/ destructive). Never permitted in any mode or engagement.")
        except re.error:
            continue

    # Resolved from where the WORK is, not where the session started — see resolve_workspace_root().
    # Registering this hook globally is only safe because of that: without it, a session started
    # outside the workspace either denies everything (Phase-1 lockdown, including python3) or, if
    # never registered at all, denies nothing.
    project_dir, _root_how = resolve_workspace_root(payload)

    # ---- PROGRAM RATE CEILING ------------------------------------------------------------
    # Deliberately placed BEFORE the soft-boundary valve, alongside the hard floor.
    #
    # Lowering shields is the operator relaxing constraints WE chose. A program's rate limit is
    # not ours to relax — it is a term we agreed to when we accepted the engagement, and exceeding
    # it is abuse of a live production system regardless of what mode this workspace is in.
    #
    # Before this existed the ceiling lived only in scope_compiler._clamp_rates(), which rewrites
    # rate flags in the compiled TTP templates. Library commands were clamped; anything typed by
    # hand was not. Measured 2026-07-27 against a lock documenting 5 req/s: `-rl 50` allowed,
    # `-rl 99` allowed, denied only at 150 by the hard DoS floor — up to 20x the program's stated
    # limit. The protection covered the library, not the operator.
    _, _ceiling_profile = load_profile(project_dir)
    _ceiling = (_ceiling_profile or {}).get("rate_ceiling")
    _hit = rate_violation(command, _ceiling)
    if _hit:
        _bin, _flag, _val = _hit
        emit("deny", f"{_bin} '{_flag} {_val}' exceeds this engagement's rate ceiling of "
                     f"{_ceiling} req/s. The program's stated limit is a term of the engagement, "
                     f"not a workspace preference — it is enforced in every mode, including "
                     f"soft-boundary. Lower the rate to {_ceiling} or below.")

    # ---- EXECUTION LOCATION --------------------------------------------------------------
    # Also before the soft-boundary valve, for the same reason as the rate ceiling. "No tools
    # running on my home network" is the operator's standing instruction about their own
    # residential line — it is not one of the constraints shields-down exists to relax. The
    # deliberate way to say otherwise is settings.EXECUTE_MODE = "local", which is specific and
    # typed rather than a blanket switch.
    _is_remote = execution_is_remote(project_dir)
    _loc = location_violation(command, _is_remote, _ceiling_profile)
    if _loc:
        emit("deny", f"'{_loc}' is a network-facing tool and execution for this workspace resolves "
                     f"to REMOTE — so it must run ON the executor, not from this machine. Invoked "
                     f"through Bash it would run HERE, putting the traffic on the operator's home "
                     f"IP, which is the one thing the remote executor exists to prevent. Dispatch "
                     f"it instead: remote_exec.run_remote(cmd, engagement=..., pull=[...]). If this "
                     f"step genuinely has to run locally, that is a deliberate change to "
                     f"settings.EXECUTE_MODE, not something to work around here.")

    # Safety valve: if the operator has lowered shields in the config, defer to CLAUDE.md policy.
    if not read_hard_boundaries(project_dir):
        emit("allow", "Soft-boundary mode (HARD_BOUNDARIES=`false`): the hard wall is disabled; "
                      "enforcement is deferred to the CLAUDE.md operating policy. Set it back to "
                      "`true` to re-arm the hook.")

    # Tier-0 read-only guard: never let an engagement mutate a registered production tool in place.
    prod_hit = production_write_violation(command, load_production_paths(project_dir))
    if prod_hit:
        emit("deny", f"'{prod_hit}' is a registered PRODUCTION tool (read-only during engagements). "
                     "Do not alter it in place. Copy it into the engagement sandbox "
                     "(engagements/<name>/sandbox/) and patch the copy there instead.")

    active_name, profile = load_profile(project_dir)

    # ---- approval gate -------------------------------------------------------------------
    # `/generate-scope` writes `approved: false` and the skill documents the consequence:
    #
    #   "The hook refuses everything against an unapproved profile, so generating one changes
    #    nothing about what may run. That is why generation is safe for an agent to perform."
    #
    # That was false. The word "approved" appeared eleven times in this file — every one of them
    # a comment or a deny-string, never a lookup. Reproduced 2026-07-26 against a synthetic
    # profile with `approved: false`: `nuclei -u https://acme.example` was ALLOWED, while the
    # asset wall and deny-list both fired correctly on their controls. So an agent running
    # /generate-scope was arming the scope it had just written for itself, and the sentence that
    # made that safe to delegate was describing code that did not exist.
    #
    # Unapproved is treated as Phase-1 lockdown rather than a blanket refusal: local setup work
    # (reading scope files, listing directories) stays possible so an engagement can be prepared,
    # and only offensive tooling is withheld. The deny-list stays live while unapproved — it can
    # only ever subtract, so applying it early is free.
    # `is True`, not `bool(...)`. JSON `"approved": "false"` is a non-empty string and therefore
    # truthy — a hand-edited lock meant to be OFF would silently arm the wall, which is the same
    # hole this gate exists to close. Only a real JSON `true` counts; anything else, including a
    # missing key on a lock that predates this field, is unapproved.
    approved = profile.get("approved") is True if profile else False

    safe = set(DEFAULT_SAFE)
    denied, allowed, assets = [], None, {}
    if profile is not None:
        denied = profile.get("denied_patterns") or []
        assets = profile.get("assets") or {}
        safe |= set(profile.get("always_allowed_extra") or [])
        if profile.get("allowed_binaries") is not None:
            # An unapproved profile grants nothing. Leaving `allowed` as None puts the command
            # through the same Phase-1 lockdown path as "no engagement loaded", which already
            # exists and is already tested — rather than inventing a second refusal path that
            # could drift from it.
            allowed = set(profile.get("allowed_binaries") or []) if approved else None

    bins = candidate_binaries(command)
    if not bins:
        emit("deny", "Could not identify the command's binary. Blocked (fail-closed). "
                     "Simplify the command or re-scope via /generate-scope.")

    # 1) Deny-list always wins.
    for pat in denied:
        try:
            if re.search(pat, command):
                emit("deny", f"Command matches a denied pattern ('{pat}') in the engagement's "
                             "scope lock. Blocked.")
        except re.error:
            continue

    # 2) Binary allow-list.
    offensive_used = False
    for b in sorted(bins):
        if b in safe:
            continue
        offensive_used = True
        if allowed is None:
            # Two ways to land here, and the operator needs to know which — "no engagement" and
            # "engagement loaded but not approved" have completely different next steps.
            if profile is not None and not approved:
                emit("deny", f"Phase 1 lockdown: engagement '{active_name}' has a compiled scope "
                             f"but it is NOT APPROVED, so offensive tooling ('{b}') is blocked. "
                             f"Review the profile and approve it:\n"
                             f"  python3 global/scope/scope_compiler.py approve {active_name} "
                             f"--by <operator>\n"
                             f"Generating a scope does not arm it. That is the point.")
            emit("deny", "Phase 1 lockdown: no engagement is loaded with an approved scope, so "
                         f"offensive tooling ('{b}') is blocked. Run `/generate-scope "
                         "<engagement>` and approve it first.")
        if b not in allowed:
            emit("deny", f"'{b}' is NOT in the approved allow-list for engagement "
                         f"'{active_name}'. Phase 2 absolute boundary. If you need it, re-scope "
                         "via `/generate-scope` (or add it with the discovery loop) and "
                         "re-approve — do not work around this.")

    # 3) Asset/destination boundary (only when an offensive binary acts and assets are defined).
    if offensive_used and assets_nonempty(assets):
        for dest in sorted(extract_destinations(command)):
            if not dest_allowed(dest, assets):
                # A bare apex whose only coverage would be a wildcard is the single most likely
                # honest mistake here, so name it specifically rather than leaving the operator
                # to re-read the scope file wondering why an obviously-related host was refused.
                apex_hint = ""
                _bases = [(w[2:] if w.lower().startswith("*.") else w).lower()
                          for w in (assets.get("wildcards") or [])]
                if dest.lower() in _bases:
                    apex_hint = (f" NOTE: '*.{dest}' IS in scope, but a wildcard covers SUBDOMAINS "
                                 f"only — not the bare apex. Programs list an apex separately when "
                                 f"they mean to include it (see the explicit host list in this "
                                 f"engagement's scope). If the program does list '{dest}' itself, "
                                 f"add it to the scope file's hosts and re-run "
                                 f"`/generate-scope --update`; do not infer it from the wildcard.")
                emit("deny", f"Target '{dest}' is OUTSIDE the approved asset scope for engagement "
                             f"'{active_name}'. Phase 2 asset boundary. Only in-scope hosts/IP "
                             "ranges from the approved profile may be targeted. If '" + dest +
                             "' is legitimately in scope, update the scope file and re-run "
                             "`/generate-scope --update`." + apex_hint)
        # Targets fed from a file / stdin are invisible on the command line — read & verify them
        # so `nmap -iL out.txt` / `httpx < list` can't slip past the asset wall.
        file_dests, unresolved = file_fed_targets(command, project_dir)
        for dest in sorted(file_dests):
            if not dest_allowed(dest, assets):
                emit("deny", f"Target '{dest}' (from a target-list file) is OUTSIDE the approved "
                             f"asset scope for engagement '{active_name}'. Phase 2 asset boundary. "
                             "Remove out-of-scope hosts from the list or re-scope.")
        if unresolved:
            emit("deny", "This command sources targets from a file or stdin the enforcement hook "
                         "cannot read and verify against scope (missing/unreadable file, a "
                         "variable, a glob, or piped stdin). Inline the in-scope targets on the "
                         "command line, or point it at a readable in-scope target list. "
                         "Blocked (fail-closed).")

    emit("allow")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # absolute fail-closed backstop
        emit("deny", f"Enforcement hook error ({exc.__class__.__name__}). Blocked (fail-closed).")
