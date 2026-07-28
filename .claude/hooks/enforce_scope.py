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
}

INTRODUCERS = {"sudo", "env", "xargs", "nohup", "nice", "time", "watch", "command", "then",
               "do", "exec", "-exec", "-execdir", "-ok", "timeout", "stdbuf", "setsid"}

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
            "pem", "key", "crt", "sql", "db", "bin", "exe", "dll"}
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


def location_violation(command, is_remote):
    """Return the offending binary when a network tool would run HERE but should run on the executor.

    Returns None when: execution is local or unknown, the dispatcher is calling, the command is a
    transport invocation, or no network-facing binary is present.
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
                if not re.search(r"https?://(?!localhost|127\.|\[::1\])", seg):
                    continue
            return binary
    return None


def extract_subcommands(cmd):
    inner = re.findall(r"\$\(([^()]*)\)", cmd)
    inner += re.findall(r"`([^`]*)`", cmd)
    return inner


def candidate_binaries(cmd):
    bins = set()
    for sub in extract_subcommands(cmd):
        bins |= candidate_binaries(sub)
    # unwrap `bash -c "..."` / `sh -c '...'` / `eval "..."` so a binary hidden inside the
    # quoted payload is still checked, not just the wrapper.
    for m in list(SHELL_C_RE.finditer(cmd)) + list(EVAL_RE.finditer(cmd)):
        inner = m.group(1) or m.group(2) or m.group(3) or ""
        if inner and inner != cmd:
            bins |= candidate_binaries(inner)
    scrubbed = re.sub(r"\$\([^()]*\)", " ; ", cmd)
    scrubbed = re.sub(r"`[^`]*`", " ; ", scrubbed)
    try:
        tokens = shlex.split(scrubbed, comments=False, posix=True)
    except ValueError:
        tokens = re.split(r"\s+", scrubbed)
    expect = True
    for tok in tokens:
        if not tok:
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
        bins.add(os.path.basename(tok))
        expect = False
    return bins


def extract_destinations(cmd):
    """URL hosts + bare IPv4s + FQDN tokens (excluding filenames)."""
    dests = set()
    for host in URL_RE.findall(cmd):
        host = host.split("@")[-1]          # strip userinfo
        host = host.split(":")[0]           # strip port
        if host:
            dests.add(host.lower())
    for ip in IPV4_RE.findall(cmd):
        dests.add(ip)
    for tok in FQDN_RE.findall(cmd):
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
    # stdin redirect: `tool < file`
    files += re.findall(r"<\s*([^\s;&|<>]+)", command)
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
        if d == base or d.endswith("." + base):
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

    project_dir = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or os.getcwd()

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
    _loc = location_violation(command, _is_remote)
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
                emit("deny", f"Target '{dest}' is OUTSIDE the approved asset scope for engagement "
                             f"'{active_name}'. Phase 2 asset boundary. Only in-scope hosts/IP "
                             "ranges from the approved profile may be targeted. If '" + dest +
                             "' is legitimately in scope, update the scope file and re-run "
                             "`/generate-scope --update`.")
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
