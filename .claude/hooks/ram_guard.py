#!/usr/bin/env python3
"""
ram_guard.py — refuse to run a command when the machine is about to run out of memory.

WHY THIS EXISTS
    §2F says "never max out RAM and freeze the system" and §2F-LOCAL says to cap commands with
    `ulimit -v`. Both are instructions to an agent that has to remember them. On 2026-07-26 the
    operator's machine locked up hard enough to need a restart, and the agent found out because
    the operator typed "ram at 71% - be carfull". That is a human being the monitor for a rule
    the machine could enforce itself.

    A ugrep over a recon directory once reached 3.96 GB in 58 seconds and left the box at 61 MB
    available with swap exhausted. Nothing stopped it. The rule existed the whole time.

    So: this runs before every Bash command, reads MemAvailable, and fails closed when the
    machine cannot afford the command. It is the mechanism behind the policy.

WHAT IT DOES NOT DO
    It cannot predict how much a command will use — only whether there is room to survive a
    spike. That is enough: the failure mode being prevented is a freeze, and a freeze needs
    headroom, not prophecy.

    It never blocks a command that is trying to FREE memory or diagnose the problem, because a
    guard that stops you fixing the thing it is complaining about is worse than no guard.

Thresholds are deliberately generous. A false refusal costs one retry; a frozen box costs every
running engagement.
"""
import json
import os
import re
import sys

CRITICAL_MB = 400        # below this: refuse anything that could allocate
WARN_MB = 900            # below this: allow, but say so loudly

# Commands that reduce memory pressure or diagnose it are never blocked — see module docstring.
_ALWAYS_ALLOW = re.compile(
    r"^\s*(free|ps|top|htop|pgrep|pkill|kill|killall|df|du|uptime|dmesg|swapoff|swapon|sync|"
    r"systemctl|journalctl|cat\s+/proc/meminfo|echo|true|:)\b|(^|\s)(--help|-h)(\s|$)")


def mem_available_mb():
    """MemAvailable is the kernel's own estimate of what can be allocated without swapping."""
    try:
        with open("/proc/meminfo", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        return None                      # unknown -> do not block; see main()
    return None


def emit(decision, reason=""):
    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                  "permissionDecision": decision}}
    if reason:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
    print(json.dumps(out))
    sys.exit(0)


def main():
    try:
        payload = json.load(sys.stdin)
    except (ValueError, OSError):
        emit("allow")                    # malformed payload is not this hook's problem

    command = (payload.get("tool_input") or {}).get("command") or ""
    avail = mem_available_mb()

    # An unreadable /proc/meminfo (non-Linux, container without procfs) must not wedge every
    # command. This guard protects against a freeze; it is not a security control, so unknown
    # fails OPEN rather than closed. The scope wall is the thing that fails closed.
    if avail is None:
        emit("allow")

    if _ALWAYS_ALLOW.search(command):
        emit("allow")

    if avail < CRITICAL_MB:
        emit("deny",
             f"MEMORY GUARD: only {avail} MB available (floor is {CRITICAL_MB} MB). Refusing to "
             f"start a command that could push the machine into swap and freeze it.\n"
             f"Free memory first — close a browser tab or an editor, check `free -m` and "
             f"`ps -eo pmem,rss,comm --sort=-rss | head`, or kill a background job you started. "
             f"Diagnostic and memory-freeing commands are never blocked by this guard.")

    if avail < WARN_MB:
        emit("allow",
             f"MEMORY WARNING: {avail} MB available. Cap anything that could fan out — "
             f"`( ulimit -v 1000000; <cmd> )` — and avoid running tools concurrently until this "
             f"recovers.")

    emit("allow")


if __name__ == "__main__":
    main()
