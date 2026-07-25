"""
rate_budget — divide the global outbound cap across everything running right now.
================================================================================

The problem this solves (we watched it happen): two engagements, each correctly
capped at its own limit, still SUMMED to ~60 req/s because nothing coordinated
them. This computes the rate each concurrent tool should use so the SUM stays
under the global ceiling in settings.GLOBAL_MAX_RPS.

Our tools are external binaries (dnsx, httpx, ffuf) that take a `-rl`/`-rate`
flag, so the practical "global limiter" is BUDGET DIVISION at launch, not a
mid-run token bucket: ask this what rate to pass, then pass it.

    python3 rate_budget.py                 # show current budget + active count
    python3 rate_budget.py --for-new       # rate to give ONE tool you are about to start
    python3 rate_budget.py --tools 3       # rate if 3 network tools will run together

As a library:
    from execution.rate_budget import rate_for
    rl = rate_for(concurrent_tools=2)      # -> int req/s to pass to each tool
"""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from execution import settings as S  # noqa: E402


def _running_network_tools():
    """Best-effort count of network tools currently running (for auto-division).
    Counts live scanner/enumerator processes via /proc — no external deps."""
    names = ("dnsx", "httpx", "subfinder", "nuclei", "ffuf", "katana",
             "feroxbuster", "gobuster", "wpscan", "amass", "naabu")
    n = 0
    for pid in glob.glob("/proc/[0-9]*"):
        try:
            with open(os.path.join(pid, "comm"), encoding="utf-8") as fh:
                if fh.read().strip() in names:
                    n += 1
        except OSError:
            continue
    return n


def rate_for(concurrent_tools=None):
    """Return the req/s an individual tool should use so the SUM of all concurrent
    tools stays under GLOBAL_MAX_RPS, and no single tool exceeds PER_ENGAGEMENT_MAX_RPS.

    concurrent_tools: how many network tools will run at once INCLUDING this one.
                      If None, auto-detects currently-running tools and adds 1."""
    # Raw-local override (deliberately set) or global cap turned off -> no global division;
    # each tool just uses the per-engagement default, like before today.
    if S.raw_local_active() or not S.GLOBAL_RATE_LIMIT_ENABLED:
        return S.PER_ENGAGEMENT_MAX_RPS

    if concurrent_tools is None:
        concurrent_tools = _running_network_tools() + 1
    concurrent_tools = max(1, int(concurrent_tools))

    share = S.GLOBAL_MAX_RPS // concurrent_tools
    share = max(1, share)                                  # never below 1/s
    return min(share, S.PER_ENGAGEMENT_MAX_RPS)            # per-engagement cap still wins


def max_concurrent_tools():
    """How many tools the global cap can actually cover.

    Division bottoms out at 1 req/s — a tool rated below 1/s would stall — so beyond
    GLOBAL_MAX_RPS concurrent tools the ceiling can no longer be met by dividing. Past that
    point the real aggregate is (number of tools) x 1 req/s, which EXCEEDS the cap."""
    return max(1, int(S.GLOBAL_MAX_RPS))


def check_budget(concurrent_tools=None):
    """(within_cap, projected_total_rps, message) — makes the breakdown above visible instead
    of silent. Callers launching a fan-out should check this before starting the Nth tool."""
    if S.raw_local_active() or not S.GLOBAL_RATE_LIMIT_ENABLED:
        return True, None, "global rate limiting is OFF (raw-local ack or limiter disabled)"
    if concurrent_tools is None:
        concurrent_tools = _running_network_tools() + 1
    n = max(1, int(concurrent_tools))
    total = rate_for(n) * n
    if n > max_concurrent_tools():
        return (False, total,
                f"OVER GLOBAL CAP: {n} concurrent tools x 1 req/s (the floor) = ~{total} req/s, "
                f"above GLOBAL_MAX_RPS={S.GLOBAL_MAX_RPS}. Dividing further would stall tools. "
                f"Run at most {max_concurrent_tools()} network tools at once, or raise "
                f"GLOBAL_MAX_RPS in settings.py only if your ISP headroom genuinely allows it.")
    return True, total, f"{n} tool(s) x {rate_for(n)} req/s = ~{total} req/s (cap {S.GLOBAL_MAX_RPS})"


def _cli(argv):
    args = argv[1:]
    if "--for-new" in args:
        print(rate_for())
        return 0
    if "--tools" in args:
        try:
            n = int(args[args.index("--tools") + 1])
        except (ValueError, IndexError):
            print("usage: rate_budget.py --tools <N>")
            return 2
        print(rate_for(n))
        return 0
    running = _running_network_tools()
    print(S.summary())
    print(f"network tools running now : {running}")
    print(f"rate for one MORE tool    : {rate_for()} req/s "
          f"(so {running + 1} tools stay under {S.GLOBAL_MAX_RPS}/s combined)")
    print(f"max tools the cap covers  : {max_concurrent_tools()}")
    ok, total, msg = check_budget()
    print(f"budget check              : {msg}")
    if not ok:
        print("  [!] STOP STARTING TOOLS — the global cap can no longer be honoured.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv))
