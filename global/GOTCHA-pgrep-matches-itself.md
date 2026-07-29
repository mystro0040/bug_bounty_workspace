# `pgrep -f <pattern>` matches its own command line. Five times in one night.

Not a subtle bug. A cheap one, repeated, because the output always looks plausible.

## What happens

`pgrep -f` matches against the FULL COMMAND LINE of every process — including the shell that is
running the `pgrep`, whose command line contains the pattern you just typed. So the check finds
itself and reports a process that is not there.

It never errors. It returns a PID. The output is the right shape and the wrong answer.

## Every occurrence on 2026-07-27/28

| # | What was run | What it reported | What was true |
|---|---|---|---|
| 1 | `pgrep -f katana` over SSH | a katana PID, then a DIFFERENT one on the retry | katana was already dead; each probe matched its own shell |
| 2 | `pgrep -f crawl_200_hosts \| kill` | — | **killed the shell running the command** (exit 144) |
| 3 | `pgrep -cf 'probe_live\|rerun\|crawl_'` | "3 jobs running" | one job was running |
| 4 | `pgrep -af 'httpx\|dnsx\|nuclei\|...'` | nothing — silently | pattern exceeded 15 chars; warned, matched nothing, read as "all clear" |
| 5 | `while pgrep -f dns_bruteforce.py; do sleep; done` | never exited | **the waiter waited for itself, forever.** A queued recovery job never started |

Number 5 is the expensive one: a recovery run sat unstarted while everything looked fine.

## What to use instead

**Match the executable name, which cannot contain your pattern:**

    pgrep -x katana                    # exact process NAME. Self-match is impossible.
    pgrep -x httpx

**Or bracket the first character, so the pattern text does not match itself:**

    ps -eo pid,args --no-headers | grep '[k]atana'

**Or match on something structural rather than the tool's name:**

    ps -eo pid,args --no-headers | grep 'python3 engagements/'

**For a wait loop, wait on the PID you started — never on a pattern:**

    python3 job.py & JOB=$!
    while kill -0 "$JOB" 2>/dev/null; do sleep 20; done

## The general shape, which is the point

This belongs with the other checks that lied on the same night: a `grep` filter that hid the box's
tool list, a status-code regex that counted content-lengths as HTTP codes, and an IP cross-check
that compared against a set of one entry and printed a confident tick.

**All four returned a plausible-looking answer from broken input.** None of them errored. The
common failure is not "the check failed" — it is "the check succeeded at measuring the wrong
thing," and the output gives no hint of it.

So: when a check underpins a decision, ask what it would print if the thing being checked were
absent, broken, or self-referential. If the answer is "the same as now," it is not a check.
