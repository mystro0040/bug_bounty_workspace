# execution/ — central run settings, global rate cap, optional remote execution

The one place to change **how and where tools run**. Operational config the operator
tunes; it is NOT a scope-lock and can never widen scope.

## Files
- **`settings.py`** — every global toggle in one obvious place: the global ISP rate
  cap, per-engagement cap, DNS defaults, `EXECUTE_MODE` (local/remote), the remote
  executor list, and the documented-absent local VPN. Run it to print the posture:
  `python3 settings.py`
- **`rate_budget.py`** — divides the global cap across everything running so their
  SUM stays under `GLOBAL_MAX_RPS`. `python3 rate_budget.py --for-new` → the `-rl`
  value to pass a tool you're about to start.
- **`vendors.py`** — provider profiles with AUP status. The framework runs on a vendor ONLY
  when its status is `allowed`. `python3 vendors.py --usable` shows cleared ones (currently: linode).
- **`remote_exec.py`** — SCAFFOLD (disabled). Dispatches a tool to a VPS after LOCAL
  scope validation, syncs results back. Off until a box is provisioned.

## The two things this protects against (both real residential-ISP trip-wires)
1. **Bulk DNS volume.** The global cap + `rate_budget` keep combined outbound DNS
   under an ISP-safe ceiling even with several engagements running. When that isn't
   enough, `EXECUTE_MODE="remote"` moves the DNS off your home IP entirely.
2. **Unattended runaway.** `UNATTENDED_TOOL_TIMEOUT` wraps long runs; the remote path
   applies it automatically.

## Using the global cap (local runs)
Before launching a network tool, ask what rate to give it:
```bash
RL=$(python3 <framework>/utilities/execution/rate_budget.py --for-new)
dnsx -l cand.txt -r ~/.config/offsec/resolvers.txt -rl "$RL" -t 25 -o out.txt
```
Two engagements now can't sum past the ceiling — the second tool automatically gets
a smaller share. That's the fix for "each capped at 10 but summed to 60".

## Default posture
`EXECUTE_MODE="auto"` runs tools REMOTE the moment a VPS is configured on a
CLEARED vendor, else local (so it is local today, remote automatically once the Linode is set up).
Claude always stays home. Tool-executor IPs may rotate freely; only the orchestrator IP must be
stable. An escape hatch (`RAW_LOCAL_ACK`, exact-string, typo-proof) can drop the ISP cap for
raw-local runs — it never touches scope, the hard floor, or the Anthropic-direct rule.

## The hard rule (never changes)
Whatever machine talks to Anthropic reaches it **directly, on a clean stable IP,
never through a VPN**. Anthropic path and scanning path stay on separate IPs. That's
why there is no local-tool VPN here — see `settings.py` §3 and `docs/REMOTE-EXECUTION.md`.
