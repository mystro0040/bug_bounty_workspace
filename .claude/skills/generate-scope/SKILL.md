---
name: generate-scope
description: Manually generate or refresh an engagement's approved_TTPs.yaml scope lock by filtering the read-only Bug Bounty Execution Framework against that engagement's scope file. Parses in-scope assets (subdomains, IP ranges, endpoints) into strict boundaries and compiles a machine-enforceable profile. Operator-triggered only; never runs autonomously. Smart-cached and always hard-stops for operator review before the scope is live.
disable-model-invocation: true
user-invocable: true
argument-hint: [engagement_name] [--update]
arguments: [engagement, flag]
---

# /generate-scope — build the per-engagement scope lock (cached, human-in-the-loop)

Invoked explicitly as `/generate-scope <engagement> [--update]`. `$engagement` = target folder
under `engagements/`. `$flag` may be `--update` (force regeneration even if cached).

This command reads the engagement's scope, cross-references it against the **read-only**
`FRAMEWORK_SOURCE` (see the CONFIG block in the global CLAUDE.md), filters out non-compliant
techniques, parses the scope's **asset boundaries**, and writes TWO artifacts:
1. `engagements/<name>/approved_TTPs.yaml` — the rich, human-readable review surface.
2. `engagements/<name>/.scope_lock/enforcement.json` — the compiled machine profile the
   PreToolUse hook reads to gate every command (binaries **and** target destinations).
Then it STOPS and waits for your approval.

Follow these steps exactly.

## Step 0 — Resolve paths
- `ENG_DIR = engagements/$engagement`. If missing, STOP and list available engagement folders.
- Auto-detect the scope file in `ENG_DIR`: try `scope.md`, `scope.txt`, `SCOPE*`, then any
  single `*scope*`. If none / empty / placeholder, STOP and ask the operator to fill it in.
- `APPROVED = ENG_DIR/approved_TTPs.yaml`; `LOCKDIR = ENG_DIR/.scope_lock/`;
  `ENFORCE = LOCKDIR/enforcement.json`.
- Read `FRAMEWORK_SOURCE` (the master bounty framework TTP dir) from the global CLAUDE.md CONFIG
  block. READ-ONLY — never write to it here.

## Step 1 — Smart caching check
- `sha256sum <scopefile>` → hash.
- If `APPROVED` exists AND non-empty AND `$flag` != `--update`:
  - Compare against the `source_scope_sha256:` stored in `APPROVED`.
  - **Match:** cached profile still valid — do NOT regenerate. Tell the operator "A valid target
    profile is already cached and loaded for `$engagement` (scope unchanged)." Ensure
    `.claude/state/active_engagement` names `$engagement`, and STOP.
  - **Mismatch:** scope changed — proceed to Step 2.
- If `APPROVED` missing/empty or `$flag` == `--update`: proceed to Step 2.

## Step 2 — Parse scope (assets + rules) and cross-reference the framework
**2a. Asset boundaries.** From the scope file, extract and normalize:
- `hosts` — explicit in-scope domains/subdomains (e.g. `app.example.com`).
- `wildcards` — wildcard scopes (e.g. `*.example.com`).
- `cidrs` — in-scope IP ranges in CIDR (e.g. `192.0.2.0/24`).
- `ips` — explicit in-scope IPs.
- `endpoints` — specific API endpoints/paths, if the program lists them.
- Also capture `out_of_scope` and `program_rules` (rate limits, allowed test accounts, forbidden
  actions, PII handling). If the program is wildcard-only with no concrete host, record the
  wildcard; if truly no assets are given, note it (the hook then enforces tools-only).

**2b. Technique selection.** Walk the `FRAMEWORK_SOURCE` YAML TTPs. Include/exclude each:
- **Exclude** any task with `policy.bounty_safe: false` or `policy.locked: true`, and anything
  out of bounty scope (DoS, destructive, internal/AD/lateral/persistence/evasion). When in
  doubt, EXCLUDE. Locked TTPs are NEVER auto-included (Tier 2).
- **Include** only techniques appropriate to the in-scope assets and permitted by program rules;
  honor `policy.poc_only` (minimal, non-destructive).

## Step 2c — Hardcoded bounty operational constraints (PERMANENT — always applied)

These **four constraints are non-negotiable** and are baked into every generated profile
regardless of the scope file. Encode them into `operational_constraints:` in `approved_TTPs.yaml`,
reflect them in the compiled `commands:`, and mirror the DoS ban into `denied_patterns`:

1. **No user-facing attacks / social engineering** — never target real users. Any technique that
   interacts with another account (IDOR/BOLA/auth-bypass proof, cross-account access) is permitted
   **only between distinct test accounts the operator personally created** on the platform. If the
   scope file doesn't name the operator's test accounts, record `test_accounts: [ASK_OPERATOR]`
   and require them before any cross-account technique is approved. Phishing / social engineering
   of real people is always excluded.
2. **No DoS / DDoS — banned entirely.** Never include volumetric, stress, resource-exhaustion, or
   flood techniques. Add stress/flood tooling and flood flags to `denied_patterns` (e.g.
   `hping3`, `slowloris`, `t50`, `\bab\b.*-n\s*[0-9]{5,}`, `--flood`, `siege`).
3. **Strict rate limiting on all automated scanning/enumeration.** Every automated web scan/enum
   command MUST carry a conservative rate-limit flag so the target stays stable — e.g.
   `ffuf -rate 20 -t 10`, `nuclei -rl 20 -c 10`, `feroxbuster --rate-limit 20`,
   `gobuster ... --delay 50ms`. Honor a stricter program-stated limit if the scope gives one.
4. **Identification header on all outgoing HTTP requests.** Inject the operator's platform hacker
   handle into a custom request header on every web request, for clear attribution. Default header
   `X-Bug-Bounty-Handle: <handle>` (use a program-mandated header/value if the scope specifies
   one). Read the handle from the scope's `program_rules`; if absent record
   `hacker_handle: ASK_OPERATOR` and require it before approval. Apply as `-H`/`--header` on
   `curl`, `ffuf`, `nuclei -H`, `httpx -H`, etc.

> **How each constraint is enforced (know the difference).** Constraints 1 and 2 are enforced by
> the **hook**: cross-account/social-eng exclusions drop the techniques, and the DoS ban is
> mirrored into `denied_patterns` so the hook actively blocks flood tooling. Constraints 3
> (rate-limit) and 4 (ID header) are enforced by the **approved-command allowlist convention** —
> they are baked into every emitted command string and the Step 3c self-check confirms every
> approved web command carries them — but the hook gates on *binary + asset + deny-list*, not
> command *shape*. They therefore hold as long as commands come from this approved set; an ad-hoc
> `curl`/`ffuf`/`nuclei` invocation the operator types by hand would NOT be forced to include the
> rate limit or the header. Keep to the approved commands, and treat 3 & 4 as convention-enforced.

## Step 3 — Write the artifacts

**3a. `approved_TTPs.yaml` (rich review surface).** TTPs are **complex objects**, not a raw tool
list — each records the technique intent plus the exact authorized command strings and binaries:
```yaml
engagement: <name>
generated_by: /generate-scope
source_scope_file: <relative path>
source_scope_sha256: <hash>
assets:
  hosts: [ app.example.com, ... ]
  wildcards: [ "*.example.com" ]
  cidrs: [ 192.0.2.0/24 ]
  ips: [ 203.0.113.10 ]
  endpoints: [ https://api.example.com/v1/ ]
  out_of_scope: [ ... ]
program_rules: [ "≤ 5 req/s", "use test accounts only", ... ]
operational_constraints:                        # §Step 2c — always present, non-negotiable
  social_engineering: forbidden                 # real users off-limits
  cross_account_testing: test_accounts_only
  test_accounts: [ ASK_OPERATOR ]               # operator-created platform test accounts
  dos: banned
  rate_limit: "≤ 20 req/s (or stricter program limit)"
  identification_header: { name: X-Bug-Bounty-Handle, value: ASK_OPERATOR }
approved_ttps:
  - id: <framework task id>
    technique: <name>
    phase: <phase>
    intent: <what this TTP is for and why it's in scope/compliant>
    poc_only: true
    binaries: [ ffuf, curl ]                    # every binary the commands invoke
    commands:                                   # exact, authorized command strings —
                                                # rate-limited + carrying the ID header
      - 'ffuf -u https://app.example.com/FUZZ -w words.txt -rate 20 -t 10 -H "X-Bug-Bounty-Handle: <handle>"'
      - 'curl -s https://app.example.com/ -H "X-Bug-Bounty-Handle: <handle>"'
    source: framework                           # framework | discovery-loop
approval:
  status: PENDING_OPERATOR_REVIEW
  approved_by: null
  approved_at: null
```

**3b. `.scope_lock/enforcement.json` (compiled machine wall).** Derive it from 3a — the union of
all `binaries` across approved TTPs, the asset boundaries, and the deny-list:
```json
{
  "engagement": "<name>",
  "approved": false,
  "source_scope_sha256": "<hash>",
  "allowed_binaries": ["curl", "ffuf", "nuclei", "httpx"],
  "denied_patterns": ["--os-shell", "rm\\s+-rf\\s+/", "hping3", "slowloris", "t50",
                       "--flood", "\\bsiege\\b", "\\bab\\b.*-n\\s*[0-9]{5,}"],
  "always_allowed_extra": [],
  "assets": { "hosts": [...], "wildcards": [...], "cidrs": [...], "ips": [...] }
}
```
Write both with the Write tool (file writes are not gated by the hook). Keep them in lockstep —
`enforcement.json` must always reflect exactly what's in `approved_TTPs.yaml`.

## Step 3c — Self-verify the artifacts before presenting (machine check, NOT approval)
Before Step 4, confirm the two files are internally consistent. Do NOT present until **all** pass;
if any fails, fix the artifacts and re-run this step:
- `enforcement.json` parses as valid JSON.
- `allowed_binaries` is exactly the deduped **union** of every approved TTP's `binaries` — no
  extras (nothing allowed that no approved command uses), none missing (every invoked binary is
  listed).
- every approved command's target host/IP resolves **inside** `assets` (or is localhost) — no
  approved command targets an out-of-scope host.
- no approved command string matches any `denied_patterns` entry (your own commands don't trip the
  deny-list).
- `source_scope_sha256` is identical in `approved_TTPs.yaml` and `enforcement.json`.
- every web command carries **both** its rate-limit flag and the `X-Bug-Bounty-Handle` header
  (constraints 3 & 4), and no `ASK_OPERATOR` placeholder (handle / test accounts) remains.

This self-check catches silent drift between the two artifacts; it is NOT operator approval — that
is Step 4.

## Step 4 — HARD STOP for operator review (mandatory)
Do NOT set the engagement active yet. Present a concise summary: the parsed **asset boundaries**
(in/out of scope), the **operational constraints** (social-eng forbidden / test-accounts-only,
DoS banned, rate limit, ID header + whether the handle & test accounts are still `ASK_OPERATOR`),
the count + list of approved TTPs (technique + intent + binaries), the compiled `allowed_binaries`,
and the deny-list. Then STOP and ask the operator to review and explicitly approve. If the handle
or test accounts are still `ASK_OPERATOR`, collect them before approval.

Only AFTER approval: set `approval.status: APPROVED` (+ who/when) in `approved_TTPs.yaml`, set
`"approved": true` in `enforcement.json`, and write `$engagement` into
`.claude/state/active_engagement` so the hook begins gating against this profile (binaries **and**
target assets). If the operator requests changes, adjust and repeat Step 4. Never self-approve.
