# Bug Bounty Workspace

> **PUBLIC-SAFE DISTRIBUTABLE VERSION.** This is the shareable release of the workspace. It
> ships the **methodology skills, the agent configuration, and the scope-enforcement hook** — the
> reusable framework only. It contains **NO engagement data, no findings, no scope locks, no
> secrets, and no operator-specific identifiers**: `engagements/` holds only the empty
> `_TEMPLATE/` phase structure, `.claude/production_tools.json` is an example placeholder registry,
> and the active-engagement pointer is empty. Third-party **vendor** skill packs are **not
> included** — install them separately via `global/skills/install-external-skills.sh` /
> `EXTERNAL-SKILLS.md`. Add your own engagements, tools, and platform handle before use.

A production-ready, Claude-driven **bug bounty** workspace. It configures the agent as a
senior bug bounty hunter, loads a curated skill library, and enforces per-program scope
discipline before any testing begins.

## Layout
```
bug_bounty_workspace/
├── CLAUDE.md                  # Root loader — imports global/CLAUDE.md (@import)
├── .claude/
│   ├── settings.json          # Registers the PreToolUse enforcement hook
│   ├── hooks/enforce_scope.py # HARD guardrail: blocks any tool not in the approved scope
│   ├── skills/generate-scope/ # /generate-scope custom command (cached, hard-stops for approval)
│   └── state/                 # Runtime: active_engagement pointer (git-ignored)
├── global/
│   ├── CLAUDE.md              # Authoritative agent config: role, CONFIG block, Phase 1/2 guardrails
│   └── skills/
│       ├── methodology/       # Core hunting skills authored for this workspace (6)
│       ├── ttp-derived/       # Bug-bounty-SAFE subset of the framework TTPs (readable know-how)
│       ├── vendor/            # Vetted MIT skill packs (markdown only, no payloads) + attribution
│       ├── EXTERNAL-SKILLS.md # Catalog of additional vetted packs
│       └── install-external-skills.sh
└── engagements/
    └── _TEMPLATE/             # Empty phase-folder structure to copy per engagement
        └── (after scoping) approved_TTPs.yaml + .scope_lock/   # git-ignored
```
The technique **catalog** lives outside this repo in the read-only **Bug Bounty Execution
Framework** (`FRAMEWORK_SOURCE`, see `global/CLAUDE.md` §0). This workspace *consumes* it.

## Workflow — how to use

> Launch Claude Code **from this workspace root** (so the root `CLAUDE.md` and `.claude/` load).

**1. Add / pick an engagement.** Copy `engagements/_TEMPLATE/` to a new folder (e.g.
`engagements/acme_vdp/`) and fill in its `scope.md` with the program's in-scope, out-of-scope,
and rules. On start, the agent **halts and asks which engagement to load** (Initialization
protocol).

**2. Generate the scope lock — `/generate-scope <engagement>`.** This operator-only command:
- reads the engagement's scope file and cross-references it against the read-only framework,
- **filters out** anything non-compliant or aggressive (only bounty-safe, in-scope techniques
  survive),
- parses the scope's **asset boundaries** (in-scope subdomains, IP ranges, endpoints),
- compiles the concrete tools + assets into `approved_TTPs.yaml` (rich TTP objects: intent +
  command strings + binaries) and a machine-readable `.scope_lock/enforcement.json`.
- It is **smart-cached**: if the scope file hasn't changed since last time, it tells you the
  profile is already cached instead of regenerating (pass `--update` to force).
- It then **hard-stops and asks you to review & approve** — nothing is live until you say so.

**3. Approve.** Review the summary (in/out-of-scope, approved techniques, allowed tools). On
your approval the agent marks the scope APPROVED and sets it as the active engagement.

**4. Operate — inside the wall.** From here, the **PreToolUse hook enforces** every command on
two axes: the **binary** must be in `allowed_binaries`, **and** the **target destination**
(URL host / IP) must fall inside the approved **asset boundaries** — anything off-tool *or*
off-target is **blocked**, as is anything matching `denied_patterns`. If no engagement is approved
yet, the workspace is **locked down** (offensive tooling blocked; basic file inspection works).

**Mid-engagement gap? The dynamic discovery loop.** If you hit a finding that needs a technique
or tool not in the whitelist, the agent **halts**, shows you the gap, and — with your approval —
pulls the methodology from the framework, adapts it to scope, and runs **`/add-ttp`** to append
it live (recompiling `enforcement.json`); the new boundary is active immediately, no reboot.

**Changing scope later:** edit `scope.md`, re-run `/generate-scope <engagement> --update`,
re-approve. Editing the framework itself is a separate, deliberate **maintenance mode** you must
explicitly ask for — and it never widens an existing engagement until you re-scope.

## Rules (hardcoded in `global/CLAUDE.md`)
- **Phase 1 (init check):** load `approved_TTPs.yaml` as active boundaries, or **lock down** and
  tell the operator to run `/generate-scope`.
- **Phase 2 (absolute boundary):** never run/recommend anything outside the approved whitelist —
  enforced in software by the hook.
- Authorized, in-scope targets only. No destructive commands, no DoS, no unauthorized remote
  exploitation. Prove impact with the **minimum viable, non-destructive PoC**.
- Focus on **high-impact, payable** vulns; ignore low-impact/informational noise.

## Scope-gating architecture (soft vs. hard)
| Layer | Role | Strength |
|-------|------|----------|
| `global/skills/`, `.claude/skills/` | Playbooks / know-how | Soft (advisory) |
| `global/CLAUDE.md` rules & phases | Policy | Soft but top-priority |
| `.claude/hooks/enforce_scope.py` + `approved_TTPs.yaml` | Command block | **HARD (real wall)** |

Skills carry *know-how*; the framework YAML carries the *technique catalog*; `approved_TTPs.yaml`
+ the hook carry the *enforced boundary*.

## Beyond scope — production tools, the ledger & the safety valve

- **HARD_BOUNDARIES safety valve** — `global/CLAUDE.md` §0 CONFIG has a backticked
  `HARD_BOUNDARIES` flag (default `` `true` ``). `true` = the hook enforces the hard wall.
  Flip it to `` `false` `` to **lower shields** for a deliberate, high-trust session — the hook
  stops blocking and enforcement falls back to the CLAUDE.md policy. Set it back to `` `true` ``
  to re-arm. (The hook reads only the backticked value, so prose can't flip it by accident.)
- **Production tools are read-only** — your proprietary utilities (HTTP tester, web app scanners,
  autoweb) are catalogued in `.claude/production_tools.json`. During an engagement the hook
  **blocks any in-place edit** of them. To use one: `cp -r <tool> engagements/<name>/sandbox/` and
  patch the **sandbox copy** — never the original. (Reads and the copy-out stay allowed.)
- **Live patching → UPGRADE_LOG** — patch a sandboxed tool if it fails against the target, and
  log the error context + change to `engagements/<name>/sandbox/UPGRADE_LOG.md`.
- **BREAKTHROUGH_LEDGER** — every code fix / bypass / new-technique discovery is appended to
  `engagements/<name>/BREAKTHROUGH_LEDGER.md` (permanent, so nothing is lost over long sessions).
  Copy the starters from `templates/`. In **Tier 1 maintenance mode** (a separate, deliberate,
  operator-approved session) ledger entries can be promoted back into the master framework.
- **Four permanent bounty constraints** are hardcoded into `/generate-scope`: no social-eng
  except between **your own test accounts**, **DoS/DDoS banned**, **auto rate-limiting** on all
  scanners, and your **hacker handle injected into an ID header** (`X-Bug-Bounty-Handle`) on every
  request. These land in `operational_constraints:` and in the compiled commands/deny-list.

## Safety & legality
Real engagement data is git-ignored (this public release ships none — only the empty
`_TEMPLATE/`). Vendored skills are MIT-licensed, markdown-only knowledge packs; they are **not
bundled** in this public version — install them yourself via
`global/skills/install-external-skills.sh` and keep each pack's `LICENSE` + attribution. Unlicensed
repos are intentionally excluded.
