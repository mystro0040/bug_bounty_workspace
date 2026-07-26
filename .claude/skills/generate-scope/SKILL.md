---
name: generate-scope
description: Compile an engagement's approved_TTPs.yaml + .scope_lock/enforcement.json from its scope file, filtered against the read-only execution framework. Produces a PENDING profile that enforces nothing until approved. Same code path whoever runs it — operator, agent, or orchestrator.
user-invocable: true
argument-hint: [engagement_name] [--update]
arguments: [engagement, flag]
---

# /generate-scope — compile the per-engagement scope lock

## This is a thin wrapper. The implementation is code.

The procedure lives in **`global/scope/scope_compiler.py`**, not in this file. Follow the steps
below by *running that program* — do not reimplement them.

**Why this matters, and it is not a style preference.** This skill used to describe the procedure
in prose. On 2026-07-25 an agent followed the prose faithfully and produced artifacts that were
missing the per-TTP `commands:` block — the only thing carrying two of the four permanent
constraints. The profiles looked complete, the wall worked, and the rate limit and identification
header were enforced by nothing. Prose is not an implementation: two readers produce two different
results and neither knows.

So: **"generate the scope" means running `scope_compiler.py`.** Whether the operator types the
slash command, an agent does it, or the orchestrator dispatches it remotely — identical code,
identical output, no surprises. If you find yourself writing your own version, stop; that is the
bug this file exists to prevent.

## Generation is not the gate — approval is

`compile` writes `approval.status: PENDING_OPERATOR_REVIEW` and `enforcement.approved: false`.
The hook refuses **everything** against an unapproved profile, so generating one changes nothing
about what may run. That is why generation is safe for an agent to perform on request.

`approve` is the checkpoint, and it is never self-granted.

## Steps

**1. Compile.**

```bash
python3 global/scope/scope_compiler.py compile <engagement> --config <facts.json> [--update]
```

`facts.json` carries the per-program facts read out of the engagement's `scope.md`: `hosts`,
`wildcards`, `capabilities`, `manual_only`, `rate_limit` + `rate_value`, `header` (name/value),
`program_rules`, `out_of_scope`, and any `extra_denied` regexes for path or subdomain exclusions.
Extracting those facts from the scope file is the judgement part and is yours; compiling them into
an enforced profile is the mechanical part and is the program's.

The compiler applies, without being asked: the four permanent constraints, exclusion of locked /
destructive / not-bounty-safe / `program_approval` techniques, capability curation, scanner
exclusion on manual-only programs, and the DoS ban mirrored into `denied_patterns`.

**2. Verify.**

```bash
python3 global/scope/scope_compiler.py verify <engagement>
```

Exit non-zero means the artifacts are inconsistent — do not present them. The check confirms the
two files agree on the scope hash, that every invoked binary is allow-listed, that a manual-only
program allows no scanners, and that the rate flag and identification header are **attached to the
right sub-command** — not merely present somewhere in the string, which is a thing that passed once
and shouldn't again.

**3. Present, then STOP.** Show the operator: asset boundaries in and out, operational constraints,
what was excluded and why, TTP count, allow-listed binaries, deny-list size, and any remaining
`ASK_OPERATOR` placeholder. Ask for explicit approval. Do not proceed.

**4. Approve — only on the operator's word.**

```bash
python3 global/scope/scope_compiler.py approve <engagement> --by <operator>
```

Refuses on a failing self-check. Approving does **not** set the engagement active; that is a
separate deliberate step, so approving several profiles cannot silently arm one.

**5. Set active only when the operator says to start.**

```bash
echo "<engagement>" > .claude/state/active_engagement
```

## Reading the scope file

Extract and normalise: `hosts`, `wildcards`, `cidrs`, `ips`, `endpoints`, `out_of_scope`, and the
program's own rules — rate ceilings, required identification header, test-account requirements,
manual-only restrictions, path exclusions.

Two traps worth naming:

- **Path-granular assets.** The hook is host-granular. If a program scopes `https://host/path`
  only, the host goes in `assets.hosts` so requests are permitted, and the path restriction goes in
  `program_rules` — and, where it matters, as an `extra_denied` regex. Record honestly that the
  wall permits the host and the operator observes the path.
- **Exclusions inside a wildcard.** `*.example.com` minus `excluded.example.com` needs an explicit
  `extra_denied` entry; a wildcard alone will happily match the excluded host.
