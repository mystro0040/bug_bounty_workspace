# External skill packs — bug bounty (vetted, legal, permissively licensed)

This workspace already vendors one MIT skill pack (see `vendor/`). The repos below are
additional **vetted, permissively-licensed** sources you can pull on demand with
`./install-external-skills.sh`. Only pull markdown knowledge — review before importing
anything executable.

| Pack | Repo | License | What it adds |
|------|------|---------|--------------|
| Claude-BugHunter *(already vendored)* | `elementalsouls/Claude-BugHunter` | MIT | 70+ vuln-class SKILL.md knowledge bases from disclosed H1 reports |
| claude-bug-bounty | `shuvonsec/claude-bug-bounty` | MIT | Full recon→hunt→validate→report methodology + report templates (H1/Bugcrowd/Intigriti) |
| awesome-skills-security | `Eyadkelleh/awesome-skills-security` | MIT | Payload/pattern references (fuzzing, secret regexes) — supplement only |
| public-skills-builder | `shuvonsec/public-skills-builder` | MIT | *Generator* — distills fresh skills from current public writeups (needs API key) |

**Deliberately excluded (legal/licensing):**
- `H-mmer/pentest-agents` — **no LICENSE file → all rights reserved.** Not redistributable;
  do not vendor. (Safe to read upstream, not to copy.)

## Usage
```bash
cd global/skills
./install-external-skills.sh            # lists available packs
./install-external-skills.sh claude-bug-bounty   # clone one into vendor/, markdown only
```
Legality bar: only MIT/Apache/permissive, markdown-only, attribution + LICENSE preserved.
If a repo has no clear license, we don't vendor it.
