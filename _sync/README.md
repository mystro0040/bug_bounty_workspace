# `_sync/` — bucket sync staging + the "get it ready for syncing" routine

> **Framework capability (built 2026-07-29).** The bucket syncs to S3 by **file COUNT, not size** — a
> single repo clone is ~70k files and makes a sync crawl. So heavy, re-derivable dirs are zipped into
> one **verified** archive before a push and unzipped after a pull.

## The routine — operator says **"get it ready for syncing"**
1. `python3 _sync/prep_for_sync.py --scan`   — list heavy dirs, change nothing.
2. `python3 _sync/prep_for_sync.py --zip`    — asks first, then per dir: zip → VERIFY → remove raw → manifest.
3. Push/sync as normal (fast — a few archives instead of tens of thousands of files).

On the **receiving** machine, after the PULL:
4. `python3 _sync/prep_for_sync.py --restore` — unzip every archive back into place.

## What it does (confirm-first, verify-before-delete)
- Finds heavy dirs (named `repos` / `node_modules` — re-derivable clones/deps).
- Zips each **AS-IS**, preserving any local test edits — that's *why we zip rather than
  exclude-and-re-clone*: re-cloning would discard local modifications.
- VERIFIES the zip (`testzip` + file count) and removes the raw dir **only after** it verifies.
- Records each archive in `SYNC-MANIFEST.md`: archive path, sha256, unzip-to location, install notes.

## Files
- `prep_for_sync.py` — the tool.
- `archives/` — the staged zips (these DO sync; they are the payload).
- `SYNC-MANIFEST.md` — what's zipped, where it restores, pinned versions (each engagement's
  `02_Reconnaissance/00-REPO-INVENTORY.md` has the repo tags).

## Rules (non-negotiable)
- **NEVER exclude or delete a `temp` dir.** The operator stores important things there (staging,
  safety copies). A sync tool's exclude list must never contain `temp`. See the memory
  `temp-dirs-are-important`.
- The vault-sync-manager excludes ONLY caches / bytecode / venvs / `node_modules` — nothing else.
- **Restore before** running anything that needs a raw checkout (e.g. a PoC that references a cloned
  repo).

## Status — framework upgrade, staged for propagation
`prep_for_sync.py` lives in this bucket now. It is logged in `_framework-propagation/CHANGELOG.md` as a
candidate to promote into the master framework (general_utils / the workspace template) so **every**
workspace/bucket gets the same routine — the home agent propagates it, same flow as the TTPs.
