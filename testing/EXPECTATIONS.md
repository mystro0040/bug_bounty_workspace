# Test expectations (auto-generated — do not edit by hand)

Regenerate with `workspace.py test --write-expectations`. This lists the suites whose tests live in THIS directory, what each covers, how to run it, and the expected result.

> **Directive:** Tests are a REGRESSION FLOOR, not a substitute for exercising the real tool. When you change or upgrade a tool you MUST do BOTH: (1) drive the actual application to confirm the change works, and (2) run AND update its suite here. Green tests on unchanged code prove nothing about code you just changed. Never skip the live app because tests pass; never skip updating tests because the app works.

## scope-wall  ·  safety  ·  CRITICAL

- **Run:** `python3 test_scope_wall.py` (from this directory)
- **Expected:** exit 0, all checks pass. PreToolUse scope hook: hard-floor denies (brute/DoS/anon/destructive/rate), out-of-scope denial, gentle in-scope allow, fail-closed. Synthetic scope-lock in a temp dir. ~32 checks.
- **Covers:** .claude/hooks/enforce_scope.py
- **Isolation:** isolated (temp dirs, no writes to tracked files).
