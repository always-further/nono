---
slug: 260507-tui-shell-fix
date: 2026-05-07
status: complete
commit: 0c69bd4b
type: docs
---

# Fix Windows POC cookbook: `nono shell` for TUI agents

## What changed

Single-file commit `0c69bd4b` rewrites the Windows POC cookbook (`docs/cli/development/windows-poc-handoff.mdx`) to recommend `nono shell --profile claude-code` as the happy path for any interactive Claude session. `nono run -- claude` is documented as an *anti-pattern* on Windows because the supervised path opens anonymous pipes rather than a ConPTY — TUIs cannot render and appear to hang.

| Section | Before | After |
|---|---|---|
| Top-of-doc Note | "Trust the binary; legacy docs are stale" — overconfident | Two-fact framing: profile-backed runs work AND `nono run -- <TUI>` cannot host a TUI on Windows |
| Step 4 live command | `nono run --profile claude-code -- claude` | `nono shell --profile claude-code --allow-cwd` then `claude` inside |
| Step 5 smoke (Live with profile) | `nono run --profile claude-code -- claude --version` | `nono run --profile claude-code -- cmd /c echo "..."` (non-TUI exercise of the spawn path) |
| Step 5 smoke (Block-net) | `nono run --profile claude-code --block-net -- claude --version` | `nono run --profile claude-code --block-net -- cmd /c "echo block-net ok && curl ..."` |
| Step 5 (new subsection) | — | "Interactive verification (manual)" — `nono shell` walkthrough |
| Between Step 5 and 6 (new section) | — | "Known limitation: `nono run` cannot host TUI agents on Windows" with code pointers + debug-session reference |
| Step 6 table — Happy path | `nono run --profile claude-code -- claude` | `nono shell --profile claude-code --allow-cwd` then `claude` inside |
| Step 6 table — TUI agents | (row missing) | New row pointing to `nono shell` |
| Step 6 table — Read-only review | `nono run --read ...` | `nono shell --read ...` |
| Step 6 table — Offline | `nono run --profile claude-code --block-net -- claude` | `nono shell --profile claude-code --allow-cwd --block-net` |

## Why this matters

The POC user my co-worker would have hit this within seconds of running the cookbook's happy path on a Windows host. `nono run --profile claude-code -- claude` does not error — it appears to start, prints capability info, prints "Applying sandbox...", and then hangs. The supervisor is alive and waiting for a child that has no terminal to render to. Without this fix, every POC user would conclude the binary is broken.

## Root cause (verified in source, not patched here)

- `crates/nono-cli/src/supervised_runtime.rs:105-111` — Windows branch of `should_allocate_pty` returns `interactive_pty` only, ignoring `detached_start`.
- `crates/nono-cli/src/launch_runtime.rs:311` — `nono run` hard-codes `interactive_pty: false`.
- `crates/nono-cli/src/command_runtime.rs:132` — `nono shell` hard-codes `interactive_pty: true`.
- `crates/nono-cli/src/launch_runtime.rs:490` — `select_exec_strategy` is hard-wired to return `Supervised`.

So on Windows, every `nono run` goes through the no-PTY supervised branch. The historical reason is in `.planning/debug/resolved/windows-supervised-exec-cascade.md` — combining `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` with `DETACHED_PROCESS` crashed grandchildren with `STATUS_DLL_INIT_FAILED (0xC0000142)`. The conservative fix at the time disabled PTY allocation entirely on the Windows supervised path; that locked out attached TUI use as a side effect.

## Out of scope

The actual code fix (allocate a PTY on Windows when `!detached_start && stdout.is_terminal()`). That belongs in a `/gsd-debug` task because it must demonstrate that the original `STATUS_DLL_INIT_FAILED` cascade does not regress.

## Verification

- `git diff --stat`: 1 file, +48 / -12.
- `grep "nono run --profile claude-code -- claude" docs/cli/development/windows-poc-handoff.mdx`: 0 hits (the broken happy-path command no longer appears anywhere in the cookbook).
- Renders cleanly as MDX (no broken Note/Warning blocks; only standard markdown + the existing `<Note>` admonition is used).

## Follow-ups

1. **`/gsd-debug`-sized:** restore PTY allocation on Windows for `!detached_start && stdout.is_terminal()` so `nono run -- <TUI>` works. Must replay the original `STATUS_DLL_INIT_FAILED` repro and prove it doesn't reappear. Likely 0.5–1 day with a regression test.
2. **Tiny:** the legacy `docs/cli/development/windows-preview-pilot.mdx` says profile-backed runs are blocked. That part is stale. Could be cleaned up in a 5-minute follow-up commit, but doesn't block POC.
