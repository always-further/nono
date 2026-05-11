---
slug: poc-keyless-doc-fix
quick_id: 260511-fg3
created: 2026-05-11
type: docs-fix
status: in-progress
---

# Quick task: Strip nonexistent `--keyless` flag from `nono trust verify` POC docs

## Problem

POC user ran `nono trust verify --keyless` (as instructed by
`docs/cli/development/windows-poc-handoff.mdx`) and got a clap "argument not found" error.

## Root cause

The CLI's `verify` subcommand (`crates/nono-cli/src/cli.rs` ~L2749-2758) accepts
**`--issuer <URL>`** and **`--identity <REGEX>`** as the keyless-mode signals — both
fail-closed-mandatory per Phase 32 D-32-07..10 (commit `f7a1bdf8`). There is NO `--keyless`
boolean on verify; that flag exists only on `nono trust sign` (cli.rs ~L2695-2697) where it
selects ambient-OIDC keyless signing.

The POC handoff doc references `nono trust verify --keyless` in 7 places — documentation
drift from the prototype-spec phase (when keyless was envisioned as a boolean) vs the final
"both flags or fail-closed" shape that landed at Plan 32-03 / commit `f7a1bdf8`. The doc's
own line 191 already states the right contract ("requires explicit `--issuer` and
`--identity`"); the surrounding examples and prose just kept the obsolete flag.

## Scope

Strip `--keyless` from `nono trust verify ...` references in
`docs/cli/development/windows-poc-handoff.mdx` at 7 line locations:

- **Code blocks (3):** lines ~198, ~207, ~216 (GitHub Actions, this-project, GitLab CI
  examples). Remove the literal ` --keyless` token; the surrounding `--issuer` + `--identity`
  flags stay.
- **Prose (4):** lines ~154, ~169, ~172, ~191. Rephrase from
  "`nono trust verify --keyless` requires/runs/fails ..." to
  "keyless `nono trust verify` requires/runs/fails ..." (or equivalent). The semantic intent
  ("keyless verification") stays; the literal nonexistent-flag syntax drops.

## Out of scope

- **No CLI changes.** The verify-flag shape is locked by Phase 32 D-32-07..10. The doc was
  wrong, not the CLI.
- **No changes to sign-side `--keyless` references** in `docs/cli/features/trust.mdx`,
  `docs/cli/internals/wsl2-feature-matrix.mdx`, `docs/cli/usage/flags.mdx`, or
  `docs/templates/trust-policy-keyless-template.json`. Sign-side `--keyless` is a real flag
  and those references are correct.
- **No changes to test files** (`crates/nono-cli/tests/keyless_*.rs`) — they use the actual
  CLI surface and are correct.
- **No CLAUDE.md updates** — Sigstore CLI surface is not documented there; nothing to drift.

## Files touched

1. `docs/cli/development/windows-poc-handoff.mdx` (~7 edit hunks)

## Acceptance

- [ ] `grep -n "trust verify --keyless" docs/cli/development/windows-poc-handoff.mdx` returns
      zero matches.
- [ ] `grep -n "trust sign --keyless" docs/cli/features/trust.mdx` still returns ≥1 match
      (sign-side flag is real; we don't touch it).
- [ ] PowerShell-block examples retain trailing backticks for line-continuation; YAML/markdown
      structure unchanged elsewhere.
- [ ] Render-readable: the prose still names "keyless verify" as a concept; reader still
      knows when keyless mode applies.
