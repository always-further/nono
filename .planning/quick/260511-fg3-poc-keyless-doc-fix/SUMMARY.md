---
slug: poc-keyless-doc-fix
quick_id: 260511-fg3
created: 2026-05-11
completed: 2026-05-11
type: docs-fix
status: complete
---

# Summary: Strip nonexistent `--keyless` flag from POC docs — FIXED

## What broke

POC user followed `docs/cli/development/windows-poc-handoff.mdx` and ran
`nono trust verify --keyless`. The CLI rejected the flag with a clap argument-not-found error.

## Root cause

`--keyless` is a **sign**-side flag only (`crates/nono-cli/src/cli.rs` ~L2695-2697 — selects
ambient-OIDC keyless signing). On `nono trust verify`, keyless mode is signaled by providing
both **`--issuer <URL>`** and **`--identity <REGEX>`** (~L2749-2758), and both flags are
fail-closed-mandatory per Phase 32 D-32-07..10 (commit `f7a1bdf8feat(32-03): harden keyless
verify --issuer/--identity flags + polish OIDC error`).

The POC handoff doc was drift from the prototype-spec phase, when keyless was envisioned as a
boolean. The final shape landed at Plan 32-03 as "both flags or fail-closed" — but 7
references in the handoff doc still wrote `nono trust verify --keyless`.

## Yes, Sigstore IS in the Windows POC

For the record: Phase 32 (shipped 2026-05-10) is the Sigstore Integration phase, and three
of its surfaces are Windows-POC-critical:

1. **Broker self-trust-anchor (D-32-11..14)** — `nono.exe` verifies its own Authenticode
   signature, then requires `nono-shell-broker.exe`'s signature to match (subject + thumbprint)
   at every `BrokerLaunch` dispatch. Phase 31 broker-process architecture (the Windows-only
   `crates/nono-shell-broker/`) depends on this gate. `nono setup --check-only` surfaces the
   exact subject + thumbprint nono.exe is comparing against.
2. **TUF cached-root (D-32-01..06,15)** — per-user `~/.nono/trust-root/trusted_root.json`,
   no admin required. Fail-closed if missing/expired with recovery hint naming
   `nono setup --refresh-trust-root`. Verify-is-offline is structurally and dynamically
   enforced (no inline network on the verify path).
3. **Keyless CLI hardening (D-32-07..10)** — `--issuer`/`--identity` mandatory + fail-closed
   on verify; `--identity` regex full-string anchored to prevent `release.yml.evil` substring
   bypass (CR-03 fix).

See ADRs `docs/architecture/broker-trust-anchor.md` and `docs/architecture/sigstore-tuf-cache.md`.

## Fix

One file touched: `docs/cli/development/windows-poc-handoff.mdx`. Three edit hunks covering
the 7 references:

- **Prose mentions (4 lines):** `nono trust verify --keyless` → `keyless nono trust verify`
  (preserves the "keyless verify" semantic concept; drops the literal nonexistent-flag syntax).
- **Code-block invocations (3 powershell examples):** dropped the ` --keyless` token. The
  `--issuer` + `--identity` flags stay (they're the actual keyless-mode signal).
- **Plan 32-03 contract clarification:** added one sentence to the `### Verifying
  Keyless-Signed Artifacts` paragraph: "Providing both is what selects keyless mode; there is
  no separate `--keyless` boolean on verify."

## Verification

| Check | Result |
|-------|--------|
| `grep -c "trust verify --keyless" docs/cli/development/windows-poc-handoff.mdx` | ✅ **0** (was 7) |
| `grep -rn "trust verify --keyless" docs/` (workspace-wide) | ✅ **0 hits** |
| `grep -c "trust sign --keyless" docs/cli/features/trust.mdx` | ✅ **1** (preserved — sign-side flag is real) |
| Surrounding doc structure (PowerShell line-continuation backticks, headings) | ✅ unchanged |
| `nono.exe trust verify --help` (binary check) | ✅ confirms `--issuer` + `--identity` are the documented flags; no `--keyless` |

## Correct invocation (for the POC user)

```powershell
# GitHub Actions canonical pattern
nono trust verify `
  --issuer https://token.actions.githubusercontent.com `
  --identity '^https://github\.com/<org>/<repo>/\.github/workflows/release\.yml@refs/tags/v.*$' `
  <bundle-file>
```

Prerequisite: `nono setup --refresh-trust-root` must have been run once on the host first
(populates `~/.nono/trust-root/trusted_root.json`). Verify checks the cache offline; if the
cache is missing or expired, verify fails fast with the exact `nono setup` recovery command in
the error text.

## Files touched

- `docs/cli/development/windows-poc-handoff.mdx` (3 edit hunks; net -7 `--keyless` tokens, +1
  contract-clarification sentence)

## Acceptance — all checked

- [x] Zero `trust verify --keyless` references in `docs/cli/development/windows-poc-handoff.mdx`
- [x] Zero `trust verify --keyless` references workspace-wide in `docs/`
- [x] `trust sign --keyless` references preserved (sign-side flag is real)
- [x] PowerShell-block backtick continuations preserved
- [x] Reader still understands what "keyless verify" means and when it applies

## Open follow-ups (out of scope)

- **No production CLI change is needed.** The user's binary already has the correct
  `--issuer` + `--identity` shape (these landed in Phase 32 Plan 32-03 / commit `f7a1bdf8`).
  As long as they're running a post-Phase-32 binary (any build of `main` after 2026-05-10),
  the correct invocation works.
- **If the user's installed binary predates Phase 32:** their `nono trust verify` won't have
  `--issuer`/`--identity` at all (the flags are post-Phase-32). In that case they need to
  reinstall from the post-Phase-32 release binary — same install-path issue as the
  Landlock-leak fix (quick task `260511-eiy-landlock-windows-leak`). `nono setup --check-only`
  reports the binary's Authenticode subject + thumbprint, which lets the operator confirm
  they're running the intended build.
