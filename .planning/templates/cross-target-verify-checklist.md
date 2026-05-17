# Cross-Target Clippy Verification Checklist

**Read this template before flipping any plan-touching-cfg-gated-Unix-code REQ to VERIFIED.**

**Source:** Phase 25 CR-A regression lesson (memory `feedback_clippy_cross_target`) + Phase 41 Plans 41-09 / 41-10 (twice mis-verified on Windows-host-only evidence).

---

## Scope

This checklist applies to every plan that touches:
- Files containing `#[cfg(target_os = "linux")]` or `#[cfg(target_os = "macos")]` blocks
- Files containing `#[cfg(any(target_os = "linux", target_os = "macos"))]` blocks
- Files under `crates/nono-cli/src/exec_strategy/` (Unix supervisor code)
- Files under `bindings/c/src/` (FFI code consumed by macOS / Linux runtimes)
- Any file re-exported via Unix-side modules in `crate::exec_strategy` (the non-Windows file path)

Does NOT apply to:
- Pure Windows-only files (e.g. anything under `crates/nono-cli/src/exec_strategy_windows/` that has NO Unix counterpart)
- Pure documentation changes
- Pure build-tooling changes (Cargo.toml, build.rs) that don't change Rust source

## Decision Tree

**Question 1:** Does the plan touch any in-scope file (per § Scope above)?
- **No** → cross-target verification not required. Proceed with standard verification.
- **Yes** → continue to Question 2.

**Question 2:** Can the verifier run `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` on the dev host?
- **Yes (clean exit)** → proceed to Question 3.
- **Yes (errors reported)** → REQ must be marked PARTIAL or GAPS_FOUND. Errors must be closed before flipping to VERIFIED.
- **No (toolchain missing — `error: linker x86_64-linux-gnu-gcc not found` or equivalent)** → either install the cross-toolchain OR mark REQ as PARTIAL with explicit live-CI deferral (see § PARTIAL Disposition below).

**Question 3:** Same as Question 2 but for macOS: `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`.
- **Yes (clean)** → REQ may be flipped to VERIFIED at codebase level.
- **Yes (errors)** → close errors first.
- **No (toolchain missing)** → mark REQ as PARTIAL with explicit live-CI deferral.

**NEVER:** Flip a Unix-touching REQ to VERIFIED based solely on `cargo check --workspace` from a Windows host. `cargo check` does not run clippy, does not enforce `-D warnings`, and does not exercise the Unix-cfg-gated code paths that CI's Linux/macOS clippy lanes do.

## Cross-Toolchain Setup (one-time)

From a Windows dev host:
```bash
rustup target add x86_64-unknown-linux-gnu
rustup target add x86_64-apple-darwin
```

Note: Linux cross-toolchain may require `x86_64-linux-gnu-gcc` for native crates that link to C (`aws-lc-sys`, `ring`). If unavailable via package manager, mark cross-target Linux as load-bearing-but-SKIPPED per § PARTIAL Disposition.

## PARTIAL Disposition

When cross-target clippy CANNOT run from the dev host (toolchain missing, link errors on C-linking crates), the verifier MUST:

1. Mark the related REQ as **PARTIAL** (not VERIFIED) at the codebase level.
2. Add a `human_verification_truths` entry referencing the specific live-CI lane that compensates (e.g., "GH Actions Linux Clippy lane on the head SHA reports no -Dwarnings errors").
3. Set the overall verification status to `human_needed` (not `passed`).
4. Document the SKIPPED reason in the verification report's § "Codebase Evidence" section using this exact prose:

   > Cross-target clippy gate SKIPPED on Windows dev host due to missing toolchain (x86_64-{unknown-linux-gnu | apple-darwin}). The live GH Actions {Linux Clippy | macOS Clippy} lane on the head SHA is the decisive signal per .planning/templates/cross-target-verify-checklist.md. REQ marked PARTIAL pending CI confirmation.

Do NOT flip the REQ to VERIFIED until the live CI lane reports green on the head SHA.

## Anti-Patterns (do NOT do)

- **Anti-pattern 1:** "Documented as load-bearing risk; flipped to VERIFIED anyway" — this is what happened in Phase 41 (twice). Acknowledging the risk in prose does not discharge it. The REQ must be PARTIAL until CI confirms.
- **Anti-pattern 2:** Adding `#[allow(dead_code)]` or `#[allow(clippy::unwrap_used)]` to silence cross-target lints. This violates REQ-CI-01 SC#4 (no raw allows) AND CLAUDE.md § Unwrap Policy. Use cfg-gates, visibility changes, or structural code changes instead.
- **Anti-pattern 3:** Running `cargo check` and assuming it covers clippy. It does not. `cargo check` does not run clippy.
- **Anti-pattern 4:** Running `cargo clippy --workspace` (no `--target`) on Windows host and assuming it covers Linux/macOS. It does NOT — the host-target clippy only exercises Windows cfg branches.

## Enforcement

This checklist is referenced from:
- CLAUDE.md § "Coding Standards" → bullet "Cross-target clippy verification"
- Future close-gate verifications via `/gsd-verify-phase` (verifier reads this file before flipping cfg-gated-Unix-touching REQs)

Established 2026-05-16 by Phase 41 Plan 41-10 Task 5 (REQ-CI-03 closure response to twice-mis-verified REQ-CI-01).
