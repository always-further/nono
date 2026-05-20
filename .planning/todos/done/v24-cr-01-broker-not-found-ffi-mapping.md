---
title: "Re-map NonoError::BrokerNotFound to FFI ErrSandboxInit (CR-01 from Phase 31 review)"
created: 2026-05-09
source: .planning/phases/31-broker-process-architecture-shell-01/31-REVIEW.md (CR-01)
target_milestone: v2.4
priority: low
resolves_phase: 41
---

# CR-01: BrokerNotFound FFI mapping is semantically wrong

`bindings/c/src/lib.rs:128-134` maps `NonoError::BrokerNotFound { path }` to `NonoErrorCode::ErrPathNotFound`. Plan 31-01 documented this as a "closest C-API code" choice but the semantic class is wrong: `BrokerNotFound` is an installation/runtime defect (sibling artifact missing), not a user-input path-resolution failure.

**Suggested fix:** Map to `ErrSandboxInit` (or add a dedicated `ErrBrokerMissing` variant if the C ABI supports additive enum changes).

**Source:** Phase 31 code review report `31-REVIEW.md` finding CR-01.
**Impact:** Affects only C-API consumers (nono-py, nono-ts, nono-ffi callers) interpreting error codes from `nono shell` invocations. Does not affect Rust-side behavior or the security envelope.
**Acceptance gate:** Update mapping; update `bindings/c/include/nono.h` doc-comments; verify no breakage in nono-py / nono-ts.
