---
title: "Reject --inherit-handle 0x0 in nono-shell-broker argv parser (CR-02 from Phase 31 review)"
created: 2026-05-09
source: .planning/phases/31-broker-process-architecture-shell-01/31-REVIEW.md (CR-02)
target_milestone: v2.4
priority: medium
resolves_phase: 41
---

# CR-02: Broker accepts --inherit-handle 0x0 (null HANDLE)

`crates/nono-shell-broker/src/main.rs` argv parser accepts `--inherit-handle 0x0` (or any null HANDLE value) without validation. Passing a null HANDLE to `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` is undefined Win32 behavior and risks pseudo-handle confusion (e.g., `(HANDLE)-1` is `INVALID_HANDLE_VALUE` but `(HANDLE)0` could resolve to the calling process's pseudo-handle in some Win32 paths).

**Suggested fix:** In the broker's argv parser, reject any `--inherit-handle` value that parses to `0` or `INVALID_HANDLE_VALUE`. Return a structured error and exit non-zero before reaching `UpdateProcThreadAttribute`.

**Source:** Phase 31 code review report `31-REVIEW.md` finding CR-02.
**Impact:** Defense-in-depth against malformed broker invocations. Production cascade in `nono-cli` always passes valid handles; this hardens the broker against direct misuse.
**Acceptance gate:** Add argv validation; add unit test asserting `--inherit-handle 0x0` returns non-zero exit with structured error message.
