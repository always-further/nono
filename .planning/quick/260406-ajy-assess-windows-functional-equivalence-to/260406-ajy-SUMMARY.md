---
quick_id: 260406-ajy
description: Assess Windows functional equivalence to macOS and Linux
date: 2026-04-06
status: completed
---

# Windows Functional Equivalence Assessment

## Short Answer

**No — Windows is not yet functionally equivalent to macOS and Linux.** It shares the core `nono run` path with OS-enforced sandboxing via Job Objects + WFP, but several surface areas are intentionally unavailable or have a narrower capability contract.

---

## What Windows Supports (parity with Unix)

| Feature | Windows | macOS/Linux |
|---------|---------|------------|
| `nono run` (directory grants, blocked network) | ✅ | ✅ |
| Supervisor process lifecycle (Job Objects) | ✅ | ✅ (signals) |
| Rollback / snapshot | ✅ | ✅ |
| WFP network enforcement (blocked mode) | ✅ | ✅ (Landlock/Seatbelt) |
| `nono ps` / `nono stop` (session management) | ✅ | ✅ |
| `nono setup --check-only` | ✅ | ✅ |
| `nono rollback` | ✅ | ✅ |
| Built-in profiles (`claude-code`, etc.) | ✅ | ✅ |
| `nono run --dry-run` | ✅ | ✅ |

---

## What Windows Does NOT Support (gaps vs Unix)

### Hard gaps (kernel/structural)

| Feature | Status | Notes |
|---------|--------|-------|
| `nono shell` (live) | ❌ Blocked | Intentionally unavailable — no PTY host equivalent |
| `nono wrap` (live) | ❌ Blocked | Intentionally unavailable — one-way apply not portable |
| `nono learn` | ❌ No-op | strace-based path discovery is Linux-only |
| Proxy filtering (`--proxy`, credential injection) | ❌ Unsupported | `classify_supervisor_support` marks ProxyFiltering as unsupported |
| Runtime capability expansion (`--trust`) | ❌ Unsupported | `extensions_enabled()` check fails on Windows |
| Runtime trust interception | ❌ Unsupported | WindowsSupervisorFeatureKind::RuntimeTrustInterception |
| Port-level network filtering | ❌ Unsupported | `PortConnectAllowlist`, `PortBindAllowlist`, `LocalhostPortAllowlist` are all unsupported issues |
| Single-file grants | ❌ Unsupported | `WindowsUnsupportedIssueKind::SingleFileGrant` |
| Write-only directory grants | ❌ Unsupported | `WindowsUnsupportedIssueKind::WriteOnlyDirectoryGrant` |
| Platform-specific rules (Seatbelt) | ❌ N/A | macOS-only; Windows fails closed if attempted |
| Non-default signal/process/IPC modes | ❌ Blocked | Hard-coded to defaults; any variation errors out |
| `nono detach` / `nono attach` (PTY) | ❌ Not supported | PTY-backed sessions not available; named-pipe supervisor only |
| `nono logs` / `nono inspect` / `nono prune` | ❌ Stub | Args structs compile to empty `Default` stubs on Windows |

### Narrower capability contract

| Feature | Windows | macOS/Linux |
|---------|---------|------------|
| Filesystem grants | Directory read + directory read-write only | Full: file, directory, read, write, write-only |
| Network enforcement | WFP blocked-mode or allow-all only | Port-level filtering, proxy domain filtering |
| Approval backend | `windows-preview-deny` (deny all expansion) | Full approval flow with `trust` workflow |

---

## Summary

Windows covers the **primary use case**: running an untrusted agent (`nono run -- agent`) in a sandboxed environment with kernel-enforced filesystem restrictions and network blocking. The core security model (fail-secure, no silent degradation) is intact.

What's missing is the **developer productivity surface** — `shell`, `wrap`, `learn`, proxy credential injection, port-level filtering, and the full PTY-backed session lifecycle. These are structural gaps that would require significant platform-specific work to close.

For the current milestone goal ("Windows parity for supervisor capabilities and WFP network enforcement"), the implementation is complete. For _full feature parity_ with macOS/Linux, the remaining gap list above represents the outstanding work.
