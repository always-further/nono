# Requirements: nono — Windows Gap Closure (v2.0)

**Defined:** 2026-04-06
**Core Value:** Every nono command that works on Linux/macOS should work on Windows with equivalent security guarantees, or be explicitly documented as intentionally unsupported with a clear rationale.

## v1.0 Requirements (Validated)

All v1.0 requirements are complete. Carried here for traceability.

### Supervisor Control (SUPV)

- [x] **SUPV-01**: User can detach from a running Windows agent using `nono run --detach`.
- [x] **SUPV-02**: User can re-attach to a running Windows agent session via Named Pipe IPC.
- [x] **SUPV-03**: User can list all running Windows agent processes using `nono ps`.
- [x] **SUPV-04**: User can atomically stop a Windows agent and its entire process tree using `nono stop`.
- [x] **SUPV-05**: Windows Job Objects are named using session IDs to allow persistent management after CLI exit.

### Network Sandboxing (NETW)

- [x] **NETW-01**: User can block network access for Windows agents using the WFP (Windows Filtering Platform) backend.
- [x] **NETW-02**: WFP rules persist correctly during detach/attach cycles via a background supervisor process.
- [x] **NETW-03**: User can allow specific local ports on Windows via WFP-enforced filtering.

### State Management (STAT)

- [x] **STAT-01**: User can create a filesystem snapshot of a Windows workspace before execution.
- [x] **STAT-02**: User can rollback Windows filesystem changes to a previous snapshot using `nono rollback`.

### Deployment & Packaging (DEPL)

- [x] **DEPL-01**: Windows MSI packages (machine and user) are automatically generated and signed in CI.
- [x] **DEPL-02**: CLI provides a unified support status report on Windows via `nono setup --check-only`.

## v2.0 Requirements (Active)

Gap closure milestone. Closes the 7 remaining feature gaps between Windows and Unix platforms.

### Wrap (WRAP)

- [ ] **WRAP-01**: User can run `nono wrap <cmd>` on Windows using Direct strategy with Job Object + WFP enforcement; help text documents that the supervisor stays alive as Job Object owner (no exec-replace, unlike Unix).

### Session Commands (SESS)

- [ ] **SESS-01**: User can view logs for a Windows session using `nono logs <session>`.
- [ ] **SESS-02**: User can inspect a Windows session record in JSON format using `nono inspect <session>`.
- [ ] **SESS-03**: User can prune stale Windows session records using `nono prune`.

### Interactive Shell (SHELL)

- [ ] **SHELL-01**: User can run `nono shell` to launch an interactive PowerShell or cmd.exe session inside a Job Object + WFP sandbox via ConPTY on Windows 10 build 17763+; terminal resize and Ctrl-C forwarding work correctly; no silent fallback to non-PTY path on unsupported builds.

### Network Policy (PORT, PROXY)

- [ ] **PORT-01**: User can allow specific ports for outbound TCP connections on Windows using `--allow-port`; bind and connect allowlists operate independently; WFP permit filters have higher weight than the block-all filter.
- [ ] **PROXY-01**: User can route sandboxed agent traffic through a local proxy via `--proxy-only` with `HTTPS_PROXY` credential injection; a WFP loopback permit filter ensures the proxy port is reachable; all other outbound traffic is blocked.

### Path Discovery (LEARN)

- [ ] **LEARN-01**: User can run `nono learn <cmd>` on Windows to capture file and network access patterns via ETW; output format matches Unix learn format so existing profile tooling works unchanged; running without admin privilege produces a clear error rather than silent empty output.

### Runtime Expansion — Stretch (TRUST)

- [ ] **TRUST-01** *(stretch)*: A sandboxed child process can request additional capabilities from the supervisor at runtime via named pipe; the supervisor prompts the user for approval before granting; requests without a valid session token are denied immediately with a constant-time comparison.

## Future Requirements

Tracked but not in current roadmap.

### Resource Limits (RESL)

- **RESL-01**: User can set CPU usage limits for Windows agent Job Objects.
- **RESL-02**: User can set memory usage limits for Windows agent Job Objects.

### Advanced IPC (AIPC)

- **AIPC-01**: Secure handle brokering (passing file handles) via Named Pipe IPC.

## Out of Scope

| Feature | Reason |
|---------|--------|
| Gap 6b: Runtime file-open interception (kernel minifilter) | Requires a signed kernel-mode minifilter driver; no user-mode workaround is acceptable. Deferred to v3.0. |
| Job Object nesting | Excessive complexity; single-job model is sufficient for parity. |
| Global kernel walk | Security risk and performance overhead. |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| WRAP-01 | Phase 7 | Pending |
| SESS-01 | Phase 7 | Pending |
| SESS-02 | Phase 7 | Pending |
| SESS-03 | Phase 7 | Pending |
| SHELL-01 | Phase 8 | Pending |
| PORT-01 | Phase 9 | Pending |
| PROXY-01 | Phase 9 | Pending |
| LEARN-01 | Phase 10 | Pending |
| TRUST-01 | Phase 11 (stretch) | Pending |

**Coverage:**
- v2.0 requirements: 9 total (8 firm + 1 stretch)
- Mapped to phases: 9
- Unmapped: 0 ✓

---
*Requirements defined: 2026-04-06*
*Last updated: 2026-04-06 — v2.0 traceability updated with phase numbers (Phases 7–11)*
