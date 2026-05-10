---
quick_id: 260509-stb
date: 2026-05-10
status: complete
files_modified:
  - docs/cli/development/windows-poc-handoff.mdx
commits:
  - 10eb64e6  # docs(quick-260509-stb): reframe block-net smoke as WFP-required in POC handoff
---

# Quick Task 260509-stb — Summary

**Description:** fix `docs/cli/development/windows-poc-handoff.mdx` block-net section: doc claimed block-net works without WFP service but code routes `Blocked` mode unconditionally through WFP probe; reframe as WFP-required with prereq.

**Outcome:** Single-file doc fix committed (`10eb64e6`). 8 insertions / 1 deletion. All 7 acceptance grep checks pass.

## Trigger

POC operator ran the cookbook's Must-pass block-net smoke on a fresh Windows install:

```powershell
nono run --profile claude-code --block-net -- cmd /c "echo block-net ok && curl -m 3 https://example.com"
```

Got the WFP-required fail-closed diagnostic instead of the expected curl-fails-blocked behavior:

```
ERROR Platform not supported: Windows WFP runtime activation is required for blocked
Windows network access but the WFP service `nono-wfp-service` is not registered.
Run `nono setup --install-wfp-service` first ... This request remains fail-closed
until WFP activation is implemented.
```

## Investigation findings

| Source | Claim | Verdict |
|--------|-------|---------|
| `windows-poc-handoff.mdx:179` | "Block-net works on Windows without WFP service (Job Object + token-level)" | **False** — see code reality below |
| `network.rs:1469-1542` (`install_wfp_network_backend_with_runner`) | Routes `WindowsNetworkPolicyMode::Blocked` through the same WFP probe path as `AllowAll` and `ProxyOnly`; on probe status `!= Ready` returns `NonoError::UnsupportedPlatform` (line 1537-1539). No Job Object / token-level fallback exists for network blocking. | **Code is correct (fail-closed)** |
| `network.rs:425` | User-facing message: "the WFP service \`{}\` is not registered. Run \`nono setup --install-wfp-service\` first" | **Diagnostic is helpful** |
| `env_vars.rs:770-823` (`windows_run_block_net_blocks_probe_connection`) | Exercises `--block-net` E2E but uses `--dangerous-force-wfp-ready` (line 792) to bypass the prereq probe; the assertion `!text.contains("install-wfp-service")` (line 814) only proves the install-wfp-service hint doesn't leak ONCE WFP is forced ready | **Test coverage is misleading** for the doc's "without WFP service" claim |

**Conclusion:** Documentation bug, not a code bug. The error is correct fail-closed behavior; the doc was lying.

## Edit applied

`docs/cli/development/windows-poc-handoff.mdx` (lines around 178-188):

**Removed:**
```
# Block-net works on Windows without WFP service (Job Object + token-level).
```

**Added (inline prereq + fail-closed-correct callout):**
```
# Block-net requires the WFP service to be registered + running first. Run this ONCE,
# in an elevated PowerShell (admin), before any block-net or network-profile smoke:
#   nono setup --install-wfp-service
#   nono setup --start-wfp-service
# (Skip if `nono setup --check-only` already shows the service is registered & running.)
...
# If you instead see the diagnostic `This request remains fail-closed until WFP activation
# is implemented`, the WFP service prereq above was skipped — fix that and re-run. (This
# is fail-closed-correct behavior, NOT a regression.)
```

The smoke command itself (`nono run --profile claude-code --block-net ...`) was preserved verbatim — POC operators still exercise the WFP-enforced block-net path; the prereq is just made mandatory rather than implicit.

## Acceptance verification

All 7 grep checks pass:

| # | Check | Result |
|--:|-------|--------|
| 1 | False "without WFP service" claim removed | ✓ exit 1 (no match) |
| 2 | "Job Object + token-level" mechanism claim removed | ✓ exit 1 (no match) |
| 3 | `nono setup --install-wfp-service` prereq documented | ✓ line 181 |
| 4 | `nono setup --start-wfp-service` prereq documented | ✓ line 182 |
| 5 | Fail-closed grep anchor preserved | ✓ lines 214, 217 (Must-fail-loudly section unchanged) |
| 6 | Block-net smoke command preserved verbatim | ✓ line 186 |
| 7 | Diff localized to one file | ✓ 8 insertions, 1 deletion |

## Out of scope (follow-ups)

- **Code-side: add a Job Object / token-level network-blocking fallback for `--block-net` when the WFP service is not registered.** This would require designing a non-WFP enforcement primitive on Windows (token integrity-level network restriction is not a directly supportable Win32 mechanism — the AppContainer "Internet Client" capability gates apply only to AppContainer-launched processes, and removing it from a Low-IL token doesn't actually deny outbound TCP). Realistic path: AppContainer + capability stripping, OR a userland host-firewall stub via `INetFwPolicy2` (but that requires admin too, just for a one-time rule add). Either is a Phase 32 (Sigstore Integration) decoy: this is really a v2.4 / v3.0 conversation about whether the Windows Native Build's `--block-net` UX should require a one-time admin install or stay fully unprivileged. Captured here as a follow-up; not blocked.
- **`env_vars.rs:770-823` test could grow a non-`--dangerous-force-wfp-ready` companion** that asserts the user-facing diagnostic when WFP service is genuinely missing — would prove the fail-closed gate is wired correctly without bypass. Low priority; the gate is already validated by the manual smoke that triggered this fix.
- **`nono setup --check-only` could surface block-net-readiness more loudly** — it already lists service status, but the cookbook could lean on it as a "gate" check before the smokes. Polish item; not urgent.

## Phase 32 input

The Phase 32 (Sigstore Integration) scoping conversation should explicitly address whether `--block-net` UX on Windows native build should:
- (a) Stay WFP-required and treat `nono setup --install-wfp-service` as a documented prereq (current state, post-this-fix)
- (b) Add a non-WFP fallback for the simple "block all outbound" case so per-user MSI installs work without admin
- (c) Defer the fallback to v3.0 alongside the kernel mini-filter driver work

Recorded as a candidate decision point for `/gsd-discuss-phase 32`.
