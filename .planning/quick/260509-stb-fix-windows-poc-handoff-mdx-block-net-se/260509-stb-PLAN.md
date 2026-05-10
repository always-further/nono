---
phase: 260509-stb-fix-windows-poc-handoff-mdx-block-net-se
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - docs/cli/development/windows-poc-handoff.mdx
autonomous: true
requirements:
  - DOCS-WPOC-BNET-01  # Reframe block-net section as WFP-required, not "Job Object + token-level"
  - DOCS-WPOC-BNET-02  # Surface the install-wfp-service prereq + start-wfp-service before the block-net smoke
must_haves:
  truths:
    - "The line 'Block-net works on Windows without WFP service (Job Object + token-level)' is removed from windows-poc-handoff.mdx"
    - "Operators are told they must run `nono setup --install-wfp-service` (admin) and `nono setup --start-wfp-service` once before any --block-net smoke"
    - "The block-net smoke is reframed so failure with 'This request remains fail-closed until WFP activation is implemented' indicates the prereq was skipped, not a regression"
    - "The fail-closed grep anchor 'This request remains fail-closed until WFP activation is implemented' continues to be the documented detection signal"
  artifacts:
    - path: "docs/cli/development/windows-poc-handoff.mdx"
      provides: "Windows POC handoff cookbook with block-net section corrected"
      contains: "nono setup --install-wfp-service"
    - path: ".planning/quick/260509-stb-fix-windows-poc-handoff-mdx-block-net-se/260509-stb-SUMMARY.md"
      provides: "Findings + the single doc edit applied"
  key_links:
    - from: "docs/cli/development/windows-poc-handoff.mdx (block-net smoke prereq)"
      to: "WFP probe code in crates/nono-cli/src/exec_strategy_windows/network.rs:1469-1542"
      via: "Documented prereq matches code's unconditional WFP probe for Blocked mode"
      pattern: "install-wfp-service"
---

<objective>
Fix one stale claim and one missing prereq in `docs/cli/development/windows-poc-handoff.mdx`. The doc currently says block-net works without the WFP service via "Job Object + token-level" enforcement; in reality `network.rs:install_wfp_network_backend_with_runner` (lines 1469-1542) routes `WindowsNetworkPolicyMode::Blocked` unconditionally through a WFP service probe, and on probe failure returns `NonoError::UnsupportedPlatform` with the user-facing "Run `nono setup --install-wfp-service` first" diagnostic. There is no Job Object–based network-blocking primitive in the Windows code path.

This bug surfaced when a POC operator ran the cookbook's `--block-net` smoke test on a fresh Windows install and got the WFP-required fail-closed diagnostic — exactly what the doc told them shouldn't happen.

Purpose: keep the cookbook truthful so day-1 POC operators don't conclude there's a regression. The error is correct fail-closed behavior; the doc is the lying party.

Output: a single commit modifying only `docs/cli/development/windows-poc-handoff.mdx`.
</objective>

<verified_facts>
**Fact A — code reality** (read by the orchestrator before this plan was written):
- `crates/nono-cli/src/exec_strategy_windows/network.rs:1469-1542` (`install_wfp_network_backend_with_runner`) handles all three `WindowsNetworkPolicyMode` variants (`AllowAll`, `Blocked`, `ProxyOnly`) through the same WFP probe path. There is no Job Object / token-level fallback for `Blocked`.
- On probe status != `Ready`, the function returns `NonoError::UnsupportedPlatform(describe_wfp_runtime_activation_failure(...))` — line 1537-1539.
- The user-facing message at `network.rs:425` is exactly: `the WFP service \`{}\` is not registered. Run \`nono setup --install-wfp-service\` first`.

**Fact B — test coverage** (read before this plan was written):
- `crates/nono-cli/tests/env_vars.rs:770-823` (`windows_run_block_net_blocks_probe_connection`) does exercise the `--block-net` path end-to-end, but uses `--dangerous-force-wfp-ready` (line 792) to bypass the prereq check. The assertion `!text.contains("install-wfp-service")` (line 814) only proves that ONCE the WFP path is forced ready, no install-wfp-service hint is leaked — it does NOT prove block-net works without WFP service registration.

**Fact C — existing doc structure** (read before this plan was written):
- The existing `## Step 4 — Smoke test the binary` section is split into "Must-pass" and "Must-fail loudly" subsections.
- The current "Must-pass" block at lines 178-183 contains both the false claim and the smoke command.
- The "Must-fail loudly" block at lines 190-212 already documents the WFP-required diagnostic and the grep anchor `This request remains fail-closed until WFP activation is implemented`.

**Fact D — out of scope**:
- Adding Job Object / token-level network blocking is a code change that would land in Phase 32 or later, not in a doc-fix quick task.
- Running `nono setup --install-wfp-service` to test the prereq path requires admin and is not done by this task.
</verified_facts>

<tasks>

## Task T-260509-stb-01: Reframe the block-net smoke as WFP-required

<read_first>
- docs/cli/development/windows-poc-handoff.mdx (the file being edited — read lines 155-215 for context)
- crates/nono-cli/src/exec_strategy_windows/network.rs (verified facts above already capture the relevant snippets)
</read_first>

<action>
Edit `docs/cli/development/windows-poc-handoff.mdx` to apply the following changes in a single Edit-tool call (find-replace pattern; the lines around 178-183 in the current file).

**Replace:**
```
# Block-net works on Windows without WFP service (Job Object + token-level).
# Use a non-interactive child so the smoke is a one-liner. (Interactive `nono shell` is
# also supported as of Phase 31 — see the security-envelope section for the broker path.)
nono run --profile claude-code --block-net -- cmd /c "echo block-net ok && curl -m 3 https://example.com"
# The curl call should fail/timeout since outbound is blocked. Verify exit and no body returned.
```

**With:**
```
# Block-net requires the WFP service to be registered + running first. Run this ONCE,
# in an elevated PowerShell (admin), before any block-net or network-profile smoke:
#   nono setup --install-wfp-service
#   nono setup --start-wfp-service
# (Skip if `nono setup --check-only` already shows the service is registered & running.)
# Use a non-interactive child so the smoke is a one-liner. (Interactive `nono shell` is
# also supported as of Phase 31 — see the security-envelope section for the broker path.)
nono run --profile claude-code --block-net -- cmd /c "echo block-net ok && curl -m 3 https://example.com"
# The curl call should fail/timeout since outbound is blocked. Verify exit and no body returned.
# If you instead see the diagnostic `This request remains fail-closed until WFP activation
# is implemented`, the WFP service prereq above was skipped — fix that and re-run. (This
# is fail-closed-correct behavior, NOT a regression.)
```

**Rationale (do NOT include this in the doc itself):** removes the false "Job Object + token-level" claim, anchors the prereq commands the user actually needs, and points the user at the existing grep-stable fail-closed diagnostic when the prereq was skipped. Keeps the smoke in Must-pass (so POC operators still exercise the WFP-enforced block-net path), but makes the prereq mandatory rather than implicit.
</action>

<acceptance_criteria>
- `grep -nE "Block-net works on Windows without WFP service" docs/cli/development/windows-poc-handoff.mdx` returns exit 1 (no matches; the false claim is removed).
- `grep -nE "Job Object \+ token-level" docs/cli/development/windows-poc-handoff.mdx` returns exit 1 (the false mechanism claim is removed).
- `grep -nE "nono setup --install-wfp-service" docs/cli/development/windows-poc-handoff.mdx` returns exit 0 (the prereq is now documented inline with the block-net smoke).
- `grep -nE "nono setup --start-wfp-service" docs/cli/development/windows-poc-handoff.mdx` returns exit 0 (the start step is documented).
- `grep -nE "This request remains fail-closed until WFP activation is implemented" docs/cli/development/windows-poc-handoff.mdx` returns exit 0 — the existing grep-stable anchor remains in the file (it should still appear in the Must-fail-loudly section as well as the new "if you see this here, it means prereq skipped" callout).
- `grep -nE "fail-closed-correct" docs/cli/development/windows-poc-handoff.mdx` returns exit 0 — the operator is told the diagnostic is intentional, not a regression.
- The block-net smoke command itself (`nono run --profile claude-code --block-net -- cmd /c "echo block-net ok && curl -m 3 https://example.com"`) is preserved verbatim.
- No other section of the file is modified (the diff is localized to the lines around the block-net Must-pass entry).
</acceptance_criteria>

<done>
A single Edit-tool call applied; `git diff -- docs/cli/development/windows-poc-handoff.mdx` shows only the localized replacement in the Must-pass block. The acceptance grep checks above all pass. Commit with: `docs(quick-260509-stb): reframe block-net smoke as WFP-required in POC handoff`.
</done>

</tasks>

<verification>

| Check | Command | Expected |
|------:|--------|---------|
| False claim removed | `grep -nE "Block-net works on Windows without WFP service" docs/cli/development/windows-poc-handoff.mdx` | exit 1 |
| Job-Object claim removed | `grep -nE "Job Object \+ token-level" docs/cli/development/windows-poc-handoff.mdx` | exit 1 |
| Prereq install command documented | `grep -n "nono setup --install-wfp-service" docs/cli/development/windows-poc-handoff.mdx` | exit 0, ≥1 hit |
| Prereq start command documented | `grep -n "nono setup --start-wfp-service" docs/cli/development/windows-poc-handoff.mdx` | exit 0, ≥1 hit |
| Fail-closed anchor preserved | `grep -n "This request remains fail-closed until WFP activation is implemented" docs/cli/development/windows-poc-handoff.mdx` | exit 0, ≥1 hit |
| Block-net smoke command preserved | `grep -n "nono run --profile claude-code --block-net" docs/cli/development/windows-poc-handoff.mdx` | exit 0, ≥1 hit |
| Diff localized | `git diff --stat -- docs/cli/development/windows-poc-handoff.mdx` | one file, small line delta |

</verification>
