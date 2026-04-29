---
milestone: v2.2
milestone_name: Windows/macOS Parity Sweep
status: active
created: 2026-04-24
---

# Requirements — v2.2 Windows/macOS Parity Sweep

**Defined:** 2026-04-24
**Core Value:** Every nono command that works on Linux/macOS must work on Windows with equivalent security guarantees.

**Context:** v2.1 Phase 20 synced the fork to upstream `always-further/nono` v0.37.1. Upstream has since shipped v0.38.0, v0.39.0, v0.40.0, and v0.40.1 — each release opens a new Windows-vs-macOS gap because the fork cannot take upstream PRs directly (see quick task 260424-upr SUMMARY.md for the 78-commit / 9k-LOC review). v2.2 closes the current gap and installs a drift-prevention mechanism so v0.41+ don't recreate the problem.

**Scope shape:** All requirements are framed Windows-first. Ports preserve upstream commit provenance via `Upstream-commit:` trailer per the v2.1 Phase 20 cherry-pick-per-commit pattern.

**Pre-milestone:** Merge `windows-squash` → `main` is a separate quick task (not a v2.2 phase). Must land before Phase 22 begins so cherry-picks target stable mainline.

---

## PROF — Profile Struct Alignment

Context: Upstream added 4 new profile fields in v0.38–v0.40 + 1 new built-in profile. Windows must deserialize every field without breaking cross-platform profile parse, apply the macOS-only escape-hatch field on macOS only, and ship the new built-in as a compiled-in option for Windows users.

### REQ-PROF-01 — Profile deserializes `unsafe_macos_seatbelt_rules` field

- **What:** Add `unsafe_macos_seatbelt_rules: Vec<String>` to `Profile` struct with `#[serde(default)]`. Field merges via `dedup_append` in profile inheritance. Rules applied via `add_platform_rule` on macOS only; Windows and Linux parse the field but emit no platform rule. Malformed S-expressions fail fast with a warning.
- **Enforcement:** Deserialize on every platform. Apply only when `cfg(target_os = "macos")`. Schema documents the field with usage guidance (macOS-only escape hatch).
- **Security:** No Windows code path can execute raw Seatbelt rules. `cargo clippy --workspace --all-targets` clean on Windows after the add.
- **Acceptance:**
  1. Cross-platform profile JSON parses cleanly on Windows when `unsafe_macos_seatbelt_rules` is present.
  2. `policy show` surfaces the field prominently (yellow header) and in `--json` output.
  3. macOS `add_platform_rule` call path applies the rules; Windows/Linux paths do not.
- **Maps to:** Upstream `14c644ce feat: add unsafe_macos_seatbelt_rules profile field` + `e3decf9d` + `ecd09313`.

### REQ-PROF-02 — Profile deserializes `packs` + `command_args`

- **What:** Add `packs: Vec<PackRef>` and `command_args: Vec<String>` to `Profile` struct. `packs` may reference registry packs loaded via `Profile::from_registry_pack` path. `command_args` contribute arguments to the sandboxed child command.
- **Enforcement:** Deserialize on all platforms. Pack resolution short-circuits on Windows if registry client unavailable (per platform capability), but profile must still parse.
- **Security:** Pack loading uses signed-artifact trust chain (see PKG-04). No profile can specify a pack that bypasses `override_deny` or other fail-closed checks.
- **Acceptance:**
  1. Profile with `packs: []` and `command_args: []` round-trips through `serde_json` on Windows.
  2. A profile extending a registry-pack loads the pack's contributions with correct precedence.
  3. `command_args` appear in the child process command line.
- **Maps to:** Upstream `088bdad7 feat(profile): introduce packs and command_args for profiles` + `115b5cfa feat(profile): load profiles from registry packs`.

### REQ-PROF-03 — Profile `custom_credentials.oauth2` deserializes

- **What:** Extend `custom_credentials` in Profile to accept an `oauth2: OAuth2Config` block. `OAuth2Config` carries `client_id`, `client_secret` (supports `keyring://` + `env://` URI schemes), `token_url`, and optional `scope`.
- **Enforcement:** Deserialize on all platforms. `client_secret` loaded via existing `nono::keystore::load_secret` path (cross-platform Credential Manager on Windows, keychain on macOS).
- **Security:** `client_secret` never logged; Zeroize-wrapped in memory. `token_url` must be HTTPS (http scheme rejected with a clear error).
- **Acceptance:**
  1. Profile with `custom_credentials.oauth2` parses on Windows and resolves `client_secret` via Credential Manager.
  2. `token_url: http://…` fails profile load with a fail-closed error.
  3. Zeroize test confirms `client_secret` bytes are scrubbed on `Drop`.
- **Maps to:** Upstream `fbf5c06e feat(config): OAuth2Config type` + `b1ecbc02 feat(profile): support OAuth2 auth in custom_credentials`.

### REQ-PROF-04 — `claude-no-keychain` built-in profile available

- **What:** Ship `claude-no-keychain` as a compiled-in built-in profile (via `policy.json` + builtin resolver). Extends `claude-code` but substitutes keychain access with env-var-based credential loading.
- **Enforcement:** Profile appears in `nono profile list`. Resolves correctly on Windows (uses Credential Manager exclusion paths) and macOS (uses keychain exclusion).
- **Security:** Does NOT silently degrade from keyring to env; explicit opt-in only. All `claude-code` `override_deny` entries inherited.
- **Acceptance:**
  1. `nono profile list` shows `claude-no-keychain` on Windows.
  2. `nono run --profile claude-no-keychain -- <cmd>` enforces expected policy without keychain reads.
  3. Profile fails closed if both keyring and env-var paths are unavailable.
- **Maps to:** Upstream `3c8b6756 feat(claude): add no-keychain profile and expand existing access` + `713b2e0f fix(policy): update tests and claude-no-kc for allow_file move`.

---

## POLY — Policy Tightening

Context: Upstream's `5c301e8d refactor(policy)` turns two previously-silent misconfigurations into fail-closed errors, aligning with nono's fail-secure philosophy. Plus two policy rule adjustments for least-privilege.

### REQ-POLY-01 — `override_deny` requires matching grant

- **What:** `override_deny` entries in a profile MUST correspond to an existing user-intent grant. Orphan `override_deny` (no matching allow) returns a fail-closed error at profile load time. Replaces the prior silent-ignore behavior.
- **Enforcement:** Validated during `Profile::resolve` on all platforms. Error variant: `NonoError::PolicyError { kind: OrphanOverrideDeny, ... }`.
- **Security:** Misconfigured profiles fail at load, not silently at runtime. Windows `claude-code`, `claude-no-keychain`, and WSFG-test profiles audited for orphan overrides; fixed or removed before port.
- **Acceptance:**
  1. Profile with orphan `override_deny` fails load with clear error on Windows.
  2. All fork-shipped built-in profiles pass the new check.
  3. Regression test: `profile::tests::override_deny_without_grant_fails_load`.
- **Maps to:** Upstream `5c301e8d refactor(policy): enforce stricter policy for overrides, rollback` + `b83da813 feat(policy): filter profile override deny entries without grants` + `930d82b4 fix(cli): skip non-existent profile deny overrides`.

### REQ-POLY-02 — `--rollback` + `--no-audit` conflict rejected

- **What:** `--rollback` structurally requires audit to be active. CLI flag validation rejects the combination `--rollback` + `--no-audit` with a clear error before sandbox bring-up.
- **Enforcement:** `clap` `conflicts_with` attribute at the CLI layer. Fails instantly; no partial sandbox state. Windows rollback tests updated to not pair the flags.
- **Security:** Rollback requires audit session data; allowing the combination would leave rollback restoring against no integrity record.
- **Acceptance:**
  1. `nono run --rollback --no-audit -- <cmd>` fails with exit code != 0 and error referencing both flags.
  2. Windows rollback integration tests (`crates/nono-cli/tests/rollback*`) pass without pairing `--no-audit`.
  3. Help text for `--rollback` mentions the audit dependency.
- **Maps to:** Upstream `5c301e8d refactor(policy): enforce stricter policy for overrides, rollback`.

### REQ-POLY-03 — `.claude.lock` moved to `allow_file` (least-privilege)

- **What:** Default-profile rule granting access to `.claude.lock` moves from a broader allow-directory scope to a narrow `allow_file` entry. Paired policy test updates for `claude-no-kc` profile.
- **Enforcement:** `policy.json` edit; `compile_filesystem_policy` emits a single-file grant (Windows Low-IL label applied per WSFG mode encoding).
- **Security:** Reduces attack surface from directory-level to file-level. No silent permission expansion.
- **Acceptance:**
  1. `.claude.lock` grant renders as single-file (not directory) grant on Windows.
  2. Windows regression test confirms grant scope matches expectation.
  3. `claude-no-keychain` inherits the narrower grant cleanly.
- **Maps to:** Upstream `49925bbf fix(policy): move .claude.lock to allow_file` + `713b2e0f fix(policy): update tests and claude-no-kc for allow_file move` + `a524b1a7 fix(policy): add entry for ~.local/share/claude/versions` + `7d1d9a0d fix(policy): improve unlink rules; add claude read path`.

---

## PKG — Package Manager + Packs

Context: Upstream v0.38.0 introduced a signed-artifact package manager with profile-as-pack loading, install_dir placement, and hook registration. ~1,500 LOC of new cross-platform code. Windows must cover this subcommand tree with correct path handling, trust chain, and hook installer interaction.

### REQ-PKG-01 — `nono package pull/remove/search/list` subcommands on Windows

- **What:** All four subcommands execute successfully on Windows: `pull <name>` downloads + verifies + installs; `remove <name>` uninstalls + un-hooks; `search <query>` queries the registry; `list` enumerates installed packs.
- **Enforcement:** `package_cmd.rs` + `registry_client.rs` code paths exercised on Windows CI. No `#[cfg(not(windows))]` gates in subcommand surface.
- **Security:** Artifacts verified via `nono::trust::signing` (sigstore-rs) before any filesystem placement. Unverified artifacts never reach `install_dir`.
- **Acceptance:**
  1. `nono package list` returns empty set on a clean Windows install.
  2. `nono package pull <known-good>` places artifacts and registers hooks.
  3. `nono package remove <name>` reverses both.
  4. `nono package search <q>` returns deterministic results against a mock registry.
- **Maps to:** Upstream `8b46573d feat(cli): add package management commands` + `71d82cd0 feat(pack): introduce pack types` + `58b5a24e refactor(cli): improve artifact path validation` + `9ebad89a refactor(pkg): stream package artifact downloads`.

### REQ-PKG-02 — Windows `install_dir` path resolution

- **What:** `install_dir` on Windows resolves to `%LOCALAPPDATA%\nono\packages\<name>` (or equivalent per OS conventions), with long-path (`\\?\` prefix) handling for paths > `MAX_PATH`.
- **Enforcement:** `package.rs` Windows code path uses `windows-sys` directory APIs or `dirs` crate; validates paths via existing canonicalization before write.
- **Security:** Path never escapes `LOCALAPPDATA\nono` via traversal (`..`, symlinks, or UNC aliasing). Regression test covers traversal rejection.
- **Acceptance:**
  1. `nono package pull` writes to `%LOCALAPPDATA%\nono\packages\<name>` on Windows.
  2. Long-path test: install a pack with a name causing path > 260 chars; succeeds via `\\?\` prefix.
  3. Path-traversal regression: pack with `../` in manifest rejected.
- **Maps to:** Upstream `55fb42b8 feat(package): add install_dir artifact placement` + `ec49a7af fix(package): harden package installation security`.

### REQ-PKG-03 — Hook registration/unregistration on Windows

- **What:** `nono package pull` registers hooks via the fork's existing Windows hook installer (`hooks.rs`). `remove` unregisters cleanly. Works with Claude Code hook settings format (the only hook consumer today).
- **Enforcement:** Hook entries written atomically; partial writes don't leave stale hooks. Idempotent install (double-install is a no-op).
- **Security:** Hook script paths validated against `install_dir`; no arbitrary script execution via manipulated hook manifest.
- **Acceptance:**
  1. `nono package pull` registers hooks; Claude Code sees them.
  2. `nono package remove` leaves Claude Code hook settings in pre-install state.
  3. Double-pull is a no-op (no duplicate hook entries).
- **Maps to:** Upstream `55fb42b8 feat(package): add install_dir artifact placement and hook unregistration` + `8b2a5ffb fix(hooks): invoke bash via env` (Windows hook strategy documented as intentionally different).

### REQ-PKG-04 — Signed-artifact streaming download on Windows

- **What:** Artifact download uses streaming HTTP (chunked) through `hyper` + `rustls` + `rustls-webpki`. Progress surfaced to stderr. Verification runs on streamed bytes (not buffered in full memory).
- **Enforcement:** Uses fork's existing `rustls-webpki` 0.103.13+ trust chain. Verification via `nono::trust` module. Windows does NOT fall back to `schannel`.
- **Security:** Invalid signature aborts download + removes partial artifacts. No plaintext HTTP fallback.
- **Acceptance:**
  1. Streaming download succeeds on Windows for a packed artifact of ≥50MB.
  2. Corrupted artifact (tampered mid-stream) is rejected before install.
  3. HTTP-only URL rejected with clear error.
- **Maps to:** Upstream `9ebad89a refactor(pkg): stream package artifact downloads` + `600ba4ec refactor(package-cmd): centralize trust bundle` + `0cbb7e62 refactor(package): simplify artifact signer validation`.

---

## OAUTH — OAuth2 Proxy Credential Injection

Context: Upstream v0.39.0 added ~900 LOC to `nono-proxy` for OAuth2 client-credentials token exchange with in-memory caching. Plus reverse-proxy HTTP upstream support restricted to loopback-only targets.

### REQ-OAUTH-01 — `nono-proxy` client-credentials token exchange with cache

- **What:** `nono-proxy` supports OAuth2 client-credentials flow: on child request, exchanges client_id/client_secret for an access token, caches the token until expiry, injects `Authorization: Bearer <token>` into outbound requests to configured upstreams.
- **Enforcement:** Cross-platform by construction (`nono-proxy` is already cross-platform). Windows proxy-credentials path (Phase 9) accepts `OAuth2Config` shape without Windows-specific branching.
- **Security:** Token cache in memory only (never persisted to disk); Zeroize on expiry. Token exchange endpoint must be HTTPS. Concurrent token-exchange requests coalesce to a single upstream request.
- **Acceptance:**
  1. Windows integration test: `nono run --profile <with-oauth2> -- curl https://api.example.com` receives a `Bearer` token on the request.
  2. Cached token is reused on subsequent requests until expiry.
  3. Expired token triggers silent refresh.
- **Maps to:** Upstream `9546c879 feat(proxy): implement OAuth2 client_credentials token exchange with cache` + `fbf5c06e feat(config): add OAuth2Config type`.

### REQ-OAUTH-02 — Reverse-proxy HTTP upstream gated to local-only

- **What:** `nono-proxy` reverse-proxy mode accepts HTTP upstreams only when the target is loopback (127.0.0.1, ::1) or a bind-local address. Unspecified/wildcard addresses and non-loopback public/private IPs must use HTTPS.
- **Enforcement:** `reverse.rs` enforces at request time before dispatch. Fail-closed: unknown address class rejected, not upgraded silently.
- **Security:** Defense-in-depth atop Windows WFP port-level filtering (Phase 9). WFP enforces at kernel; this check enforces at application layer so a misconfig surfaces earlier.
- **Acceptance:**
  1. `http://127.0.0.1:8080` upstream works.
  2. `http://192.168.1.10:8080` rejected.
  3. `http://0.0.0.0:8080` rejected.
- **Maps to:** Upstream `2bf5668f feat(reverse-proxy): add http upstream support` + `0340ebff` + `b2a24402` + `0c990116`.

### REQ-OAUTH-03 — `--allow-domain` preserved in strict proxy-only mode

- **What:** `--allow-domain` continues to apply when user sets `strict proxy-only` network mode (was previously silently dropped). WFP kernel-level port filter + proxy-level host filter compose cleanly.
- **Enforcement:** `network_policy.rs` retains domain list through strict mode path; dry-run prints it once (no duplicated warning).
- **Security:** No WFP override — domain filter is additive, not a WFP bypass. Windows `net_filter_windows` test fixtures cover the combo.
- **Acceptance:**
  1. `nono run --allow-domain api.example.com --strict-proxy -- <cmd>` enforces both gates on Windows.
  2. Dry-run output lists the domain exactly once.
  3. Port-level WFP allowlist untouched by the strict mode transition.
- **Maps to:** Upstream `10bcd054 fix(network): keep --allow-domain in strict proxy-only mode` + `60ad1eb3 fix(dry): duplicated allow_domain warning-print logic` + `005579a9` + `d44e404e`.

---

## AUD — Audit Integrity + Attestation

Context: Upstream v0.40.0 introduced the largest architectural change in the range — tamper-evident audit log with hash-chain + Merkle root, optional DSSE/in-toto signing, `nono audit verify` command, executable identity recording, and a `prune` → `session cleanup` rename. ~1.4k LOC across `exec_strategy.rs`, `supervised_runtime.rs`, `rollback_runtime.rs`, plus new modules (`audit_integrity.rs`, `audit_session.rs`, `audit_attestation.rs`). Windows supervisor must emit matching events and preserve v2.1 Phase 19 CLEAN-04 invariants through the rename.

### REQ-AUD-01 — `--audit-integrity` hash-chained + Merkle-rooted ledger

- **What:** `nono run --audit-integrity` enables append-only hashing of audit events. Hash-chains supervisor-observed events (capability decisions, URL opens). Computes a Merkle root over all recorded events. Stores integrity summary (`event_count`, `chain_head`, `merkle_root`) in session metadata, viewable via `nono audit show`.
- **Enforcement:** Flag wired at CLI layer; `--audit-integrity` requires supervised execution (not Direct). On Windows, the supervised path (WindowsSupervisorRuntime) records events.
- **Security:** Hash chain prevents event reordering. Merkle root detects tampering anywhere in the ledger. Session metadata is read-only after session closes (file permissions).
- **Acceptance:**
  1. `nono run --audit-integrity -- <cmd>` on Windows produces a session with populated `event_count` > 0, non-empty `chain_head` and `merkle_root`.
  2. `nono audit show <session-id>` displays the integrity summary.
  3. Tamper test: modifying a ledger event invalidates subsequent chain entries.
- **Maps to:** Upstream `4f9552ec feat(audit): add tamper-evident audit log integrity` + `4ec61c29 feat(audit): capture pre/post merkle roots`.

### REQ-AUD-02 — `--audit-sign-key` DSSE/in-toto attestation + `nono audit verify`

- **What:** `--audit-sign-key <key-ref>` enables signing the session Merkle root. Output: `audit-attestation.bundle` (DSSE envelope with in-toto statement) + summary in `session.json`. `nono audit verify [--public-key-file <path>]` checks chain integrity + attestation signature + Merkle-root binding to session metadata.
- **Enforcement:** Requires `--audit-integrity` active. Uses `nono::trust::signing::sign_statement_bundle` + `public_key_id_hex` (cross-platform sigstore-rs; no Windows-specific code). Verify command works offline (key file) and with sigstore Rekor (online lookup per fork's existing trust path).
- **Security:** Private-key reference goes through `nono::keystore` (Credential Manager on Windows). Signature covers session ID + Merkle root + event count.
- **Acceptance:**
  1. `nono run --audit-integrity --audit-sign-key keyring://nono/audit -- <cmd>` on Windows produces `audit-attestation.bundle`.
  2. `nono audit verify <session-id> --public-key-file <path>` succeeds for untampered session; fails for tampered.
  3. Verify surfaces signer key ID in output.
- **Maps to:** Upstream `6ecade2e feat(audit): add audit attestation` + `0b1822a9 feat(audit): add audit verify command`.

### REQ-AUD-03 — Executable identity recorded on Windows

- **What:** Audit ledger records the executable identity (path + signature/hash) of the `nono` binary at session start. On Windows, uses `GetModuleFileNameW` for path resolution and Authenticode signature query for provenance (falls back to SHA-256 hash if unsigned).
- **Enforcement:** `audit_session.rs` or equivalent has a Windows branch distinct from Unix procfs-based resolution.
- **Security:** Signature failures do not prevent session start; they're recorded as `unsigned`. Spoofed binaries surface in `nono audit show` as hash-only entries.
- **Acceptance:**
  1. `nono audit show` on Windows includes `exec_identity` with path + Authenticode status.
  2. Signed release binary shows valid signer chain.
  3. Unsigned dev build shows `unsigned` + SHA-256.
- **Maps to:** Upstream `02ee0bd1 feat(audit): record executable identity` + `7b7815f7 feat(audit): record exec identity and unify audit integrity`.

### REQ-AUD-04 — `prune` → `session cleanup` rename preserves CLEAN-04 invariants

- **What:** `nono prune` becomes `nono session cleanup` (old name remains as hidden alias for one release). `nono audit cleanup` is added as a peer for audit-only sessions. All v2.1 Phase 19 CLEAN-04 invariants preserved: `NONO_CAP_FILE` structural no-op; `--older-than <DURATION>` require-suffix parser; `--all-exited` escape hatch; 100-file auto-sweep threshold; one-shot cleanup of existing stale files.
- **Enforcement:** Rename done at CLI layer. `auto_prune_if_needed` function (or renamed equivalent) retains the `if env::var_os("NONO_CAP_FILE").is_some() { return; }` early-return as its first statement.
- **Security:** A sandboxed agent calling `nono ps` or `nono session list` must NOT be able to trigger host-side file deletion (T-19-04-07 mitigation preserved).
- **Acceptance:**
  1. `nono session cleanup --older-than 7d` works on Windows.
  2. `nono audit cleanup --older-than 30d` works on Windows.
  3. `nono prune` (hidden alias) still works and surfaces a deprecation note.
  4. Regression: `auto_prune_is_noop_when_sandboxed` test passes under both old + new function names.
  5. `--older-than 30` (no suffix) still fails with the CLEAN-04 migration hint.
- **Maps to:** Upstream `4f9552ec feat(audit): add tamper-evident audit log integrity` (section: "Deprecate nono prune, replacing it with nono session cleanup").

### REQ-AUD-05 — Windows supervisor emits ledger events for AIPC broker decisions

- **What:** Windows supervisor (`exec_strategy_windows/supervisor.rs`) emits capability-decision events to the audit ledger for ALL 5 AIPC broker paths: File, Socket, Pipe, JobObject, Event, Mutex. Plus URL-open events from any existing URL-handling surfaces. Events carry: HandleKind, reason (Approved / Denied with reason), brokered access mask, target PID, timestamp.
- **Enforcement:** Emission wired into each `handle_*_request` function. WR-01 reject-stage asymmetry (BEFORE vs AFTER prompt) preserved in event stream but explicitly recorded per event.
- **Security:** Event payload sanitized via `sanitize_for_terminal` before write. No credential material in reason strings. Emissions survive the `AppliedLabelsGuard` cleanup path (events flushed on Drop).
- **Acceptance:**
  1. AIPC integration test: brokering Event + Mutex + Pipe + Socket + JobObject produces 5 corresponding ledger events visible via `nono audit show`.
  2. Denied request (e.g. privileged-port Socket) produces a Denied event with reason `"broker failed: ... privileged port"`.
  3. WR-01 `wr01_*` regression tests still pass and their reject-stage claim is reflected in the ledger (BEFORE-prompt kinds show `backend.calls == 0` equivalent; AFTER-prompt kinds show `backend.calls == 1`).
- **Maps to:** Derived requirement (not a direct upstream commit port) — covers the Windows-specific parity retrofit the 260424-upr review called out as Phase 23 (conditional). Roadmapper may fold into Phase 22-05 or break out into Phase 23 as scope clarifies.

---

## DRIFT — Parity-Drift Prevention

Context: Without a process for absorbing upstream releases, v0.42 and v0.43 will recreate the Windows-vs-macOS gap. This section installs the tooling + cadence so parity becomes maintenance, not milestone-scale work.

### REQ-DRIFT-01 — `check-upstream-drift` reports cross-platform gap

- **What:** A script (PowerShell + Bash twin, or cross-platform Rust tool) that reports commits in `upstream/main..HEAD` (or last-synced tag..latest upstream tag) touching cross-platform files (`crates/nono/src/`, `crates/nono-cli/src/` excluding `*_windows.rs` / `exec_strategy_windows/`, `crates/nono-proxy/src/`, `crates/nono/Cargo.toml`).
- **Enforcement:** Script lives at `scripts/check-upstream-drift.ps1` and `scripts/check-upstream-drift.sh`. Output groups commits by file category (profile, policy, proxy, audit, other).
- **Security:** Read-only (git log, no repo state changes).
- **Acceptance:**
  1. Run against v0.37.1..v0.40.1 reproduces the commit inventory from quick task 260424-upr SUMMARY.md.
  2. Script produces structured output (table or JSON) consumable by humans + CI.
  3. Documented in a short `docs/cli/development/upstream-drift.md`.
- **Maps to:** New — derived from 260424-upr SUMMARY.md § "Recommended v2.2 scope additions".

### REQ-DRIFT-02 — GSD quick-task template for upstream sync

- **What:** A reusable template or skill (`.planning/templates/upstream-sync-quick.md` or similar) that scaffolds an upstream-sync quick task. Template includes: diff-range specification, cherry-pick-per-commit pattern (preserving `Upstream-commit:` trailer), conflict-file inventory, Windows-specific retrofit checklist.
- **Enforcement:** Template exists and is referenced from PROJECT.md § "Upstream Parity Process" or equivalent.
- **Security:** N/A (documentation).
- **Acceptance:**
  1. Template file committed at agreed location.
  2. PROJECT.md references the template.
  3. A dry-run invocation (for v0.41.0) produces a sensible quick-task PLAN.md skeleton.
- **Maps to:** New — derived from 260424-upr SUMMARY.md § "Recommended v2.2 scope additions".

---

## Out of Scope (Explicit Deferrals)

| Item | Reason | Destination |
|------|--------|-------------|
| WR-01 reject-stage unification (AIPC HandleKinds BEFORE vs AFTER prompt) | Windows-internal consistency, not a Windows-vs-macOS gap. Not user-visible. | v2.3+ |
| AIPC G-04 wire-protocol compile-time tightening (`Approved(ResourceGrant)` inline) | Same — internal type-system hardening. Cascades into child SDK + 23 tests. | v2.3+ |
| Cross-platform RESL Unix backends (cgroup v2 / rlimit) | Reverse-direction drift (Windows shipped first, Unix behind). Not a Windows parity issue. | v2.3+ |
| WR-02 EDR HUMAN-UAT | Requires EDR-instrumented runner; no host available. | v3.0 |
| Upstream v0.41.0+ ingestion | Scope cap: v2.2 focuses on v0.38–v0.40. v0.41+ handled via DRIFT-02 template once it lands. | v2.3 first quick task |
| `unsafe_macos_seatbelt_rules` runtime application on Windows | macOS-only by design; Windows deserialize-only per REQ-PROF-01. | Out of scope forever |
| `claude-code integration package` carry-forward vs removal | Product decision: follow upstream's removal. Fork's hook installer (`hooks.rs`) is sufficient. | Removed in PKG-03 wiring |

---

## Traceability

Mapped by gsd-roadmapper 2026-04-24 at v2.2 milestone scope-lock.

| Requirement | Phase | Status |
|-------------|-------|--------|
| PROF-01 | Phase 22 (Plan 22-01) | Complete (commit d12b6535) |
| PROF-02 | Phase 22 (Plan 22-01) | Complete (commit 5040411c) |
| PROF-03 | Phase 22 (Plan 22-01) | Complete (commits bb79552a + 41ac5898) |
| PROF-04 | Phase 22 (Plan 22-01) | Complete (commit 52d4ee49) |
| POLY-01 | Phase 22 (Plan 22-02) | Complete (commits 0d83a1e2 + a47c5962; orphan override_deny fails closed via NonoError::SandboxInit + .exists() pre-filter cross-platform safety) |
| POLY-02 | Phase 22 (Plan 22-02) | Complete (commit 490a8a5c integration test; clap conflicts_with at cli.rs:1602 was already in fork — CONTRADICTION-B confirmed) |
| POLY-03 | Phase 22 (Plan 22-02) | Complete (commit ef0facdc; .claude.lock in filesystem.allow_file for both claude-code and claude-no-kc) |
| PKG-01 | Phase 22 (Plan 22-03) | Complete-partial (6/8 cherry-picks landed; PKG streaming follow-up deferred to v2.3 — needs `ArtifactType::Plugin` + `bundle_json` field + Rule-4 architectural call on `validate_path_within` belt-and-suspenders) |
| PKG-02 | Phase 22 (Plan 22-03) | Complete (`nono remove` flat top-level subcommand; hook unregistration via fork's `hooks.rs`) |
| PKG-03 | Phase 22 (Plan 22-03) | Complete (`nono pull` flat top-level + Claude-Code hook registration via fork's `hooks.rs`) |
| PKG-04 | Phase 22 (Plan 22-03) | Complete (`nono search` + `nono list` flat top-level subcommands; signed-artifact verification at install time) |
| OAUTH-01 | Phase 22 (Plan 22-04) | Complete (commit 5c8df06a; `OAuth2Config` + `nono-proxy/src/oauth2.rs` client-credentials Bearer-token injection) |
| OAUTH-02 | Phase 22 (Plan 22-04) | Complete (`custom_credentials.oauth2` parses in profile; PROF-04 `claude-no-kc` builtin verified) |
| OAUTH-03 | Phase 22 (Plan 22-04) | Complete (reverse-proxy HTTP upstream loopback-only by default + `--allow-domain` strict-proxy composition; CL-03-M literal `client_secret` warning + CL-04-M manifest-export skip + HG-01-M Debug redaction) |
| AUD-01 | Phase 22 (Plan 22-05a) | Complete (commit d15a3ab6; `--audit-integrity` produces hash-chained Merkle-rooted ledger; `audit-events.ndjson` per session; AuditRecorder lifecycle integrated into supervisor; pre/post-merkle roots captured) |
| AUD-02 | Phase 22 (Plan 22-05a) | Complete (`nono audit verify <id>` recomputes per-event leaves + chain head + Merkle root with fail-closed mismatch detection; `--public-key-file <PATH>` flag; HG-01-H upgrade landed cryptographic DSSE bundle verification — commit cffb43b1; 2 fixture-driven tests `#[ignore]`'d pending sigstore-rs `KeyPair::from_pkcs8` re-enablement deferred to v2.3) |
| AUD-03 | Phase 22 (Plan 22-05a SHA-256 + Plan 22-05b Authenticode) | Complete-partial (`executable_identity` SHA-256 portion shipped; on Windows, `WinVerifyTrust` records `Valid` / `Unsigned` / `InvalidSignature{hresult}` discriminant; chain-walker subject extraction deferred to v2.3 — `windows-sys 0.59` does not expose `WTHelperProvDataFromStateData` without `Win32_Security_Cryptography_Catalog` + `Win32_Security_Cryptography_Sip` features) |
| AUD-04 | Phase 22 (Plan 22-05b) | Complete (commit b5640cd4; `prune` → `session cleanup` rename with v2.1 CLEAN-04 byte-identical preservation guaranteed by formal `applied_labels_guard::audit_flush_before_drop` 83 LOC regression test; 5 rename lifecycle items: new `nono session cleanup` + peer `nono audit cleanup` + hidden `nono prune` with stderr deprecation + ALL_SUBCOMMANDS test + `NONO_CAP_FILE` no-op preserved; live UAT 10/10 verified 2026-04-28) |
| AUD-05 | Phase 23 | Pending |
| DRIFT-01 | Phase 24 | Complete (2026-04-27) |
| DRIFT-02 | Phase 24 | Complete (2026-04-27) |

**Coverage target:**
- v2.2 requirements: 21 total
- Mapped to phases: 21
- Unmapped: 0

---
*Requirements defined: 2026-04-24.*
*Last updated: 2026-04-24 at v2.2 milestone scope-lock (traceability filled by gsd-roadmapper).*
