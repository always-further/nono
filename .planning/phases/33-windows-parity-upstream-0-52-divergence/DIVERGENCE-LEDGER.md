---
slug: divergence-ledger-v041-v052
status: complete
type: audit-only
date: 2026-05-11
range: v0.40.1..v0.52.0
upstream_head_at_audit: 54f7c32a315dabe56cf0530e8ea6bdc44985122d
drift_tool_sh_sha: 0834aa664fbaf4c5e41af5debece292992211559
drift_tool_ps1_sha: 0834aa664fbaf4c5e41af5debece292992211559
drift_tool_invocation: 'make check-upstream-drift ARGS="--from v0.40.1 --to v0.52.0 --format json"'
fork_baseline: v0.40.1 (Phase 22 UPST2 sync point — 2026-04-28)
total_unique_commits: 97
---

# Upstream v0.40.1 -> v0.52.0 divergence ledger

## Headline

**97 non-merge commits across 12 minor releases (v0.41.0 -> v0.52.0); ~24,094 insertions / ~7,728 deletions across drift-tool categories: profile=15, policy=5, package=5, proxy=6, audit=4, other=91.**

Twelve themed clusters span the range. Eight clusters disposition `will-sync` (carry into Phase 34 UPST3-sync execution); three `fork-preserve` (manual-replay shape per D-20, cherry-pick would delete fork-only Windows wiring — `pty_proxy_windows.rs` ConPTY path, claude-code Phase 18.1-03 widening, nono-proxy Windows credential injection); one `won't-sync` (Unix-socket-typed capability is structurally Unix-only and would expose a no-op enum variant on the Windows backend, violating D-19 if pulled in this audit cycle).

**CRITICAL audit finding (contradicts G-25-DRIFT-01 hypothesis):** The audit surfaces ZERO commits matching the four RESL flag rename keywords (`--memory`, `--cpu-percent`, `--max-processes`, `--timeout` -> renamed forms) anywhere in the v0.40.1..v0.52.0 range. The G-25-DRIFT-01 entry recorded at Phase 25 HUMAN-UAT time (2026-05-10) cited "deprecated/renamed in upstream nono v0.52" as the originating concern; this audit shows that claim is empirically false against `upstream/main` HEAD `54f7c32a` at `2026-05-11`. Upstream at v0.52.0 still ships the 4 flags under their original Phase 25 names. Wave 2 ADR + Wave 3 REQ-4 G-25-DRIFT-01 update MUST re-classify this gap (the divergence does not exist).

## Reproduction

This audit is regenerable from the values in the YAML frontmatter above (D-33-A2):

```bash
git fetch upstream --tags
# Drift-tool script pinned at sha 0834aa664fbaf4c5e41af5debece292992211559 (Phase 24 ship sha; unchanged at audit time):
make check-upstream-drift ARGS="--from v0.40.1 --to v0.52.0 --format json"
# (On Windows hosts where `make` is not on PATH, the Makefile target dispatches to
#  bash scripts/check-upstream-drift.sh ... — same shell command, same JSON output.)
```

Per D-33-A2 the raw JSON output is NOT committed. The cluster tables below are the canonical artifact — the JSON is regenerable on demand from the locked invocation + the upstream HEAD sha + drift-tool script sha recorded in the frontmatter.

Per D-11 (see [Phase 24 CONTEXT.md](../24-parity-drift-prevention/24-CONTEXT.md) D-11), `*_windows.rs` and `crates/nono-cli/src/exec_strategy_windows/` are EXCLUDED from drift-tool output. Fork-only Windows surface added since v0.40.1 is enumerated in [§ Fork-only surface area](#fork-only-surface-area) below; cluster dispositions cover only the cross-platform surface the tool walks.

**Inspection methodology** (per RESEARCH Open Question #3): each commit's `subject` + `categories` + `files_changed[]` length was read from the drift JSON for every row (free from JSON); per-commit diffs were read for the lead commit in each cluster (the one introducing the feature) and any commit whose subject was ambiguous re: disposition.

## Cluster Summary

| # | Cluster (introduced in) | Commit count | Disposition | One-line summary |
|---|-------------------------|--------------|-------------|------------------|
| 1 | PTY attach/detach + signal handling (v0.41.0) | 7 | `won't-sync` | Unix-side scrollback/alt-screen polish; fork's ConPTY attach path on Windows is structurally different (D-11) |
| 2 | Profile/policy CLI consolidation + denial diagnostics (v0.41.0) | 6 | `will-sync` | `nono policy` -> `nono profile` consolidation + denial diagnostics; user-facing CLI surface match (G-25-DRIFT-01 class) |
| 3 | Unix socket capability + --allow-unix-socket (v0.42.0) | 4 | `won't-sync` | New `UnixSocketCapability` enum variant — Unix-only by construction, Windows backend has no analog |
| 4 | Proxy/network policy hardening (v0.42.0) | 4 | `will-sync` | Three behavioral fixes the fork should pick up: NO_PROXY hole, port allowlist, native TLS roots for packages |
| 5 | Headless keyring + display/quoting fixes (v0.43.0) | 8 | `will-sync` | Optional `system-keyring` feature for headless builds + audit-display char-aware truncation + shell-quote |
| 6 | Pack migration + claude-code/codex registry relocation (v0.44.0) | 6 | `fork-preserve` | Builtin profiles -> registry packs migration; replay would delete v2.1 Phase 18.1-03 widening wiring (D-20) |
| 7 | Path canonicalization + profile JSON schema restructure (v0.46.0) | 23 | `will-sync` | Largest cluster (23 commits): canonical profile schema + path canonicalization + draft/extends fixes |
| 8 | Shell completion + string-truncation refactor (v0.48.0) | 8 | `will-sync` | `nono completion <shell>` + truncation panic fix + string-truncation utility refactor |
| 9 | Trust scan path-traversal hardening + YAML merge directive (v0.49.0) | 8 | `will-sync` | Trust scan symlink-escape + path-traversal rejection + YAML merge wiring directive + serde_yaml_ng pin |
| 10 | CLI ps display + env:// credentials + ioctl native types (v0.50.0) | 7 | `will-sync` | `env://` URI in custom_credentials + nono ps column polish + Linux ioctl native-type fix |
| 11 | Proxy TLS interception + audit-event structured context (v0.51.0) | 6 | `fork-preserve` | TLS interception + git CA trust + structured audit context — manual replay required (D-20; Windows credential-injection) |
| 12 | Env deny_vars + macOS learn diagnostics + nono learn deprecation (v0.52.0) | 10 | `will-sync` | Operator-controlled `deny_vars` + nono learn deprecation + macOS learn diagnostics |

### Cluster: PTY attach/detach + signal handling (introduced in v0.41.0)

- **Disposition:** won't-sync
- **Rationale:** Upstream changes touch `crates/nono-cli/src/pty_proxy.rs` (cross-platform PTY proxy used on Linux/macOS attach paths); the fork's Windows attach path lives in `pty_proxy_windows.rs` (D-11 excluded; ConPTY-based, structurally different from upstream's portable_pty primitives). The Unix-side scrollback/alt-screen behavior is consumed only by macOS attach in the fork (Linux is a POC); the fork's own Phase 17 live-stream attach work (v2.1) already satisfied the user-visible scrollback requirement on the supported Windows path. Cherry-picking would add Unix attach polish that does not flow into Windows ConPTY behavior. Per CONTEXT Specifics §5 ("upstream churn not relevant to fork").
- **Target phase:** — (n/a)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 2ac3409 | feat(pty): enhance detach notice and terminal cleanup | v0.41.0 | other | 1 |
| 95f2218 | fix(pty-proxy): ensure full scrollback on reattach for normal screen | v0.41.0 | other | 1 |
| d0fa303 | feat(pty): preserve outer terminal scrollback on attach | v0.41.0 | other | 1 |
| e3fdcb9 | fix(cli): improve attach/detach scrollback and alt-screen | v0.41.0 | other | 1 |
| e8c848f | Update crates/nono-cli/src/pty_proxy.rs | v0.41.0 | other | 1 |
| fef06f3 | feat(pty-proxy): scroll viewport to native scrollback on detach | v0.41.0 | other | 1 |
| be05217 | fix(signals): prevent signal swallowing | v0.41.0 | other | 1 |

### Cluster: Profile/policy CLI consolidation + denial diagnostics (introduced in v0.41.0)

- **Disposition:** will-sync
- **Rationale:** Upstream renames the `nono policy` subcommand tree under `nono profile` with deprecation aliases AND adds richer profile-save / denial-diagnostic UX. Both are user-facing CLI surface that fork users will see in upstream documentation; keeping the fork's CLI surface alignable with upstream docs is the same justification class as G-25-DRIFT-01 (user-facing CLI must match upstream). Carry the deprecation-alias pattern forward so existing fork users' `nono policy` invocations keep working through one release.
- **Target phase:** UPST3-sync (Phase 34)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 034be70 | feat(cli): improve denial diagnostics and profile saving workflow | v0.41.0 | other,profile | 12 |
| 37488ce | refactor(cli-startup-prompt): extract startup prompt functions | v0.41.0 | other | 3 |
| 5ff9bc3 | feat(cli): consolidate 'nono policy' subcommands under 'nono profile' with deprecation alias (#594) | v0.41.0 | other,profile | 7 |
| 77bbe42 | feat(cli): enhance prompts and denial diagnostics | v0.41.0 | other | 5 |
| 87758af | fix(cli): improve profile save resilience and policy suggestions | v0.41.0 | other | 2 |
| 073620e | chore: release v0.41.0 | v0.41.0 | other | 1 |

### Cluster: Unix socket capability + --allow-unix-socket (introduced in v0.42.0)

- **Disposition:** won't-sync
- **Rationale:** Upstream adds `UnixSocketCapability` + `UnixSocketMode` + `--allow-unix-socket` flag family + Linux seccomp `af_unix` plumbing. The capability shape is Unix-specific (Windows IPC uses Named Pipes — see Phase 18 AIPC pipe/socket brokering); adding a `UnixSocketCapability` to `crates/nono/` would expose an enum variant that no Windows backend can honor and would violate D-19 (no library mutation in this audit; a sync-time addition would need its own Windows-no-op handling decision). Fork users on Windows do not consume Unix sockets; macOS users get unsigned Unix-socket access today via the broader macOS Seatbelt allowlist — a typed capability is not a regression. Per CONTEXT Specifics §5.
- **Target phase:** — (n/a)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 85708ca | feat(cli): add --allow-unix-socket flag family + profile schema | v0.42.0 | other,profile | 9 |
| a9a8b6c | feat(capability): add UnixSocketCapability and UnixSocketMode | v0.42.0 | other | 3 |
| 1d789aa | fix(supervisor(linux)): allow pathname af_unix sockets in network seccomp | v0.42.0 | other | 3 |
| a87c6ae | chore: release v0.42.0 | v0.42.0 | other | 1 |

### Cluster: Proxy/network policy hardening (introduced in v0.42.0)

- **Disposition:** will-sync
- **Rationale:** Three behavioral fixes the fork should pick up: (a) `ad23d79` stops adding `--allow-domain` hosts to `NO_PROXY` without direct TCP grants — closes a silent-bypass hole that affects the fork's `nono-proxy` interception path identically; (b) `8c818f8` adds `--allow-connect-port` for outbound TCP port allowlisting — composes cleanly with fork's WFP port-level filtering (Phase 09) as a defense-in-depth proxy layer; (c) `cb6b199` switches package downloads to native TLS roots, important for headless/MSI-installed fork installs that may not have a system rustls trust bundle. The macOS fail-fast (`cba186f`) is a 1-line guard and rides along trivially.
- **Target phase:** UPST3-sync (Phase 34)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| ad23d79 | fix(proxy): stop adding allow_domain hosts to NO_PROXY without direct TCP grants | v0.42.0 | other,proxy | 4 |
| 8c818f8 | feat(cli): add --allow-connect-port for outbound TCP port allowlisting | v0.43.0 | other,profile | 3 |
| cba186f | fix(cli): fail fast on --allow-connect-port on macOS | v0.43.0 | other | 1 |
| cb6b199 | feat(packages): use native tls root certificates | v0.45.0 | other | 1 |

### Cluster: Headless keyring + display/quoting fixes (introduced in v0.43.0)

- **Disposition:** will-sync
- **Rationale:** Two clusters of fixes worth syncing: (a) `7b58c3e` + `f521591` make the `system-keyring` feature optional for headless/container builds — the fork's MSI-installed Windows path uses Windows Credential Manager (`keyring v3`), but a headless-Windows or service-account install scenario may want to disable the keyring feature for diagnostics; (b) `9147610` + `e21e27d` fix character-aware truncation and shell-quote command args in audit-display output — both fix display-side correctness in `crates/nono-cli/src/audit*` (categorized `audit` by drift tool) which the fork's Windows audit-show surface (Phase 23 REQ-AUD-05) consumes byte-identically. Style/release rows ride along.
- **Target phase:** UPST3-sync (Phase 34)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 7b58c3e | fix: set system-keyring as default feature for backward compatibility | v0.43.0 | other | 1 |
| f521591 | feat: make system keyring optional for headless/container builds | v0.43.0 | other | 3 |
| 1f912e5 | style: run cargo fmt | v0.43.0 | other | 1 |
| 30c0f76 | chore: release v0.43.0 | v0.43.0 | other | 1 |
| 9147610 | fix(cli): char-aware truncation in truncate_command | v0.43.1 | audit,other | 3 |
| e21e27d |   fix(cli): shell-quote command args in display output (#660) | v0.43.1 | audit,other | 7 |
| f405067 | chore: release v0.43.1 | v0.43.1 | other | 1 |
| d38fe64 | chore: release v0.45.0 | v0.45.0 | other | 1 |

### Cluster: Pack migration + claude-code/codex registry relocation (introduced in v0.44.0)

- **Disposition:** fork-preserve
- **Rationale:** Upstream `24d8b92` migrates `claude-code` and `codex` builtin profiles to a registry pack format. The fork's claude-code integration follows v2.1 Phase 18.1-03 wiring (G-06 profile widening end-to-end → AipcResolvedAllowlist via Windows SupervisorConfig field); a packs-from-registry migration would force a manual replay rather than a clean cherry-pick because the fork's Windows-specific wiring lives in code paths that the upstream pack-migration commit assumes do NOT exist (D-19 invariant — no library mutation; D-20 manual replay precedent — Phase 26 Plan 26-01 PKGS-02 chose the same fork-preserve disposition for analogous package-manager surface to protect the Windows hook installer wiring). The hook-prompt-removal `5654b0f` and install/uninstall hardening fixes need fork-side audit before any replay; until then, fork's claude-code path stays as shipped in v2.1 Phase 18.1-03.
- **Target phase:** — (n/a)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 24d8b92 | feat(profile, migration): move codex, claude-code to registry pack | v0.44.0 | other,package,policy,profile | 17 |
| 5654b0f | feat(claude): prompt to remove old builtin hooks | v0.44.0 | other,package,profile | 5 |
| a05fdc5 | refactor(wiring): simplify string expansion | v0.44.0 | other | 1 |
| bdf183e | fix(package): harden re-pulls against user edits | v0.44.0 | other,package | 4 |
| d05672d | fix(wiring): harden install and uninstall wiring | v0.44.0 | other,package | 4 |
| f1243c7 | chore(ci): improve ci stability and profile test coverage | v0.44.0 | other | 3 |

### Cluster: Path canonicalization + profile JSON schema restructure (introduced in v0.46.0)

- **Disposition:** will-sync
- **Rationale:** The largest cluster (23 commits across v0.46–v0.47.1). Three security-relevant items lead the cluster: (a) `e2d0054` re-validates deny overlaps after all grants — closes an order-of-operations hole that the fork's `policy.rs::never_grant` defense (v2.1 Phase 19) is the Windows-side analog for, but the upstream re-validation pattern strengthens the cross-platform path identically; (b) `bb3f512` + `69c55f4` + `dbc10da` + `ee70922` + `be384ee` unify path canonicalization with an ancestor-walk fallback and platform-specific dedup keys — directly relevant to fork's Windows long-path / UNC handling (the fork already canonicalizes via `dunce` on Windows but the new fallback shape composes cleanly); (c) `f0abd41` is the canonical JSON schema restructure for profiles — fork's schema regenerator (`scripts/regenerate-schema.sh`) and embedded `data/profile-authoring-guide.md` need to track upstream's canonical form for the Phase 24 drift-tool `profile` category to remain meaningful. `829c341` (draft commands) + extends/drafts fixes round out a coherent profile-tooling release-pair.
- **Target phase:** UPST3-sync (Phase 34)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 1f47b3c | fix: Update examples in setup.rs | v0.46.0 | other | 1 |
| 96bd783 | test: exclude system_write_linux in post-CWD overlap regression test | v0.46.0 | other | 1 |
| d49585b | chore: release v0.46.0 | v0.46.0 | other | 1 |
| e2d0054 | fix(cli): re-validate deny overlaps after all grants | v0.46.0 | other,policy,profile | 5 |
| efbfa49 | feat(network): support GitLab developer domains | v0.46.0 | other | 1 |
| 167b4ea | fix: doc changes + relax strict cap check | v0.47.0 | policy | 1 |
| 1c89346 | style: run cargo fmt | v0.47.0 | other | 1 |
| 20e2286 | Add macOS warning when --allow targets a deny-group path On macOS, Seatbelt deny rules silently override earlier allow rules, so --allow on a path like ~/.gnupg has no effect when deny_credentials is active. Detect this overlap in finalize_caps and warn the user to use --override-deny. | v0.47.0 | other,policy | 2 |
| 26e80ed | fix: replace unwrap() with expect() in path tests for clippy | v0.47.0 | other | 1 |
| 3f11772 | style: remove extra blank line in diagnostic.rs | v0.47.0 | other | 1 |
| 69c55f4 | fix: migrate diagnostic.rs to shared try_canonicalize helper | v0.47.0 | other | 1 |
| 7a01e32 | chore: release v0.47.0 | v0.47.0 | other | 1 |
| bb3f512 | fix: unify path canonicalization with ancestor-walk fallback | v0.47.0 | other | 8 |
| bc44392 | fix: resolve extends against sibling profiles in the same directory | v0.47.0 | profile | 1 |
| be384ee | perf: eliminate redundant canonicalize syscalls per review feedback | v0.47.0 | other | 3 |
| dbc10da | fix(capability): platform-specific dedup key (original on macOS, resolved on Linux) | v0.47.0 | other | 1 |
| ee70922 | fix: canonicalize protected roots at call sites to handle raw paths | v0.47.0 | other | 1 |
| f0abd41 | feat(profile): #594 phase 2 â€” canonical JSON schema restructure (#594) | v0.47.0 | other,policy,profile | 23 |
| f3e7f88 | fix(profile): emit serde-rendered values in show/diff JSON output | v0.47.0 | other | 1 |
| 0cba04a | chore: release v0.47.1 | v0.47.1 | other | 1 |
| 7329ef7 | chore(deps): bump jsonschema from 0.45.1 to 0.46.4 | v0.47.1 | other | 1 |
| 829c341 | add commands to manage profile drafts and check package status | v0.47.1 | other,package,profile | 9 |
| ab74f5c | docs: fix stale references, deprecation wording, and built-in vs pack distinction | v0.47.1 | other | 2 |

### Cluster: Shell completion + string-truncation refactor (introduced in v0.48.0)

- **Disposition:** will-sync
- **Rationale:** `03546d6` adds `nono completion <shell>` — clap-driven CLI completion generation. Worth syncing for fork users who install `nono` via MSI on Windows (powershell completion) and via Homebrew on macOS (bash/zsh completion). The truncation panic fix (`4b35354`) and string-truncation utility refactor (`7b71855`) close real bugs in the cross-platform display path that the fork's `nono audit show` consumes. `e4e73e1` (skip self-references in sibling extends resolution) is a defensive fix in the same `profile/mod.rs` cluster as the v0.47 schema restructure; bundle with the parent cluster on cherry-pick. `f2592a2` log-level demote rides along.
- **Target phase:** UPST3-sync (Phase 34)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 03546d6 | feat(cli): add shell completion generation via `nono completion <shell>` | v0.48.0 | other | 6 |
| 30245db | cleanup unused code | v0.48.0 | other | 1 |
| 4b35354 | fix(cli): prevent truncate_chars panic and spurious truncation | v0.48.0 | other | 1 |
| 777dd95 | chore: reduce nono run output verbosity | v0.48.0 | other | 3 |
| 7b71855 | refactor(string-truncation): extract generic string truncation utility | v0.48.0 | other | 2 |
| e15b9c4 | chore: release v0.48.0 | v0.48.0 | other | 1 |
| e4e73e1 | fix(profile): skip self-references in sibling extends resolution | v0.48.0 | profile | 1 |
| f2592a2 | fix: demote --allow-launch-services log from warn to debug | v0.48.0 | other | 1 |

### Cluster: Trust scan path-traversal hardening + YAML merge directive (introduced in v0.49.0)

- **Disposition:** will-sync
- **Rationale:** Two security fixes in the trust subsystem worth syncing: `cd4fd98` rejects symlink-escape in multi-subject bundle subject names and `fdef133` rejects path-traversal in the same — both close real validation gaps in `crates/nono/src/trust/scan.rs` (cross-platform; the fork's Sigstore TUF cached-root work in Phase 32 consumes this trust subsystem). `4f8c332` (`treat empty parent() as CWD when deriving scan_root`) is a Windows-relevant fix — Windows path semantics differ from POSIX for empty-parent cases. `d44f554` adds `yaml_merge` wiring directive — useful for fork users patching upstream profiles via YAML overlay. `242d491` pins `serde_yaml_ng` 0.10.0 — a guard against the serde_yaml deprecation that the fork should also pin.
- **Target phase:** UPST3-sync (Phase 34)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 242d491 | fix(yaml-merge): pin serde_yaml_ng to 0.10.0 and add reversal failure test | v0.49.0 | other | 1 |
| 4f8c332 | fix(trust): treat empty parent() as CWD when deriving scan_root | v0.49.0 | other | 1 |
| 587d98d | chore: release v0.49.0 | v0.49.0 | other | 1 |
| 802c856 | style: apply rustfmt | v0.49.0 | other | 1 |
| cd4fd98 | fix(trust): reject symlink-escape in multi-subject bundle subject names | v0.49.0 | other | 1 |
| ce3230d | style: apply rustfmt to trust_cmd and trust_scan | v0.49.0 | other | 2 |
| d44f554 | feat(wiring): add yaml_merge directive for YAML config patching | v0.49.0 | other | 1 |
| fdef133 | fix(trust): reject path traversal in multi-subject bundle subject names | v0.49.0 | other | 2 |

### Cluster: CLI ps display + env:// credentials + ioctl native types (introduced in v0.50.0)

- **Disposition:** will-sync
- **Rationale:** `ca2e948` adds `env://` URI support in `custom_credentials.credential_key` — composes with the fork's existing `keystore` `env://` support (`crates/nono/src/keystore.rs`) so this is a natural surface extension that keeps fork and upstream credential-loading shape aligned. `a9eeb3f` + `7547f91` improve `nono ps` column display — cosmetic but the fork's `nono ps` is the Windows session-listing surface (Phase 02-04 era), so visual parity matters. `4e642f2` (`Use native types for ioctl integers`) is a Linux-only fix (`crates/nono-cli/src/exec_strategy/linux.rs` ioctl invocation) — fork's Linux POC inherits it. `0b29d8b` (restore comment) + release rows ride along.
- **Target phase:** UPST3-sync (Phase 34)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 0b29d8b | restore comment | v0.50.0 | profile | 1 |
| 7547f91 | refactor(cli): optimize ps command column width calculation | v0.50.0 | other | 1 |
| a9eeb3f | refactor(cli/ps): improve ps command display with dynamic columns | v0.50.0 | other | 1 |
| ca2e948 | feat(profile): support env:// URI in custom_credentials credential_key | v0.50.0 | other,profile | 2 |
| cd74c4c | chore: release v0.50.0 | v0.50.0 | other | 1 |
| 2d183e8 | chore: release v0.50.1 | v0.50.1 | other | 1 |
| 4e642f2 | fix: Use native types for iotcl integers | v0.50.1 | other | 1 |

### Cluster: Proxy TLS interception + audit-event structured context (introduced in v0.51.0)

- **Disposition:** fork-preserve
- **Rationale:** Upstream `149abde` + `879562c` + `8db8919` + `dcf2d29` add deep TLS interception (`tls_intercept`) for L7-bearing CONNECT routes, plus extend CA trust to git clients. Cherry-picking would merge a 21-file proxy-side change into `crates/nono-proxy/` — but the fork's `nono-proxy` interception path was rewritten on `windows-squash` for Windows credential injection (Phase 09 + Phase 11) and the upstream tls-interception pattern assumes a UNIX socket trust-store layout that the fork's Windows credential-store path does not match. Manual replay is the right shape (D-20 pattern from Phase 26 Plan 26-01 PKGS-02 — cherry-pick would delete fork-only Windows credential-injection code). Audit-event structured context (`9300de9`) — fork-preserve as a bundle with the proxy work (REQ-AUD-05 already shipped richer Windows AIPC ledger emissions in Phase 23 / commit `263795a9`).
- **Target phase:** — (n/a)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 149abde | feat(proxy): add tls interception for l7-bearing connect routes | v0.51.0 | audit,other,proxy | 21 |
| 879562c | feat(proxy): enhance audit context for managed auth and harden tls ca dir | v0.51.0 | other,proxy | 5 |
| 8db8919 | feat(proxy): extend ca trust to git clients | v0.51.0 | proxy | 1 |
| 9300de9 | feat(audit): add structured context to network audit events | v0.51.0 | audit,other,proxy | 12 |
| da60dae | chore: release v0.51.0 | v0.51.0 | other | 1 |
| dcf2d29 | fix(tls_intercept): add authority key identifier to leaf certs | v0.51.0 | proxy | 1 |

### Cluster: Env deny_vars + macOS learn diagnostics + nono learn deprecation (introduced in v0.52.0)

- **Disposition:** will-sync
- **Rationale:** Three sync-worthy items: (a) `3657c93` + `780965d` + `a022e5c` add operator-controlled `deny_vars` to `EnvironmentConfig` and preserve fail-closed semantics for empty `allow_vars` — both are correctness/security fixes the fork's env-sanitization pipeline (`crates/nono-cli/src/exec_strategy/env_sanitization.rs`, ported via Phase 20 UPST-03) should track to maintain parity with upstream's environment-policy contract; (b) `b34c2af` deprecates `nono learn` in favor of profile-authoring workflow — the fork's `learn_windows.rs` is D-11 excluded, but the deprecation message + cli surface change is cross-platform, so the deprecation needs to flow through; (c) `b5f0a3a` + `bbdf7b8` + `f782ddc` enhance macOS learn / interactive diagnostics — affects macOS surface only, but rides along with the cluster. Style/release/lint rows (`1d491b4`, `31f2fc2`, `5d15b50`) ride along.

**Audit finding (CRITICAL — contradicts G-25-DRIFT-01 hypothesis):** The audit walk surfaces ZERO commits matching RESL flag rename keywords (`memory`, `cpu-percent`, `max-processes`, `mem-limit`, `RESL`) in v0.40.1..v0.52.0. The G-25-DRIFT-01 claim (`'--memory' flag deprecated/renamed in upstream nono v0.52`) is empirically false against this audit's source-of-truth (`upstream/main` HEAD `54f7c32a` at `2026-05-11`). The 4 RESL flag names are STILL `--memory` / `--cpu-percent` / `--max-processes` / `--timeout` in upstream as of v0.52.0. Wave 2's ADR + REQ-4 G-25-DRIFT-01 update must record this finding and re-classify the gap (the fork's RESL surface is NOT diverged from upstream — it was a speculative hypothesis at Phase 25 HUMAN-UAT time).
- **Target phase:** UPST3-sync (Phase 34)

| sha | subject | upstream-tag | categories | files-changed |
|-----|---------|--------------|------------|---------------|
| 1d491b4 | style: run cargo fmt | v0.52.0 | other,profile | 2 |
| 31f2fc2 | fix(lint): replace unwrap() with is_some_and() in test | v0.52.0 | other | 1 |
| 3657c93 | feat(env): add operator-controlled deny_vars to EnvironmentConfig | v0.52.0 | other,profile | 9 |
| 5d15b50 | chore: release v0.52.0 | v0.52.0 | other | 1 |
| 780965d | fix(env): preserve fail-closed semantics for empty allow_vars | v0.52.0 | other | 1 |
| a022e5c | refactor(env): extract matches_env_var_patterns helper, fix docs wording | v0.52.0 | other | 1 |
| b34c2af | feat(cli): deprecate 'nono learn' and improve diagnostics | v0.52.0 | other | 3 |
| b5f0a3a | feat(cli): enhance macos learn and run diagnostics | v0.52.0 | other | 9 |
| bbdf7b8 | fix(diagnostic): parse escaped quotes in structured properties | v0.52.0 | other | 2 |
| f782ddc | feat(cli): enhance interactive experience and profile saving | v0.52.0 | other | 8 |

## Fork-only surface area

Surface added since v0.40.1 with NO upstream analog. The drift tool's D-11 filter (`*_windows.rs` + `crates/nono-cli/src/exec_strategy_windows/` excluded) hides ALL of this from the audit walk; this section is the manual enumeration mandated by D-33-A3. The Wave 2 strategic ADR (`docs/architecture/upstream-parity-strategy.md`) quotes this enumeration as evidence supporting the security-posture column for the "continue parity" option.

### Crate-level surface

- `crates/nono-shell-broker/` — Phase 31 Low-IL broker process (Windows-only by design; landed in `Cargo.toml` workspace `members` array as of audit time).

### Seam-level surface

- **Phase 27.1 `NONO_TEST_HOME` seam** — `crates/nono-cli/src/cli_bootstrap.rs` (cross-platform conditional but introduced post-v0.40 with no upstream analog).
- **Phase 28 Authenticode chain-walker** — `parse_signer_subject` + `parse_thumbprint` helpers within `crates/nono-cli/src/exec_strategy_windows/` (D-11 excluded).
- **Phase 31 broker dispatch** — `WindowsTokenArm::BrokerLaunch` arm in `crates/nono-cli/src/exec_strategy_windows/launch.rs` ~L1246-1438 (D-11 excluded).
- **Phase 32 Sigstore TUF cached-root** — `crates/nono/src/trust/bundle.rs::load_production_trusted_root` (cross-platform per D-32-15 but introduced post-v0.40 with no upstream analog).
- **Phase 32 broker self-trust-anchor** — verify gate at `crates/nono-cli/src/exec_strategy_windows/launch.rs` ~L1246+ (Windows-only; D-11 excluded).

### `*_windows.rs` files (D-11 excluded by construction)

Verified via `git ls-files | grep -E '_windows\.rs$'` at audit time:

- `crates/nono-cli/src/exec_identity_windows.rs`
- `crates/nono-cli/src/learn_windows.rs`
- `crates/nono-cli/src/open_url_runtime_windows.rs`
- `crates/nono-cli/src/pty_proxy_windows.rs`
- `crates/nono-cli/src/session_commands_windows.rs`
- `crates/nono-cli/src/trust_intercept_windows.rs`
- `crates/nono-cli/tests/exec_identity_windows.rs` (Windows-only test)
- `crates/nono/src/supervisor/socket_windows.rs`

Plus the entire `crates/nono-cli/src/exec_strategy_windows/` subtree (D-11 path filter excludes the directory by glob).

### NOT in workspace (correction to CONTEXT D-33-A3 wording)

- `crates/nono-wfp-service/` — per RESEARCH §"Verification gap" + `Cargo.toml` `[workspace] members` list, this is NOT a crate in the workspace as of audit time. CONTEXT.md D-33-A3 listed it; the planner verified against `Cargo.toml` and the planner-noted absence is confirmed by this audit. WFP service surface lives in `crates/nono-cli/src/` `*_windows.rs` files (already covered above).
