## Plan 43-05 — Cluster 5 platform-conditional profile fields foundation

**Cluster:** 5 (Platform-conditional profile fields — single upstream commit `ce06bd59` introducing `crates/nono-cli/src/platform.rs` + WhenPredicate deserialization)
**Disposition:** `resolved_disposition: fork-preserve` (D-20 manual replay) — Task 1 D-43-C1 diff-inspection verdict; both D-40-B1 clauses (a) zero-conflicts and (b) identical-surface-semantics FAILED at the trial cherry-pick gate (7 conflicts; fork lacks `pub struct GroupsConfig` target struct)
**Upstream commits:** `ce06bd59 feat(profile): add platform-conditional profile fields` (v0.54.0)
**Files touched:**
- `crates/nono-cli/src/platform.rs` (NEW, 659 lines — full upstream module replayed verbatim because the predicate grammar is closed and security-relevant)
- `crates/nono-cli/src/profile/mod.rs` (+217 lines: 4 helper deserialize functions + `deserialize_with` attributes on 9 `FilesystemConfig` path fields + 1 `OpenUrlConfig::allow_origins` field + manual `SecretsConfig` Deserialize impl with conditional object form + 1 integration test)
- `crates/nono-cli/src/main.rs` (`mod platform;` declaration)
- `crates/nono-cli/data/nono-profile.schema.json` (+99 lines: `WhenPredicate` / `ConditionalPath` / `ConditionalName` / `ConditionalOrigin` `$defs` + reference updates on `FilesystemConfig` / `SecretsConfig` / `OpenUrlConfig`)

**Key decisions:**
- D-43-C1 diff-inspection authority applied — Task 1 trial cherry-pick + Q1-Q8 surface-overlap analysis produced canonical `resolved_disposition: fork-preserve` verdict. Both clauses of the D-40-B1 upgrade rule failed (clause a: 7 conflicts at trial; clause b: fork has no `GroupsConfig` struct).
- Phase 36-01b `From<ProfileDeserialize> for Profile` exhaustive enumeration at lines 1893+ preserved AUTOMATICALLY — Cluster 5 adds NO new top-level `Profile` field; conditional logic is wired INSIDE field-level deserializers + a new manual `SecretsConfig` Deserialize impl.
- Phase 36-01c `bypass_protection` canonical name honored — already what upstream references in this commit; the new `deserialize_with` attribute is merged into the same serde block as the existing `alias = "override_deny"`.
- Path-component comparison invariant preserved per CLAUDE.md § Common Footguns #1 — Q7 verified `platform.rs` has zero path-string `.starts_with` calls (only char-literal compares for `/etc/os-release` parse and version comparator detection).
- **W-4 fix mitigation:** `wiring.rs` SKIPped (no callers in fork; +126 lines would be dead code). Directive-level `when:` predicates are rejected fail-secure by fork's existing `#[serde(deny_unknown_fields)]` on `WiringDirective` enum variants — no silent JSON-schema-vs-Rust-deserialization divergence. Field-level `when:` (the load-bearing surface) IS fully consumed by the replayed `deserialize_conditional_*_vec` helpers.
- **Rust 1.95 lint Rule-3 deviation:** `clippy::unnecessary_map_or` surfaced at `platform.rs:232` in Gate 2; mechanical `when.map_or(true, ...)` → `when.is_none_or(...)` rewrite landed as separate `fix(43-05-cra):` commit `d4285ead` (mirrors Plan 43-01b DEC-4 precedent for `clippy::manual_is_multiple_of`).
- D-43-E1 invariant honored — 0 touches to fork-only Windows files (`*_windows.rs`, `exec_strategy_windows/`, `crates/nono-shell-broker/`) across all 3 plan commits.

**Plan commit chain (3 commits):**
- `22df643d` `docs(43-05): record D-43-C1 diff-inspection verdict for cluster 5` (DCO sign-off; no D-19 trailer)
- `fe04e887` `feat(43-05): replay platform.rs + when-predicate deserialization (cluster 5)` (5-section D-20 body; `Upstream-replayed-from: ce06bd59`; Co-Authored-By; DCO sign-off; ZERO `Upstream-commit:` trailer)
- `d4285ead` `fix(43-05-cra): adopt is_none_or() for rust-1.95 clippy lint compliance` (DCO sign-off)

**CI baseline diff:** Wave 2a head against baseline `13cc0628`. Local Windows-host evidence shows zero `success → failure` lane transition vectors; post-merge CI gate filled in by orchestrator. Cross-target Linux + macOS clippy lanes deferred to live CI per `cross-target-verify-checklist.md § PARTIAL Disposition` (load-bearing because `platform.rs` contains cfg-gated Linux + macOS branches; CI lanes substitute for missing cross-toolchain on Windows host).
