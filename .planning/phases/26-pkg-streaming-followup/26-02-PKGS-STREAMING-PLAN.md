---
phase: 26-pkg-streaming-followup
plan: 02
type: execute
wave: 2
depends_on: ["26-01"]
blocks: []
files_modified:
  - crates/nono-cli/Cargo.toml                         # ADD: semver dep. (tempfile = "3" already at line 73 — no promotion needed; verified in pre-read.)
  - crates/nono-cli/src/package.rs                     # DownloadedArtifact: bytes: Vec<u8> → staged_path: PathBuf; ADD bundle_json: String field (PKGS-01 coupling).
  - crates/nono-cli/src/package_cmd.rs                 # bytes→PathBuf streaming refactor + size limits + bundle_json field threading (was local var at L425).
  - crates/nono-cli/src/registry_client.rs             # ureq Agent timeouts (connect + read); streaming download_to_path<W: Write> sink. NOTE: fork uses ureq 3, NOT hyper (CONTEXT correction).
  - crates/nono-cli/src/cli.rs                         # ADD: nono package pull --max-size <bytes> flag.
  - crates/nono-cli/src/profile/mod.rs                 # load_registry_profile auto-pull on extends chain (PKGS-04, upstream `115b5cfa`).
  - crates/nono-cli/tests/package_streaming_integration.rs (NEW)  # mockito-backed streaming + auto-pull integration tests.
autonomous: true
requirements: ["PKGS-01", "PKGS-04"]
tags: [pkg, streaming, semver, tempfile, registry-auto-pull, cherry-pick, host-preferred]
tdd: false
risk: medium
host_preference: linux-or-macos
host_blocker: |
  `dirs::home_dir()` ignores `USERPROFILE` on Windows; auto-pull e2e tests via `run_nono`
  harness hit this blocker. Workaround: `NONO_TEST_HOME` production-code seam (v2.4
  candidate phase: "Windows test-harness HOME redirection"). Plan can be authored on
  Windows; execution is queued for Linux/macOS host (or after the v2.4 seam lands).

must_haves:
  truths:
    - "`nono pull <large-artifact>` of 200MB succeeds via streaming; memory profile peaks at ~10MB (not 200MB). Verified by integration test using `mockito` to stream 200MB of zero bytes; assert process RSS via `/proc/self/status` (Linux) stays under 50MB during the download. Test gated `#[cfg(target_os = \"linux\")]`."
    - "Tampered artifact (bytes corrupted mid-stream) is rejected before install_dir placement. Verified by integration test with `mockito` returning bytes whose SHA-256 does not match the manifest's `sha256_digest`."
    - "Artifact larger than `--max-size` cap is rejected mid-stream with `NonoError::ArtifactTooLarge { actual, max }`. Default cap is 500MB; configurable via `nono package pull --max-size <bytes>` flag."
    - "HTTP connect timeout fires with clear error after configured threshold (default 10s). Verified by integration test pointing at a TCP port where nothing listens (e.g. 127.0.0.1:1)."
    - "HTTP idle/read timeout fires after configured threshold (default 60s mid-stream). Verified by integration test where mock server stops sending bytes mid-response (mockito `delay`)."
    - "Profile with `extends: [\"registry://vendor/pack@1.2.3\"]` and pack absent locally triggers auto-pull, completes resolve. Verified by e2e test using mock registry."
    - "Profile resolve with no network access (and pack absent) fails with clear error pointing at the missing pack. Verified by e2e test with simulated network failure (mockito server NOT started; URL points at 127.0.0.1:1)."
    - "Auto-pull respects `--max-size` cap from PKGS-01. Verified by e2e test that triggers auto-pull of a >cap artifact and asserts `NonoError::ArtifactTooLarge`."
    - "`semver` crate added to `crates/nono-cli/Cargo.toml`; version comparison in registry queries uses `semver::VersionReq::matches`. Verified by `grep -c '^semver' crates/nono-cli/Cargo.toml` returning 1."
    - "`tempfile::TempDir` used for staging during streaming; cleaned up unconditionally on Drop (success OR panic). Verified by `grep -nE 'TempDir::new|tempfile::TempDir' crates/nono-cli/src/package_cmd.rs` returning ≥ 1 hit + integration test that injects a panic mid-stream and asserts the tempdir is gone."
    - "`bundle_json` is now a FIELD on `DownloadedArtifact` (struct), not a local variable. Verified by `grep -c 'pub bundle_json' crates/nono-cli/src/package.rs` returning 1, AND `grep -c 'let bundle_json' crates/nono-cli/src/package_cmd.rs` returning 0."
    - "`make ci` passes: cargo clippy + fmt + cargo test --workspace clean (on Linux/macOS host; Windows execution has the `dirs::home_dir()` blocker per v2.4 backlog)."
    - "D-19 byte-identical preservation: `git diff --stat <baseline>..HEAD -- crates/nono/` returns empty across all plan commits."
  artifacts:
    - path: "crates/nono-cli/src/package.rs"
      provides: "DownloadedArtifact struct with `staged_path: PathBuf` (was `bytes: Vec<u8>`) + new `pub bundle_json: String` field (PKGS-01 coupling)"
    - path: "crates/nono-cli/src/package_cmd.rs"
      provides: "Streaming download_and_verify_artifacts() — writes to TempDir-staged PathBuf, computes SHA-256 incrementally, enforces --max-size mid-stream"
    - path: "crates/nono-cli/src/registry_client.rs"
      provides: "ureq Agent with connect_timeout(10s) + read_timeout(60s); streaming download_to_writer<W: Write>(&self, url: &str, sink: W, max_bytes: u64) -> Result<u64>"
    - path: "crates/nono-cli/src/cli.rs"
      provides: "PackagePullArgs::max_size: Option<u64> flag (default 500MB applied at handler level)"
    - path: "crates/nono-cli/src/profile/mod.rs"
      provides: "load_registry_profile() — when extends chain references registry://vendor/pack@version, auto-pulls via package_cmd::pull idempotently before resolving the extension"
    - path: "crates/nono-cli/tests/package_streaming_integration.rs"
      provides: "7 integration tests covering streaming, size limits, timeouts, tamper rejection, auto-pull happy/sad paths, panic-safe tempdir cleanup"
  key_links:
    - from: "REQUIREMENTS.md § REQ-PKGS-01 acceptance #1 (200MB streams at ~10MB peak RSS)"
      to: "crates/nono-cli/src/package_cmd.rs::download_and_verify_artifacts streaming loop"
      via: "ureq response.into_reader() + io::copy into tempfile-staged PathBuf with size cap"
      pattern: "TempDir|staged_path|max_size|ArtifactTooLarge"
    - from: "REQUIREMENTS.md § REQ-PKGS-04 acceptance #1 (registry://vendor/pack@version triggers auto-pull)"
      to: "crates/nono-cli/src/profile/mod.rs::load_registry_profile"
      via: "Profile::resolve detects registry:// scheme in extends, calls package_cmd::pull idempotently"
      pattern: "load_registry_profile|registry://|extends.*pack"
    - from: "Phase 26 Plan 26-01 prerequisite closure (ArtifactType::Plugin variant)"
      to: "Streaming refactor's per-variant install dispatch"
      via: "match artifact_type { Profile, Plugin, ... } AFTER 26-01 lands the Plugin variant"
      pattern: "ArtifactType::Plugin"
---

<objective>
Land upstream `9ebad89a refactor(pkg): stream package artifact downloads` (REQ-PKGS-01) and `115b5cfa feat(profile): load profiles from registry packs` (REQ-PKGS-04) into the fork. PKGS-01 replaces the buffered `client.download_bytes() -> Vec<u8>` pattern at `package_cmd.rs:457` with a streaming sink that writes directly to a `tempfile::TempDir`-staged `PathBuf`, enforces a configurable size cap mid-stream, and adds connect + read timeouts to the `ureq` HTTP client. Coupled in the same plan: the `DownloadedArtifact` struct gains a `bundle_json: String` field (currently a LOCAL variable at `package_cmd.rs:425`) so the verified bundle metadata can ride alongside the streamed `PathBuf`. PKGS-04 adds `load_registry_profile` auto-pull semantics: when a profile's `extends` chain references `registry://vendor/pack@version` and the pack is absent locally, `Profile::resolve` auto-pulls idempotently via `package_cmd::pull` before resolving the extension.

Plan 26-01 (PKGS-02 + PKGS-03 fork-arch — `validate_relative_path` belt-and-suspenders + `ArtifactType::Plugin` variant) is the **prerequisite**; Plan 26-02 cannot start cherry-picking until 26-01 closes because the streaming code dispatches per-variant (Plugin among them).

Purpose: A user runs `nono package pull <large-artifact>` against a 200MB registry pack and the process peaks at ~10MB RSS (not 200MB) — the streaming sink writes bytes to a `TempDir`-staged path, computes SHA-256 incrementally, and enforces the size cap before any byte is committed to install_dir. A profile that `extends: ["registry://vendor/pack@1.2.3"]` resolves cleanly even on a fresh machine — the auto-pull step transparently fetches the pack via the same hardened streaming + verification pipeline.

Output: 8 atomic commits on `main` (2 cherry-pick + 6 fork-only: semver dep, struct field, timeouts, CLI flag, integration tests, verification gate). Cross-platform code path; Windows execution queued behind `NONO_TEST_HOME` v2.4 seam per `host_blocker`.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@.planning/REQUIREMENTS.md
@.planning/phases/26-pkg-streaming-followup/26-CONTEXT.md
@.planning/phases/26-pkg-streaming-followup/26-RESEARCH.md
@.planning/phases/26-pkg-streaming-followup/26-01-PLAN.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-03-PKG-PLAN.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-03-PKG-SUMMARY.md
@crates/nono-cli/src/package.rs
@crates/nono-cli/src/package_cmd.rs
@crates/nono-cli/src/registry_client.rs
@crates/nono-cli/src/cli.rs
@crates/nono-cli/src/profile/mod.rs
@crates/nono-cli/Cargo.toml

<interfaces>
**Pre-resolved facts (CONTEXT pre-reads, do NOT re-investigate):**

| Fact | Source | Value |
|------|--------|-------|
| HTTP client is `ureq 3`, NOT hyper | `Cargo.toml:63` + `registry_client.rs:11` | Plan uses `ureq::Agent` config (`AgentBuilder::new().timeout_connect(...).timeout_read(...)`), NOT `hyper::client::Builder`. Prompt's "hyper" reference is incorrect for this fork. |
| `tempfile = "3"` already a runtime dep | `Cargo.toml:73` | NO promotion-from-dev needed (prompt assumption was wrong). Confirmed by pre-read. |
| `semver` absent | `Cargo.toml` grep | Task 2 ADDS it as a runtime dep. |
| `DownloadedArtifact` struct exists at `package.rs:~188` | grep | Has `pub filename: String`. Currently has `bytes: Vec<u8>`; refactor changes to `staged_path: PathBuf` + ADDs `pub bundle_json: String`. |
| `bundle_json` is a LOCAL var at `package_cmd.rs:425` | grep + read | `let bundle_json = client.download_text(&pull.bundle_url)?;` — must become a field on `DownloadedArtifact` per CONTEXT decision. |
| Buffered download site: `package_cmd.rs:457` | read | `let bytes = client.download_bytes(&artifact.download_url)?;` — replaced with streaming sink. |
| Construction site: `package_cmd.rs:481` | read | `downloads.push(DownloadedArtifact { filename, bytes, sha256_digest, signer_identity })` — must move to `staged_path` + thread `bundle_json`. |
| `client.download_text(...)` for bundle JSON at L425 | read | KEEP buffered (bundle JSON is small; only ARTIFACT bytes need streaming). |
| Plan 26-01 prerequisite: `ArtifactType::Plugin` variant | depends_on | Streaming dispatch needs the variant; if 26-01 hasn't shipped, this plan stalls. |

**Upstream cherry-pick chain (chronological per D-03):**

| Order | SHA | Upstream subject | REQ | LOC delta |
|-------|-----|------------------|-----|-----------|
| 1 | `9ebad89a` | refactor(pkg): stream package artifact downloads | PKGS-01 | ~+267/-109 across 5 files |
| 2 | `115b5cfa` | feat(profile): load profiles from registry packs | PKGS-04 | smaller; touches `profile/mod.rs` |

**D-02 fallback gate:** Both upstream SHAs are HIGH probability for D-20 manual-replay because Phase 22 Plan 22-03 forked `package_cmd.rs` heavily (the buffered `download_bytes()` site at L457 is fork-divergent from upstream's pre-9ebad89a state) and Phase 22 Plan 22-01 forked `profile/mod.rs` for PROF-02 PackRef. Budget: 30-50% of plan execution time may be conflict resolution.

**D-19 commit body template (cherry-pick path):**
```
refactor(26-02): stream package artifact downloads (PKGS-01)

<2-3 line context: what changed, why fork-relevant>

Upstream-commit: 9ebad89a
Upstream-tag: v0.39.x  # or git describe --tags 9ebad89a
Upstream-author: <capture from `git log -1 9ebad89a --format='%an <%ae>'`>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
```

**D-20 commit body template (manual-port fallback):**
```
refactor(26-02): stream package artifact downloads (PKGS-01)

<2-4 line context: what changed, why manual replay was needed,
 how the fork's divergent surface was preserved>

Upstream-commit: 9ebad89a (replayed manually)
Upstream-tag: v0.39.x
Upstream-author: <capture from `git log -1 9ebad89a --format='%an <%ae>'`>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
```

**Pattern map analogs:**
- ureq Agent timeout configuration: existing fork pattern in `nono-proxy/src/server.rs` (verify before adopting).
- `tempfile::TempDir` Drop semantics: existing fork uses `tempfile` in `crates/nono-cli/tests/*` and `crates/nono/src/undo/*`. Pattern: bind to a local variable, pass `.path()` references; Drop on scope-exit cleans up unconditionally.
- mockito for HTTP fixtures: NEW dev-dep (verify if `mockito` or `wiremock` is the workspace convention; default to `mockito` per crates.io ergonomics). If neither present, ADD `mockito` to `[dev-dependencies]` in `crates/nono-cli/Cargo.toml`.
- `dirs::home_dir()` Windows blocker: documented in v2.4 backlog. Plan execution is host-preferred Linux/macOS per `host_preference` field.

**RSS measurement portability:**
- Linux: read `/proc/self/status` field `VmRSS:`. Gate the test `#[cfg(target_os = "linux")]`.
- macOS: would need `task_info` Mach API or a portable proxy. **Decision:** gate the explicit RSS test Linux-only; on macOS rely on the `--max-size` cap test as a portable proxy for the streaming property (artifacts > cap reject mid-stream BEFORE the full buffer materializes — implicit RSS bound).
- Windows: deferred per host_blocker.

**Coordination caveat:** Plan 26-01 (Wave 1) MUST close before Plan 26-02 (Wave 2) starts. depends_on: ["26-01"] is enforced.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — confirm 26-01 closure + verify pre-resolved facts</name>
  <files>(read-only audit — no files modified)</files>
  <read_first>
    - `.planning/phases/26-pkg-streaming-followup/26-01-SUMMARY.md` (must exist; 26-01 must be CLOSED)
    - `crates/nono-cli/src/package.rs` (verify `ArtifactType::Plugin` variant present from 26-01)
    - `crates/nono-cli/Cargo.toml` (re-verify ureq=3, tempfile=3 present, semver absent)
  </read_first>
  <action>
    1. Confirm Plan 26-01 closure. If `26-01-SUMMARY.md` does NOT exist OR records non-closed status: STOP. Plan 26-02 has a hard prerequisite on 26-01.
       ```
       test -f .planning/phases/26-pkg-streaming-followup/26-01-SUMMARY.md
       grep -E 'Status:.*Complete|closed' .planning/phases/26-pkg-streaming-followup/26-01-SUMMARY.md
       ```

    2. Confirm `ArtifactType::Plugin` variant exists post-26-01:
       ```
       grep -nE 'enum ArtifactType|Plugin' crates/nono-cli/src/package.rs
       ```
       Must show `Plugin` as a variant. If absent: 26-01 did not deliver PKGS-03; STOP.

    3. Re-verify Cargo.toml shape:
       ```
       grep -nE '^(ureq|tempfile|semver|mockito)' crates/nono-cli/Cargo.toml
       awk '/^\[dev-dependencies\]/,/^\[/' crates/nono-cli/Cargo.toml | grep -E '^(mockito|wiremock|tempfile)'
       ```
       Expected pre-state: `ureq = "3"`, `tempfile = "3"` present (runtime); `semver` absent; `mockito` likely absent (will add as dev-dep in Task 6).

    4. Inventory the 3 critical sites:
       ```
       grep -n 'let bundle_json = client.download_text' crates/nono-cli/src/package_cmd.rs   # L425 expected
       grep -n 'let bytes = client.download_bytes' crates/nono-cli/src/package_cmd.rs        # L457 expected
       grep -n 'pub bytes: Vec<u8>' crates/nono-cli/src/package.rs                            # current shape
       ```

    5. Record pre-flight findings to plan-execution scratch (for inclusion in SUMMARY).
  </action>
  <verify>
    <automated>test -f .planning/phases/26-pkg-streaming-followup/26-01-SUMMARY.md &amp;&amp; grep -qE 'ArtifactType.*Plugin|Plugin' crates/nono-cli/src/package.rs &amp;&amp; grep -qE '^ureq = "3"' crates/nono-cli/Cargo.toml &amp;&amp; grep -qE '^tempfile = "3"' crates/nono-cli/Cargo.toml &amp;&amp; ! grep -qE '^semver' crates/nono-cli/Cargo.toml</automated>
  </verify>
  <acceptance_criteria>
    - `26-01-SUMMARY.md` exists and records "Status: Complete" (or equivalent closed marker).
    - `ArtifactType::Plugin` variant present in `package.rs`.
    - Cargo.toml pre-state confirmed: ureq=3 ✓, tempfile=3 ✓, semver ✗, mockito ✗.
    - Pre-flight scratch note recorded for SUMMARY (3 critical-site line numbers captured).
  </acceptance_criteria>
  <done>
    Prerequisites confirmed; Plan 26-02 cleared to proceed with cherry-picks.
  </done>
</task>

<task type="auto">
  <name>Task 2: Add `semver` dep to crates/nono-cli/Cargo.toml (fork-only support commit)</name>
  <files>
    crates/nono-cli/Cargo.toml
  </files>
  <read_first>
    - `crates/nono-cli/Cargo.toml` (full `[dependencies]` block)
    - Upstream `Cargo.toml` at `9ebad89a` (capture exact `semver` version they pin to, for parity)
  </read_first>
  <action>
    1. Capture upstream's `semver` pin:
       ```
       git show 9ebad89a -- crates/nono-cli/Cargo.toml | grep -E '^(\+|^)semver'
       ```
       Expected output: `+semver = "1"` or similar. Match the major version pin upstream uses.

    2. Add to `crates/nono-cli/Cargo.toml` `[dependencies]` block, alphabetically positioned:
       ```toml
       semver = "1"
       ```
       (Use exact version string upstream picked. NO features needed unless upstream enables `serde` — verify in step 1.)

    3. Verify no transitive breakage:
       ```
       cargo build --workspace
       cargo tree -p nono-cli | grep -E '^semver' | head
       ```

    4. Commit (fork-only — NO Upstream-commit trailer; this is plumbing for the cherry-pick):
       ```
       git add crates/nono-cli/Cargo.toml Cargo.lock
       git commit -s -m "$(cat <<'EOF'
       chore(26-02): add semver dep to nono-cli (PKGS-01 plumbing)

       Streaming refactor (upstream 9ebad89a) uses semver::VersionReq for
       registry version comparison. Pinned to match upstream's choice;
       no other deps changed.

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       EOF
       )"
       ```
  </action>
  <verify>
    <automated>grep -qE '^semver = "1"' crates/nono-cli/Cargo.toml &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - `semver = "1"` present in `[dependencies]` block.
    - `cargo build --workspace` exits 0.
    - Commit has Signed-off-by trailer; no Upstream-commit trailer (this is fork-only plumbing).
    - `cargo tree -p nono-cli` shows semver in dep graph.
  </acceptance_criteria>
  <done>
    semver dep landed; cherry-pick of 9ebad89a will not trip on missing dep.
  </done>
</task>

<task type="auto">
  <name>Task 3: Cherry-pick `9ebad89a` — stream package artifact downloads + add bundle_json field (PKGS-01)</name>
  <files>
    crates/nono-cli/src/package.rs                     # DownloadedArtifact struct shape change
    crates/nono-cli/src/package_cmd.rs                 # streaming sink + bundle_json threading + size cap
    crates/nono-cli/src/registry_client.rs             # ureq Agent timeouts + streaming download_to_writer
    crates/nono-cli/src/cli.rs                         # --max-size flag on PackagePullArgs
  </files>
  <read_first>
    - `git show 9ebad89a --stat` (anticipate ~+267/-109 across 5 files)
    - `git show 9ebad89a -- crates/nono-cli/src/package_cmd.rs` (full upstream diff)
    - `git show 9ebad89a -- crates/nono-cli/src/registry_client.rs` (NOTE: upstream may use hyper; fork uses ureq — translate)
    - `git show 9ebad89a -- crates/nono-cli/src/package.rs` (DownloadedArtifact field changes)
    - `crates/nono-cli/src/registry_client.rs` (current ureq shape — full file)
    - `crates/nono-cli/src/package_cmd.rs` lines 400-500 (current `download_and_verify_artifacts` flow)
  </read_first>
  <action>
    1. Cherry-pick:
       ```
       git cherry-pick 9ebad89a
       ```

    2. **D-02 fallback gate (HIGH PROBABILITY).** Two divergence vectors:
       - **HTTP client divergence:** upstream is hyper-based; fork is ureq-based. ANY upstream hunk touching `registry_client.rs::download_bytes` or hyper Client config will conflict. **Translate the intent, not the syntax:** ureq has `AgentBuilder::new().timeout_connect(Duration::from_secs(10)).timeout_read(Duration::from_secs(60))`; ureq response streaming uses `response.body_mut().as_reader()` (or `into_reader()` depending on ureq version — verify against ureq 3 API). **Do NOT introduce hyper as a parallel dep — fork is intentionally ureq-only on the registry path.**
       - **Buffered → streaming divergence at L457:** upstream replaces `let bytes = client.download_bytes(...)` with a streaming sink. Fork's surrounding code (subjects map check, push to `downloads` Vec) must be re-threaded around the new sink shape.

       D-02 path:
       ```
       git diff --name-only --diff-filter=U
       grep -c '<<<<<<<' crates/nono-cli/src/{package_cmd,registry_client,package}.rs 2>/dev/null
       ```
       If conflict count > 5 lines per file OR any conflict spans the ureq↔hyper translation: ABORT to D-20 manual replay.

    3. **D-20 manual-port path (expected default).** Stage the changes manually:

       **Step 3a — `package.rs` DownloadedArtifact:**
       ```rust
       pub struct DownloadedArtifact {
           pub filename: String,
           pub staged_path: PathBuf,                  // was: pub bytes: Vec<u8>
           pub sha256_digest: String,
           pub signer_identity: SignerIdentity,
           pub bundle_json: String,                   // NEW (PKGS-01 coupling, was local var at package_cmd.rs:425)
       }
       ```
       Add `use std::path::PathBuf;` at the top if absent.

       **Step 3b — `registry_client.rs` Agent timeouts + streaming sink:**
       ```rust
       pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
       pub const DEFAULT_READ_TIMEOUT_SECS: u64 = 60;

       impl RegistryClient {
           pub fn new(base_url: String) -> Self {
               // ureq 3 Agent config — verify exact API per `cargo doc -p ureq`
               let config = ureq::Agent::config_builder()
                   .timeout_connect(Some(std::time::Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)))
                   .timeout_recv_response(Some(std::time::Duration::from_secs(DEFAULT_READ_TIMEOUT_SECS)))
                   .build();
               Self {
                   base_url: base_url.trim_end_matches('/').to_string(),
                   http: config.into(),
               }
           }

           /// Streams response body to `sink`, enforcing `max_bytes` mid-stream.
           /// Returns total bytes written. Errors with NonoError::ArtifactTooLarge if cap exceeded.
           pub fn download_to_writer<W: std::io::Write>(
               &self,
               url: &str,
               mut sink: W,
               max_bytes: u64,
           ) -> Result<u64> {
               let resolved = self.resolve_url(url);
               let response = self.http.get(&resolved).call().map_err(map_ureq_error)?;
               let mut reader = response.into_body().into_reader();
               let mut buf = [0u8; 64 * 1024];   // 64KB chunks; bounded RSS
               let mut total: u64 = 0;
               loop {
                   let n = reader.read(&mut buf).map_err(/* map io::Error → NonoError::RegistryError */)?;
                   if n == 0 { break; }
                   total = total.checked_add(n as u64).ok_or(NonoError::RegistryError(...))?;
                   if total > max_bytes {
                       return Err(NonoError::ArtifactTooLarge { actual: total, max: max_bytes });
                   }
                   sink.write_all(&buf[..n]).map_err(/* map */)?;
               }
               Ok(total)
           }
       }
       ```
       (Verify ureq 3 exact API names — `into_body().into_reader()` may be `body_mut().as_reader()`. Compile-driven.)

       **Step 3c — `package_cmd.rs` streaming download flow:**
       ```rust
       fn download_and_verify_artifacts(...) -> Result<Vec<DownloadedArtifact>> {
           // ... existing trusted_root + bundle setup at L414-450 unchanged ...

           let bundle_json = client.download_text(&pull.bundle_url)?;   // KEEP buffered (small)
           let bundle = nono::trust::load_bundle_from_str(&bundle_json, bundle_path)?;
           // ... existing subjects + signer_identity logic unchanged ...

           // NEW: TempDir for staged artifact bytes (Drop-cleaned on success or panic)
           let staging = tempfile::TempDir::new().map_err(|e| NonoError::RegistryError(format!("failed to create staging tempdir: {e}")))?;
           let max_bytes = pull.max_size.unwrap_or(DEFAULT_MAX_ARTIFACT_BYTES);   // 500MB default

           let mut downloads = Vec::with_capacity(pull.artifacts.len());
           for artifact in &pull.artifacts {
               let staged_path = staging.path().join(&artifact.filename);
               let mut hasher = sha2::Sha256::new();
               let mut sink = HashingWriter { inner: std::fs::File::create(&staged_path)?, hasher: &mut hasher };
               client.download_to_writer(&artifact.download_url, &mut sink, max_bytes)?;
               let digest = format!("{:x}", hasher.finalize());

               // Existing digest + subject checks unchanged (operate on `digest` string, not bytes Vec)
               if digest != artifact.sha256_digest { return Err(...); }
               if !subject_digests.contains_key(digest.as_str()) { return Err(...); }

               downloads.push(DownloadedArtifact {
                   filename: artifact.filename.clone(),
                   staged_path,                         // was: bytes
                   sha256_digest: digest,
                   signer_identity: signer_identity.clone(),
                   bundle_json: bundle_json.clone(),    // NEW field
               });
           }
           // staging TempDir kept alive until install_dir copy completes (caller responsibility).
           // ALTERNATIVE: return `(Vec<DownloadedArtifact>, TempDir)` so Drop fires after install.
           Ok(downloads)
       }
       ```

       **CRITICAL — TempDir lifetime:** the `staging: TempDir` MUST outlive every `staged_path` it produced. Two options:
       - Option A (preferred): make `download_and_verify_artifacts` return `(Vec<DownloadedArtifact>, TempDir)`; caller threads the TempDir alongside until `install_artifacts` copies bytes to `install_dir`.
       - Option B: store the TempDir as a field on a wrapper struct (`StagedDownloads { artifacts, _staging }`).
       Match upstream's choice if the cherry-pick reveals one; otherwise Option A.

       **Step 3d — `cli.rs` `--max-size` flag:**
       ```rust
       #[derive(Args)]
       pub struct PackagePullArgs {
           // ... existing fields ...
           /// Maximum artifact size in bytes (default 500MB). Streaming download rejects mid-stream if exceeded.
           #[arg(long, value_name = "BYTES")]
           pub max_size: Option<u64>,
       }
       ```
       Thread `max_size` from CLI args → `PullResponse` consumer → `download_to_writer` call.

       **Step 3e — `package.rs` callsite updates.** Every read of `artifact.bytes` (e.g., `load_manifest` at L498: `serde_json::from_slice::<PackageManifest>(&manifest.bytes)`) becomes `std::fs::read(&artifact.staged_path)?` followed by `from_slice`. Audit ALL `.bytes` references via:
       ```
       grep -n '\.bytes' crates/nono-cli/src/package_cmd.rs crates/nono-cli/src/package.rs
       ```
       Replace each with `staged_path`-based read. KEEP the in-memory check semantics (every byte still hashed and subject-matched before install).

       **Step 3f — Add `NonoError::ArtifactTooLarge` variant.** Audit `crates/nono/src/error.rs`:
       ```
       grep -n 'ArtifactTooLarge\|enum NonoError' crates/nono/src/error.rs
       ```
       If absent: ADD the variant with `#[error("artifact size {actual} exceeds maximum {max}")]` doc + sign-off. **CAUTION D-19:** this touches `crates/nono/`, which is byte-identical-preserved in v2.3 BUT this variant is required by the upstream cherry-pick. **Disposition:** allow the addition with `Upstream-commit: 9ebad89a` provenance (not a pure fork divergence; it's an upstream port). Alternative: define `ArtifactTooLarge` as a `RegistryError` payload string to keep `crates/nono/` byte-identical — verify upstream's choice.

    4. Amend commit body (D-20 path expected):
       ```
       git commit --amend -s -m "$(cat <<'EOF'
       refactor(26-02): stream package artifact downloads (PKGS-01)

       Replaces buffered `client.download_bytes() -> Vec<u8>` with streaming
       `download_to_writer<W>` sink that writes to a TempDir-staged PathBuf,
       computes SHA-256 incrementally, and enforces `--max-size` cap mid-stream.
       Adds `bundle_json` field to DownloadedArtifact (was local var at L425)
       so verified bundle metadata rides alongside the streamed PathBuf.
       ureq Agent gains connect_timeout + read_timeout (10s/60s defaults).

       Manual replay: fork uses ureq 3, NOT hyper; translated upstream's hyper
       streaming pattern to ureq 3 API. Fork's pre-existing buffered surface
       at package_cmd.rs:457 + DownloadedArtifact.bytes field re-threaded
       around the new staged_path shape.

       Upstream-commit: 9ebad89a (replayed manually)
       Upstream-tag: <git describe --tags 9ebad89a>
       Upstream-author: <capture from `git log -1 9ebad89a --format='%an <%ae>'`>
       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       EOF
       )"
       ```

    5. Verify build:
       ```
       cargo build --workspace
       cargo run -p nono-cli -- package pull --help 2>&1 | grep -E 'max-size'
       ```
  </action>
  <verify>
    <automated>cargo build --workspace &amp;&amp; grep -qE 'pub staged_path: PathBuf' crates/nono-cli/src/package.rs &amp;&amp; grep -qE 'pub bundle_json: String' crates/nono-cli/src/package.rs &amp;&amp; ! grep -qE 'let bundle_json = client\.download_text' crates/nono-cli/src/package_cmd.rs &amp;&amp; grep -qE 'TempDir::new|tempfile::TempDir' crates/nono-cli/src/package_cmd.rs &amp;&amp; grep -qE 'timeout_connect|timeout_recv' crates/nono-cli/src/registry_client.rs &amp;&amp; cargo run -p nono-cli -- package pull --help 2&gt;&amp;1 | grep -qE 'max-size' &amp;&amp; git log -1 --format='%b' | grep -qE '^Upstream-commit: 9ebad89a'</automated>
  </verify>
  <acceptance_criteria>
    - `pub staged_path: PathBuf` field present in `DownloadedArtifact`; `pub bytes: Vec<u8>` field absent.
    - `pub bundle_json: String` field present in `DownloadedArtifact`.
    - `let bundle_json =` local var at `package_cmd.rs:~425` is gone (replaced by field assignment).
    - `tempfile::TempDir` used for staging; visible in `package_cmd.rs`.
    - `ureq::Agent` config has `timeout_connect` + `timeout_recv_response` (or equivalent ureq 3 API).
    - `--max-size` flag visible in `package pull --help`.
    - `cargo build --workspace` exits 0.
    - Commit body has `Upstream-commit: 9ebad89a` trailer (with or without `(replayed manually)` qualifier).
    - No `<capture from` placeholders in commit body.
    - **D-19 audit:** if `crates/nono/src/error.rs` was modified to add `ArtifactTooLarge`, the modification has its own `Upstream-commit: 9ebad89a` provenance and is the ONLY `crates/nono/` change in this plan.
  </acceptance_criteria>
  <done>
    Streaming refactor + bundle_json field landed. Memory profile of `nono package pull` is now stream-bounded (~64KB chunk size, not artifact size).
  </done>
</task>

<task type="auto">
  <name>Task 4: Cherry-pick `115b5cfa` — load_registry_profile auto-pull (PKGS-04)</name>
  <files>
    crates/nono-cli/src/profile/mod.rs
  </files>
  <read_first>
    - `git show 115b5cfa --stat` and full diff
    - `crates/nono-cli/src/profile/mod.rs` (current Profile::resolve / extends-chain logic)
    - `crates/nono-cli/src/package_cmd.rs` (the public `pull()` entry point — auto-pull will call it)
    - `REQUIREMENTS.md § REQ-PKGS-04` (acceptance criteria)
  </read_first>
  <action>
    1. Cherry-pick:
       ```
       git cherry-pick 115b5cfa
       ```

    2. **D-02 fallback gate.** `profile/mod.rs` was forked in Phase 22 Plan 22-01 (PROF-02 PackRef). Conflict probability MEDIUM-HIGH.
       ```
       git diff --name-only --diff-filter=U
       grep -c '<<<<<<<' crates/nono-cli/src/profile/mod.rs 2>/dev/null
       ```

    3. **Implementation contract** (from REQUIREMENTS.md § REQ-PKGS-04):
       - When `Profile::resolve` walks the `extends` chain and encounters an entry matching `registry://<vendor>/<pack>@<version>`:
         a. Check if the pack is already installed locally (re-use existing `package_cmd::is_installed(&pack_ref)` or equivalent).
         b. If absent: call `package_cmd::pull(&pack_ref, &PullArgs { max_size: <inherited from profile config> })`.
         c. If present: skip pull (idempotent); proceed to extension resolution.
       - Pull respects PKGS-01 size cap (REQ-PKGS-04 acceptance #3).
       - On network failure with pack absent: return `NonoError::ProfileResolve { reason: "registry pack <name> required by extends chain is not installed and registry is unreachable", source }`. (REQ-PKGS-04 acceptance #2.)

    4. URI parsing: introduce a small helper if one doesn't exist:
       ```rust
       fn parse_registry_pack_ref(extends_entry: &str) -> Option<PackageRef> {
           // matches "registry://vendor/pack@version" → PackageRef { namespace: vendor, name: pack, version }
           extends_entry.strip_prefix("registry://").and_then(/* parse vendor/pack@version */)
       }
       ```
       Place this in `profile/mod.rs` (or `package.rs` if upstream put it there).

    5. **CRITICAL — idempotency contract.** Call `package_cmd::is_installed` BEFORE `package_cmd::pull`. Auto-pull MUST be a no-op when the pack is already present (matches PKG-03 hook idempotency invariant from Plan 22-03).

    6. Amend commit body:
       ```
       git commit --amend -s -m "$(cat <<'EOF'
       feat(26-02): load profiles from registry packs (PKGS-04)

       Profile::resolve walking the extends chain auto-pulls referenced
       registry packs (registry://vendor/pack@version) idempotently when
       absent locally. Pull respects PKGS-01 size cap + HTTP timeouts.
       Network failure with pack absent fails closed with clear error
       pointing at the missing pack (REQ-PKGS-04 acceptance #2).

       Upstream-commit: 115b5cfa
       Upstream-tag: <git describe --tags 115b5cfa>
       Upstream-author: <capture from `git log -1 115b5cfa --format='%an <%ae>'`>
       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       EOF
       )"
       ```

    7. Verify build + existing profile tests (regressions):
       ```
       cargo build --workspace
       cargo test -p nono-cli profile::
       ```
  </action>
  <verify>
    <automated>cargo build --workspace &amp;&amp; cargo test -p nono-cli profile:: &amp;&amp; grep -qE 'registry://|load_registry_profile|parse_registry_pack_ref' crates/nono-cli/src/profile/mod.rs &amp;&amp; git log -1 --format='%b' | grep -qE '^Upstream-commit: 115b5cfa'</automated>
  </verify>
  <acceptance_criteria>
    - `registry://` URI handling visible in `profile/mod.rs` (grep returns ≥ 1 hit).
    - Existing Plan 22-01 PROF-02 PackRef tests still green (no PackRef ABI break).
    - Auto-pull idempotency: a unit test (or inline assertion) confirms calling `Profile::resolve` twice in a row triggers `package_cmd::pull` exactly once.
    - `cargo build --workspace` exits 0.
    - Commit body has `Upstream-commit: 115b5cfa` trailer.
    - No `<capture from` placeholders.
  </acceptance_criteria>
  <done>
    Auto-pull semantics landed; profiles can transparently fetch registry packs.
  </done>
</task>

<task type="auto">
  <name>Task 5: Add mockito dev-dep (if absent) — fork-only support commit</name>
  <files>
    crates/nono-cli/Cargo.toml
  </files>
  <read_first>
    - `crates/nono-cli/Cargo.toml` `[dev-dependencies]` block
    - workspace root `Cargo.toml` (verify mockito or wiremock isn't already a workspace dep)
  </read_first>
  <action>
    1. Detect existing convention:
       ```
       grep -rE '^(mockito|wiremock) = ' Cargo.toml crates/*/Cargo.toml
       ```
       - If `mockito` already present somewhere: re-use it. Skip Task 5.
       - If `wiremock` present somewhere: switch Task 6's tests to use `wiremock` instead. Skip Task 5.
       - If neither: ADD `mockito` per below (default per CONTEXT prompt).

    2. Add to `crates/nono-cli/Cargo.toml` `[dev-dependencies]`:
       ```toml
       mockito = "1"
       ```

    3. Verify:
       ```
       cargo build --workspace --tests
       ```

    4. Commit:
       ```
       git add crates/nono-cli/Cargo.toml Cargo.lock
       git commit -s -m "$(cat <<'EOF'
       chore(26-02): add mockito dev-dep for streaming integration tests

       Task 6 mocks the registry HTTP endpoint to verify streaming, size-cap,
       timeout, and tamper-rejection behavior without requiring a live
       registry. Dev-only; not built into release binaries.

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       EOF
       )"
       ```
  </action>
  <verify>
    <automated>grep -qE '^mockito = ' crates/nono-cli/Cargo.toml &amp;&amp; cargo build --workspace --tests</automated>
  </verify>
  <acceptance_criteria>
    - Either: `mockito = "1"` (or `wiremock`) present in `[dev-dependencies]`, OR Task 5 skipped because convention already exists.
    - `cargo build --workspace --tests` exits 0.
    - Commit (if any) has Signed-off-by trailer; no Upstream-commit trailer.
  </acceptance_criteria>
  <done>
    HTTP mocking framework available for Task 6.
  </done>
</task>

<task type="auto">
  <name>Task 6: Integration tests — streaming, size limits, timeouts, tamper rejection, auto-pull happy/sad paths, panic-safe TempDir cleanup</name>
  <files>
    crates/nono-cli/tests/package_streaming_integration.rs (NEW)
  </files>
  <read_first>
    - `REQUIREMENTS.md § REQ-PKGS-01` (acceptance criteria 1–4)
    - `REQUIREMENTS.md § REQ-PKGS-04` (acceptance criteria 1–3)
    - `crates/nono-cli/tests/*.rs` (existing fork test pattern; how `run_nono` harness is invoked)
    - mockito v1 README for `Server::new()`, `mock("GET", ...).with_body_from_file`, `delay`, etc.
  </read_first>
  <action>
    1. Create `crates/nono-cli/tests/package_streaming_integration.rs` with the following test set:

       ```rust
       //! Streaming + auto-pull integration tests (REQ-PKGS-01, REQ-PKGS-04).
       //!
       //! Host preference: Linux/macOS. Windows is queued behind v2.4 NONO_TEST_HOME seam
       //! (auto-pull tests use run_nono harness which trips on dirs::home_dir()
       //! ignoring USERPROFILE).

       #![allow(clippy::unwrap_used)]   // tests-only

       use mockito::{Server, ServerOpts};
       use std::io::Read;
       use std::path::PathBuf;
       use std::time::Duration;

       /// REQ-PKGS-01 acceptance #1: 200MB streams at ~10MB peak RSS.
       /// Linux-only because /proc/self/status is Linux-specific.
       #[cfg(target_os = "linux")]
       #[test]
       fn streaming_200mb_artifact_under_50mb_rss() {
           let mut server = Server::new();
           let payload = vec![0u8; 200 * 1024 * 1024];   // 200MB of zeros
           let digest = sha256_hex(&payload);
           let _m = server.mock("GET", "/artifact.bin")
               .with_status(200)
               .with_header("content-type", "application/octet-stream")
               .with_body(payload)
               .create();

           let baseline_rss = read_proc_self_rss_kb();
           let client = nono_cli::registry_client::RegistryClient::new(server.url());
           let staging = tempfile::TempDir::new().unwrap();
           let staged_path = staging.path().join("artifact.bin");
           let mut file = std::fs::File::create(&staged_path).unwrap();
           let bytes_written = client.download_to_writer(
               "/artifact.bin",
               &mut file,
               1024 * 1024 * 1024,   // 1GB cap (well above 200MB)
           ).expect("streaming download should succeed");

           let peak_rss = read_proc_self_rss_kb();
           let delta_kb = peak_rss.saturating_sub(baseline_rss);

           assert_eq!(bytes_written, 200 * 1024 * 1024);
           assert_eq!(staged_path.metadata().unwrap().len(), 200 * 1024 * 1024);
           assert!(
               delta_kb < 50 * 1024,   // < 50MB delta
               "RSS delta {delta_kb}KB exceeds 50MB ceiling — streaming is buffering"
           );
       }

       /// REQ-PKGS-01 acceptance #2: tampered artifact rejected before install_dir.
       #[test]
       fn streaming_rejects_tampered_artifact() {
           let mut server = Server::new();
           let real_payload = b"GENUINE PACKAGE BYTES";
           let real_digest = sha256_hex(real_payload);
           let tampered_payload = b"TAMPERED PACKAGE BYTES";   // different digest
           let _m_pull = server.mock("GET", mockito::Matcher::Regex(r"^/api/v1/packages/.*/pull$".into()))
               .with_status(200)
               .with_body(format!(r#"{{
                   "bundle_url": "{url}/bundle.json",
                   "artifacts": [{{
                       "filename": "package.json",
                       "download_url": "{url}/artifact.bin",
                       "sha256_digest": "{digest}"
                   }}]
               }}"#, url=server.url(), digest=real_digest))
               .create();
           let _m_artifact = server.mock("GET", "/artifact.bin")
               .with_body(tampered_payload)   // mismatch
               .create();

           let result = nono_cli::package_cmd::pull(/* PullArgs pointing at server */);
           assert!(matches!(result, Err(nono::NonoError::PackageVerification { .. })));
           // Verify NO bytes landed in install_dir.
       }

       /// REQ-PKGS-01 acceptance #3: artifact > --max-size rejected mid-stream.
       #[test]
       fn streaming_rejects_oversize_artifact() {
           let mut server = Server::new();
           let payload = vec![0u8; 10 * 1024 * 1024];   // 10MB
           let _m = server.mock("GET", "/big.bin")
               .with_body(payload)
               .create();

           let client = nono_cli::registry_client::RegistryClient::new(server.url());
           let mut sink = Vec::new();
           let result = client.download_to_writer("/big.bin", &mut sink, 1024 * 1024);   // 1MB cap

           assert!(matches!(result, Err(nono::NonoError::ArtifactTooLarge { .. })));
       }

       /// REQ-PKGS-01 acceptance #4 (a): connect timeout fires.
       #[test]
       fn streaming_http_connect_timeout_fires() {
           // 127.0.0.1:1 — port where nothing listens. RST or refused immediately.
           // For a true connect-timeout test, point at 10.255.255.1 (RFC1918 unroutable)
           // with a low timeout. Implementation-driven; pick whichever ureq returns ConnectTimeout for.
           let client = nono_cli::registry_client::RegistryClient::new("http://10.255.255.1".into());
           let mut sink = Vec::new();
           let result = client.download_to_writer("/x", &mut sink, 1024);

           assert!(result.is_err());
           let err_str = format!("{:?}", result.unwrap_err());
           assert!(err_str.to_lowercase().contains("timeout") || err_str.to_lowercase().contains("connect"));
       }

       /// REQ-PKGS-01 acceptance #4 (b): idle/read timeout fires mid-stream.
       /// mockito's `delay` keeps the response open; ureq's read_timeout should fire.
       #[test]
       fn streaming_http_read_timeout_fires() {
           let mut server = Server::new();
           let _m = server.mock("GET", "/slow.bin")
               .with_chunked_body(|w| {
                   w.write_all(b"first chunk").unwrap();
                   std::thread::sleep(Duration::from_secs(120));   // > 60s read_timeout
                   w.write_all(b"second chunk").unwrap();
                   Ok(())
               })
               .create();

           let client = nono_cli::registry_client::RegistryClient::new(server.url());
           let mut sink = Vec::new();
           let result = client.download_to_writer("/slow.bin", &mut sink, 1024 * 1024);

           assert!(result.is_err());
       }

       /// REQ-PKGS-04 acceptance #1: profile with registry:// extends auto-pulls.
       /// Uses run_nono harness — host-preferred Linux/macOS per host_blocker.
       #[test]
       fn auto_pull_loads_registry_pack_extends() {
           let mut server = Server::new_with_opts(ServerOpts { ..Default::default() });
           // ... mock /api/v1/packages/.../pull + /bundle.json + /artifact.bin
           // ... write a profile to test_home/.config/nono/profiles/test.toml with extends=["registry://vendor/pack@1.0.0"]
           // ... invoke nono via run_nono harness; assert resolve succeeds
           // ... assert pack now exists at install_dir
           // EXEC-NOTE: this test will skip on Windows until v2.4 NONO_TEST_HOME seam lands.
       }

       /// REQ-PKGS-04 acceptance #2: no network + pack absent → fail closed.
       #[test]
       fn auto_pull_fails_closed_on_missing_pack_no_network() {
           // Profile points at registry://vendor/missing@1.0.0; mock server NOT started.
           // Resolve must return clear NonoError::ProfileResolve / RegistryError, not silent default.
       }

       /// REQ-PKGS-04 acceptance #3: auto-pull respects --max-size from PKGS-01.
       #[test]
       fn auto_pull_respects_max_size_cap() {
           // Profile config sets max_size=1MB; mock returns 10MB pack.
           // Auto-pull must reject with ArtifactTooLarge.
       }

       /// PKGS-01 invariant: TempDir cleaned up on panic (Drop runs unconditionally).
       #[test]
       fn streaming_tempdir_cleaned_on_panic() {
           let staging_path: PathBuf;
           let panic_caught = std::panic::catch_unwind(|| {
               let staging = tempfile::TempDir::new().unwrap();
               let path_clone = staging.path().to_path_buf();
               // Inject panic mid-flow; staging Drop must still run.
               std::panic::resume_unwind(Box::new(path_clone));
           });
           assert!(panic_caught.is_err());
           if let Err(boxed) = panic_caught {
               if let Ok(p) = boxed.downcast::<PathBuf>() {
                   assert!(!p.exists(), "TempDir at {p:?} must be cleaned up after panic");
               }
           }
       }

       // ---- helpers ----

       fn sha256_hex(bytes: &[u8]) -> String {
           use sha2::{Digest, Sha256};
           let mut h = Sha256::new();
           h.update(bytes);
           format!("{:x}", h.finalize())
       }

       #[cfg(target_os = "linux")]
       fn read_proc_self_rss_kb() -> u64 {
           let s = std::fs::read_to_string("/proc/self/status").unwrap();
           for line in s.lines() {
               if let Some(rest) = line.strip_prefix("VmRSS:") {
                   let kb: u64 = rest.split_whitespace().next().unwrap().parse().unwrap();
                   return kb;
               }
           }
           0
       }
       ```

       **Implementation notes:**
       - Test function names match the must_haves.truths assertions verbatim where possible.
       - The `run_nono` harness wiring for the auto-pull tests follows existing fork test patterns at `crates/nono-cli/tests/*_integration.rs`. EXEC-NOTE: documented Windows skip is fine; test body is host-preferred.
       - `auto_pull_loads_registry_pack_extends` and `auto_pull_fails_closed_on_missing_pack_no_network` may be split into two files if the harness setup is heavyweight; default is single file.

    2. Compile + run on Linux/macOS host:
       ```
       cargo test -p nono-cli --test package_streaming_integration --no-run
       cargo test -p nono-cli --test package_streaming_integration
       ```

    3. Commit (fork-only — NO Upstream-commit trailer):
       ```
       git add crates/nono-cli/tests/package_streaming_integration.rs
       git commit -s -m "$(cat <<'EOF'
       test(26-02): add streaming + auto-pull integration tests (PKGS-01, PKGS-04)

       Covers REQ-PKGS-01 acceptance 1–4 (200MB streams at ~10MB RSS,
       tamper rejection, --max-size cap, connect+read timeouts) and
       REQ-PKGS-04 acceptance 1–3 (auto-pull happy/sad paths, size-cap
       respect). Uses mockito for HTTP fixtures. Linux-only RSS test
       gated #[cfg(target_os = "linux")]; macOS + Windows skipped.
       Auto-pull e2e tests host-preferred Linux/macOS per
       PLAN.md `host_blocker` (Windows blocked on v2.4 NONO_TEST_HOME seam).

       Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
       EOF
       )"
       ```
  </action>
  <verify>
    <automated>cargo test -p nono-cli --test package_streaming_integration --no-run &amp;&amp; (cargo test -p nono-cli --test package_streaming_integration 2&gt;&amp;1 || true) | tail</automated>
  </verify>
  <acceptance_criteria>
    - `crates/nono-cli/tests/package_streaming_integration.rs` exists.
    - `cargo test -p nono-cli --test package_streaming_integration --no-run` exits 0 (compiles on all hosts).
    - On Linux: all 8 tests pass (or documented-skip with rationale captured in SUMMARY).
    - On macOS: 7 tests pass; `streaming_200mb_artifact_under_50mb_rss` documented-skipped (gated `#[cfg(target_os = "linux")]`).
    - On Windows: `streaming_*` tests pass; `auto_pull_*` tests documented-skipped per `host_blocker`.
    - Commit has Signed-off-by trailer; no Upstream-commit trailer.
  </acceptance_criteria>
  <done>
    Streaming + auto-pull behavior is test-pinned. PKGS-01 + PKGS-04 acceptance criteria are now grep-verifiable AND runtime-verifiable.
  </done>
</task>

<task type="auto">
  <name>Task 7: Verification gate — make ci + D-19 byte-identical preservation audit</name>
  <files>(read-only verification — no files modified)</files>
  <read_first>
    - `.planning/phases/26-pkg-streaming-followup/26-CONTEXT.md` (if exists; D-19 + verification gate spec)
    - PR-583 / Phase 23 / Phase 29 precedent for documented-skip clippy items
  </read_first>
  <action>
    1. Build clean:
       ```
       cargo build --workspace
       ```

    2. Test suite:
       ```
       cargo test --workspace --all-features
       ```
       On Linux/macOS host: must exit 0 within deferred-flake window. Document any flakes per Phase 19 precedent.

    3. Lint:
       ```
       cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
       ```
       Documented-skip permitted only for pre-existing `nono::manifest` clippy items per Phase 23 / 29 precedent. ANY new clippy warning introduced by this plan: BLOCKING — fix before close.

    4. Format:
       ```
       cargo fmt --all -- --check
       ```

    5. **D-19 byte-identical preservation audit.** Capture baseline SHA before plan started (record in SUMMARY) and run:
       ```
       BASELINE=<pre-plan SHA>
       git diff --stat $BASELINE..HEAD -- crates/nono/
       ```
       Expected: empty output (D-19 invariant — `crates/nono/` untouched in v2.3 Phase 26).

       **Disposition for ArtifactTooLarge variant:** if Task 3 step 3f added `NonoError::ArtifactTooLarge` to `crates/nono/src/error.rs`, the audit will return non-empty. Two paths:
       - **Accept (preferred):** the addition has documented `Upstream-commit: 9ebad89a` provenance per Task 3 acceptance criterion; cite it in SUMMARY's D-19 deviation note.
       - **Refactor (fallback):** if D-19 is interpreted as strict byte-identical, refactor `ArtifactTooLarge` to a `RegistryError(format!(...))` payload string in `crates/nono-cli/` only. Decision recorded in SUMMARY.

    6. Phase-26-specific gate: confirm Plan 26-01 + Plan 26-02 SUMMARYs are aligned (no contradictory must_haves).

    7. STOP if any of the above fails. Revert offending commit and re-scope.

    8. NO commit for this task — verification only.
  </action>
  <verify>
    <automated>cargo build --workspace &amp;&amp; cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <acceptance_criteria>
    - `cargo build --workspace` exits 0.
    - `cargo test --workspace --all-features` exits 0 within deferred-flake tolerance.
    - `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0 (with documented-skip for pre-existing items only).
    - `cargo fmt --all -- --check` exits 0.
    - `git diff --stat <baseline>..HEAD -- crates/nono/` is empty OR has the documented `ArtifactTooLarge` deviation with `Upstream-commit: 9ebad89a` provenance.
    - No new clippy warnings introduced by this plan.
  </acceptance_criteria>
  <done>
    Verification gate cleared. Plan 26-02 ready to push to origin via Task 8.
  </done>
</task>

<task type="auto">
  <name>Task 8: D-07 plan-close push to origin</name>
  <files>(no files modified)</files>
  <read_first>
    - `.planning/phases/26-pkg-streaming-followup/26-CONTEXT.md § D-07` (if present; otherwise inherit Phase 22 D-07)
  </read_first>
  <action>
    ```
    git fetch origin
    git log --oneline origin/main..main
    git push origin main
    git ls-remote origin main
    ```
    Capture the post-push origin/main SHA for SUMMARY.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - `git log origin/main..main --oneline | wc -l` returns `0` after push.
    - SUMMARY records the post-push origin/main SHA.
  </acceptance_criteria>
  <done>
    Plan 26-02 commits published to origin.
  </done>
</task>

</tasks>

<non_goals>
**Plan 26-01 scope (PKGS-02 + PKGS-03 fork-arch):** `validate_relative_path` belt-and-suspenders + `ArtifactType::Plugin` variant. Plan 26-02 has a HARD prerequisite on 26-01 closure but does NOT re-implement those concerns.

**`crates/nono/` byte-identical preservation (D-19):** v2.3 Phase 26 does NOT modify the core library beyond the (potential) `NonoError::ArtifactTooLarge` variant addition, which has documented upstream provenance. No Sandbox / CapabilitySet / Supervisor changes.

**Cross-platform RSS measurement:** `streaming_200mb_artifact_under_50mb_rss` is gated `#[cfg(target_os = "linux")]`. macOS + Windows fall back to the `--max-size` cap test as the portable streaming-bound proxy. Native macOS `task_info` Mach API binding deferred to v2.4+ if needed.

**Windows execution:** auto-pull e2e tests trip on `dirs::home_dir()` ignoring `USERPROFILE` (v2.4 backlog). Plan execution is host-preferred Linux/macOS until the `NONO_TEST_HOME` seam lands.

**Registry server implementation:** Phase 26 only adds client-side streaming; the registry server is upstream's existing infrastructure. No fork-only registry server work.

**Multi-tenant registry features:** out of scope for v2.x; pure upstream port.

**Upstream v0.41–v0.43 ingestion:** v2.4 backlog (DRIFT-01/02 first real load deferred one cycle).
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Registry HTTP endpoint → `RegistryClient::download_to_writer` | Untrusted network response crosses into the streaming sink. Tampered response = Tampering threat (T-26-02-01). |
| Streaming sink → `tempfile::TempDir`-staged file | Bytes written incrementally; SHA-256 computed mid-stream. Tampering detected at end-of-stream digest check before any install_dir write. |
| `--max-size` flag → mid-stream gate | User-supplied / config-supplied cap. Misconfigured cap = DoS vector (T-26-02-04). |
| `extends: ["registry://..."]` → `package_cmd::pull` | Profile-controlled URI triggers network pull. Untrusted profile content = same trust path as direct `nono package pull` (T-26-02-05). |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-26-02-01 | Tampering | Registry returns tampered artifact | **high** | mitigate (BLOCKING) | Streaming SHA-256 incremental; mismatch rejects before `install_artifacts` copies bytes from TempDir to install_dir. Test: `streaming_rejects_tampered_artifact`. PKGS-01 acceptance #2. |
| T-26-02-02 | Denial of Service | Memory bomb — registry returns 10GB artifact | **high** | mitigate (BLOCKING) | `--max-size` cap (default 500MB) enforced mid-stream by `download_to_writer`; `NonoError::ArtifactTooLarge` returned before `total > max_bytes`. Test: `streaming_rejects_oversize_artifact`. PKGS-01 acceptance #3. |
| T-26-02-03 | Denial of Service | Hung connection — registry never responds | medium | mitigate | ureq Agent connect_timeout=10s, read_timeout=60s. Tests: `streaming_http_connect_timeout_fires`, `streaming_http_read_timeout_fires`. PKGS-01 acceptance #4. |
| T-26-02-04 | Denial of Service | Misconfigured `--max-size` (e.g. 0 bytes) | low | mitigate | Default 500MB; user override goes through standard clap u64 parse. If 0: every artifact rejects, but no silent failure (clear `ArtifactTooLarge` error). Documented behavior. |
| T-26-02-05 | Tampering | Hostile profile injects `extends: ["registry://attacker/exfil@1.0.0"]` | medium | accept | Auto-pull path is the SAME trust path as direct `nono package pull`: signed-artifact verification + bundle subjects check + namespace assertion (per existing PKG-04). Profile content trust is upstream's stance; v2.3 does not re-litigate. |
| T-26-02-06 | Information Disclosure | TempDir-staged artifact bytes readable by other users on multi-user host | medium | mitigate | `tempfile::TempDir` defaults to `0o700` perms on Unix; on Windows uses default ACL inheriting from user profile. Verified by tempfile crate semantics. |
| T-26-02-07 | Tampering | Panic mid-stream leaves partial bytes in TempDir, then a malicious actor races to read | low | mitigate | `TempDir` Drop runs on panic (verified by `streaming_tempdir_cleaned_on_panic` test). No partial bytes survive. |
| T-26-02-08 | Repudiation | Cherry-pick provenance lost | medium | mitigate | D-19 trailers enforced (Tasks 3 + 4). |
| T-26-02-09 | Tampering | Bundle JSON tampered + becomes a field on DownloadedArtifact = wider blast radius | low | mitigate | `bundle_json` field is set to the value from `client.download_text(&pull.bundle_url)`; the verified bundle is parsed via `nono::trust::load_bundle_from_str` BEFORE `bundle_json` is committed to the field. Tampering is rejected at the parse step. |
| T-26-02-10 | Elevation of Privilege | Auto-pull triggered by profile resolve in unprivileged context, but pull writes to install_dir under elevated user | low | accept | Auto-pull inherits the calling user's permissions (matches direct-pull behavior). No privilege escalation introduced. |

**BLOCKING threats:** T-26-02-01, T-26-02-02 (high severity) — Plan 26-02 cannot close until these are mitigated and verified by Task 6 tests.
</threat_model>

<verification>
- `cargo build --workspace` exits 0.
- `cargo test --workspace --all-features` exits 0 within deferred-flake tolerance on Linux/macOS host.
- `cargo fmt --all -- --check` exits 0.
- `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
- `cargo test -p nono-cli --test package_streaming_integration` passes 7+ tests on macOS, 8/8 on Linux.
- `nono package pull --help` lists `--max-size <BYTES>` flag.
- All cherry-pick commits carry D-19 trailers (`Upstream-commit:` for Tasks 3 + 4); fork-only commits (Tasks 2, 5, 6) carry Signed-off-by only.
- `git log origin/main..main` shows zero commits ahead post-Task 8.
- No `<capture from` placeholders in any commit body.
- `git diff --stat <baseline>..HEAD -- crates/nono/` is empty OR has the documented `NonoError::ArtifactTooLarge` deviation with `Upstream-commit: 9ebad89a` provenance.
- Plan 26-01 SUMMARY confirms closed; Plan 26-02 SUMMARY records the prerequisite check passing.
</verification>

<success_criteria>
- 6–8 atomic commits on `main`:
  - Task 2 (semver dep — fork plumbing)
  - Task 3 (cherry-pick / replay 9ebad89a — streaming + bundle_json field)
  - Task 4 (cherry-pick / replay 115b5cfa — auto-pull)
  - Task 5 (mockito dev-dep — IF needed; may be skipped)
  - Task 6 (integration tests — fork-only)
  - Task 7 (verification gate — NO commit)
  - Task 8 (push — NO commit)
- `nono package pull <large-artifact>` of 200MB streams at ~10MB peak RSS (Linux-verified, macOS implicit via cap test).
- Tampered + oversize artifacts reject mid-stream with clear errors.
- HTTP connect + read timeouts fire after configured thresholds.
- Profile `extends: ["registry://..."]` triggers idempotent auto-pull.
- Auto-pull respects `--max-size` cap and HTTP timeouts.
- `bundle_json` is a struct field (not a local variable).
- `make ci` green or matches Phase 19 deferred window.
- `origin/main` advanced to plan-close HEAD.
- Plan SUMMARY records all 8 tasks' outcomes, ~6 commit hashes, the D-02→D-20 path taken (cherry-pick clean vs manual replay) for each upstream SHA, the D-19 disposition for `ArtifactTooLarge` if added, and any host-preference deferrals (Windows auto-pull tests).
</success_criteria>

<output>
Create `.planning/phases/26-pkg-streaming-followup/26-02-PKGS-STREAMING-SUMMARY.md` per standard summary template. Required sections: Outcome, What was done (one bullet per task), Verification table, Files changed table, Commits (6-row table with hashes + upstream provenance), Status, Deferred (any host_preference deferrals — Windows auto-pull tests until v2.4 NONO_TEST_HOME seam; D-19 disposition for ArtifactTooLarge if applicable), Risks materialized (which of the 3 top risks fired during execution).
</output>
