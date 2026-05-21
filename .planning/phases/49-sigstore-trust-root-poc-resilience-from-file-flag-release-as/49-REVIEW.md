---
phase: 49-sigstore-trust-root-poc-resilience
reviewed: 2026-05-21T00:00:00Z
depth: standard
files_reviewed: 9
files_reviewed_list:
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/setup.rs
  - crates/nono-cli/tests/setup_trust_root.rs
  - crates/nono/src/trust/bundle.rs
  - crates/nono/src/trust/mod.rs
  - .github/workflows/release.yml
  - docs/cli/development/windows-poc-handoff.mdx
  - scripts/verify-trust-root-cached.ps1
  - scripts/verify-trust-root-cached.sh
findings:
  critical: 0
  warning: 7
  info: 7
  total: 14
status: issues_found
---

# Phase 49: Code Review Report

**Reviewed:** 2026-05-21T00:00:00Z
**Depth:** standard
**Files Reviewed:** 9
**Status:** issues_found

## Summary

Phase 49 adds `nono setup --from-file <PATH>` (offline trust-root population),
release-asset bundling of `trusted_root.json`, and maintainer-side smoke
scripts (`scripts/verify-trust-root-cached.{sh,ps1}`) for the rotation
cadence playbook. The `from_file_step` flow correctly reuses
`load_trusted_root` + `check_trusted_root_freshness`, fails closed on parse
and freshness errors, and does best-effort cleanup on `fs::copy` failure
(D-49-B2). The clap-mutex (`conflicts_with = "refresh_trust_root"`) is
correctly defined and tested.

The cryptographic verification posture is intact (no `verify_sct` bypass,
no new schema validator, byte-identical copy mirroring upstream
`trusted_root.json` over the wire). Library-side `check_trusted_root_freshness`
is now `pub`, but it adds no new attack surface — it only reads a parsed
struct.

However, several defense-in-depth issues are present:

1. A **TOCTOU window** exists between `load_trusted_root(src)` /
   `check_trusted_root_freshness` and `fs::copy(src, cache_path)`. The
   validated bytes and the copied bytes can diverge if `src` is swapped
   between validation and copy. For a maintainer-only POC flow against a
   user-owned source this is low-impact, but the doc comment claims
   "Validates... then writes it verbatim" — this is not strictly true
   under concurrent mutation.

2. **No release-asset freshness gate.** `release.yml` byte-asserts that
   the shipped `trusted_root.json` equals
   `crates/nono/tests/fixtures/trust-root-frozen.json`, but does NOT
   assert that the fixture is itself fresh (no equivalent of
   `check_trusted_root_freshness` in CI). A stale fixture accidentally
   committed will ship to users without any automated tripwire — the
   rotation cadence relies entirely on a maintainer remembering to refresh.
   The Phase 49 SPEC is explicit that this is a structural fix for
   stale-anchor failures; shipping a stale anchor as the recovery asset
   undermines that.

3. **PowerShell smoke script leaks env vars** into the caller's session
   when dot-sourced or run in-process (`$env:NONO_TEST_HOME`,
   `$env:XDG_CONFIG_HOME`, `$env:NONO_NO_UPDATE_CHECK` are set but never
   restored in `finally`). The Bash counterpart is process-isolated by
   construction; the PowerShell one is not.

4. **`refresh_trust_root_phase_index()` does not account for
   `from_file`.** It returns a value that is correct only when
   `refresh_trust_root` is the active flag. The integer that lands in the
   `[X/N]` header is correct in the mutually-exclusive case, but if
   defense-in-depth ever fails (e.g., a future field rename breaks the
   clap-mutex), the displayed index would be inconsistent. Compare with
   `protection_phase_index()` / `profiles_phase_index()`, which DO
   include `self.from_file.is_some()`.

5. **GitHub Actions template injection vector.** `${{ env.RELEASE_TAG }}`
   is interpolated directly into shell/pwsh `run:` blocks — for
   `workflow_dispatch`, the `tag` input is user-controlled. A maintainer
   passing `v1.0.0; rm -rf /` could trigger command injection in any of
   the inline scripts. This is a known GHA anti-pattern; the safer form
   uses `env:` mapping plus `$RELEASE_TAG` (bash) / `$env:RELEASE_TAG`
   (pwsh) to keep the value out of the templated text.

6. **Doc comment overclaims pipeline equivalence.** `SetupArgs.from_file`
   says the file is validated "via the same pipeline `nono trust verify`
   uses." `nono trust verify` goes through `load_production_trusted_root`
   (which reads the cache); `from_file_step` goes through
   `load_trusted_root` (which reads `src`). The trust-root-loading
   subpipeline is the same; the full verify pipeline is not. A POC user
   reading this comment to reason about coverage may overestimate it.

## Warnings

### WR-01: TOCTOU between trust-root validation and verbatim copy

**File:** `crates/nono-cli/src/setup.rs:902-927`
**Issue:** `from_file_step` reads `src` three times: once via
`load_trusted_root(src)` (parse), once via `check_trusted_root_freshness`
(which only sees the in-memory `&TrustedRoot`), and once via
`fs::copy(src, &cache_path)`. Between the first read and the third, an
attacker (or a careless maintainer with a script regenerating the file in
parallel) can swap `src` for a different file. The validated bytes and
the cached bytes can diverge. The cache then claims `Source: <src>` (the
D-49-B3 breadcrumb), but the bytes in cache are NOT what was validated.

Severity: WARNING. The maintainer is the attacker in this threat model,
so impact is limited — but the doc comment in `SetupArgs.from_file`
claims "writes it verbatim" after validation, which is not strictly true
under concurrent mutation. CLAUDE.md § Path Handling explicitly calls
out TOCTOU as a critical concern; the same principle applies to
file-content TOCTOU.

**Fix:** Read `src` once into memory, validate from the in-memory bytes,
then write the same bytes to the cache path. Concretely:

```rust
let bytes = std::fs::read(src).map_err(NonoError::Io)?;
let trusted_root = nono::trust::bundle::load_trusted_root_from_str(
    std::str::from_utf8(&bytes).map_err(|e| {
        NonoError::Setup(format!("non-UTF-8 trusted root at {}: {e}", src.display()))
    })?,
).map_err(|e| {
    NonoError::Setup(format!("invalid Sigstore trusted root at {}: {e}", src.display()))
})?;
nono::trust::bundle::check_trusted_root_freshness(&trusted_root, &cache_path)
    .map_err(/* ... */)?;
// Atomic write: temp file + rename for proper fail-closed semantics
let tmp = cache_path.with_extension("json.tmp");
std::fs::write(&tmp, &bytes).map_err(NonoError::Io)?;
std::fs::rename(&tmp, &cache_path).map_err(NonoError::Io)?;
```

The temp-file + rename pattern also strengthens D-49-B2 (no partial
cache file is ever observable, even with a SIGKILL between bytes).

---

### WR-02: Release workflow has no freshness gate on the bundled trust-root asset

**File:** `.github/workflows/release.yml:318-333`
**Issue:** The byte-identity assert is correct (src SHA = dst SHA), but
there is no equivalent of `check_trusted_root_freshness` against the
shipped JSON in CI. A maintainer who commits a stale
`trust-root-frozen.json` (i.e., one whose tlog `validFor.end` values are
all in the past) will pass CI, ship a release, and POC users following
the cookbook will run `nono setup --from-file` against the release asset
and hit the freshness gate — defeating the entire Phase 49 recovery path.
The Phase 49 SPEC is explicit that this flag is the structural fix for
stale-embedded-anchor failures; shipping a stale recovery asset
re-introduces the same failure mode at the asset-distribution layer.

**Fix:** Add a freshness assert step in the `release` job (or as a
separate `verify-fixture-freshness` job that the `release` job depends
on). It can be a small inline Rust binary invocation or a JSON parser
that decodes each `tlogs[].publicKey.validFor.end` and fails the build if
ALL ends are in the past. Concretely:

```yaml
- name: Verify trust-root fixture freshness
  run: |
    python3 - <<'EOF'
    import json, sys, datetime
    raw = open("crates/nono/tests/fixtures/trust-root-frozen.json").read()
    root = json.loads(raw)
    now = datetime.datetime.utcnow()
    active = False
    for tlog in root.get("tlogs", []):
        vf = tlog.get("publicKey", {}).get("validFor", {})
        end = vf.get("end")
        if not end:
            active = True
            break
        end_dt = datetime.datetime.fromisoformat(end.rstrip("Z"))
        if end_dt > now:
            active = True
            break
    if not active:
        print("ERROR: every tlog in trust-root-frozen.json has expired validFor.end", file=sys.stderr)
        sys.exit(1)
    print("trusted_root.json fixture freshness OK")
    EOF
```

The Phase 49 fixture-refresh cadence template can stay as the operator
SOP; the workflow gate ensures the cadence is mechanically enforced.

---

### WR-03: PowerShell smoke script does not restore env vars

**File:** `scripts/verify-trust-root-cached.ps1:38-40, 69-72`
**Issue:** The script assigns `$env:NONO_TEST_HOME`, `$env:XDG_CONFIG_HOME`,
`$env:NONO_NO_UPDATE_CHECK` inside `try { ... }` but `finally { ... }`
only removes the temp directory — it never restores or removes the env
vars. When the script is invoked as `.\scripts\verify-trust-root-cached.ps1 X`
inside an existing pwsh session (the documented invocation pattern, per
the SKILL/usage comment), these env vars leak into the caller's shell.
Subsequent commands in the same session run with `NONO_TEST_HOME`
pointing at a now-deleted directory — `nono trust verify`, `nono setup`,
etc. will mis-resolve their cache path.

CLAUDE.md § Coding Standards: "Tests that modify HOME, TMPDIR,
XDG_CONFIG_HOME, or other env vars must save and restore the original
value." The smoke script is not a Rust test, but the same invariant
applies because it runs in-process under PowerShell.

The Bash counterpart (`verify-trust-root-cached.sh`) is process-isolated
by construction (a subshell with `export`), so it doesn't have this
problem.

**Fix:** Capture prior values before `try`, restore in `finally`:

```powershell
$prevTestHome = $env:NONO_TEST_HOME
$prevXdgHome = $env:XDG_CONFIG_HOME
$prevNoUpdate = $env:NONO_NO_UPDATE_CHECK
try {
    $env:NONO_TEST_HOME = $tmp.FullName
    $env:XDG_CONFIG_HOME = $tmp.FullName
    $env:NONO_NO_UPDATE_CHECK = '1'
    # ... existing body ...
}
finally {
    if ($null -eq $prevTestHome) { Remove-Item Env:NONO_TEST_HOME -ErrorAction SilentlyContinue }
    else { $env:NONO_TEST_HOME = $prevTestHome }
    if ($null -eq $prevXdgHome) { Remove-Item Env:XDG_CONFIG_HOME -ErrorAction SilentlyContinue }
    else { $env:XDG_CONFIG_HOME = $prevXdgHome }
    if ($null -eq $prevNoUpdate) { Remove-Item Env:NONO_NO_UPDATE_CHECK -ErrorAction SilentlyContinue }
    else { $env:NONO_NO_UPDATE_CHECK = $prevNoUpdate }
    # ... existing tmp cleanup ...
}
```

---

### WR-04: GitHub Actions expression injection via `${{ env.RELEASE_TAG }}` in run blocks

**File:** `.github/workflows/release.yml` (multiple lines: 75, 79, 83, 97,
107, 116, 149, 160, 166, 181-188, 201-204, 222-223, 233, 257-260, 275-285,
350-363)
**Issue:** `RELEASE_TAG` is sourced from `github.event.inputs.tag ||
github.ref_name`. For `workflow_dispatch`, the `tag` input is operator-
controlled text. Each `${{ env.RELEASE_TAG }}` interpolation in a `run:`
block is template-expanded into the shell text BEFORE the shell parses
it — so a malicious or accidentally-malformed value like
`v1.0.0"; rm -rf $HOME; echo "` becomes literal shell text. This is the
canonical GHA injection vector documented at
https://securitylab.github.com/research/github-actions-untrusted-input/.

Severity: WARNING (not BLOCKER) because:
- `workflow_dispatch` is gated by repo write permission (maintainers
  only).
- Push-tag triggers constrain `RELEASE_TAG` via the `'v*'` tag pattern,
  which doesn't fully sanitize but does narrow the input space.

Still, the pattern violates CLAUDE.md § Fail Secure ("explicit over
implicit") and would survive into operator-onboarding milestones where
non-core contributors might gain `workflow_dispatch` rights.

**Fix:** Map `RELEASE_TAG` to an `env:` block on the step, then reference
it as a real shell variable:

```yaml
- name: Build .deb (x86_64)
  if: matrix.target == 'x86_64-unknown-linux-gnu'
  env:
    RELEASE_TAG: ${{ env.RELEASE_TAG }}
  run: |
    VERSION="${RELEASE_TAG#v}"
    cd crates/nono-cli
    cargo deb --deb-version "$VERSION"
```

Apply uniformly to every `run:` block that currently interpolates
`${{ env.RELEASE_TAG }}` or `${{ matrix.target }}`.

---

### WR-05: `refresh_trust_root_phase_index()` does not account for `from_file`

**File:** `crates/nono-cli/src/setup.rs:803-818`
**Issue:** `refresh_trust_root_phase_index` is called from BOTH
`refresh_trust_root_step` (line 836) AND `from_file_step` (line 896), but
the function name implies it only models the refresh-trust-root slot.
Its body returns `3` (non-Windows) or `3 + WFP-action-count` (Windows),
without adding `usize::from(self.from_file.is_some())` or
`usize::from(self.refresh_trust_root)`. This currently produces the
correct value ONLY because the slot is shared (clap-mutex enforces
mutual exclusion) and the index lands at the same position as the
trust-root step in `total_phases()`.

The neighboring functions (`protection_phase_index`, `profiles_phase_index`)
DO use `(self.refresh_trust_root || self.from_file.is_some())` to model
the shared-slot semantics explicitly. The naming asymmetry is a latent
trap: if `from_file_step` is ever called WITHOUT the clap-mutex (e.g., a
unit test that constructs `SetupRunner` directly), or if a future change
splits the slot into two, this function's hardcoded `3` would silently
produce a wrong header. The function is also misnamed for its actual
role.

**Fix:** Rename to `trust_root_phase_index` (or
`trust_root_step_phase_index`) and document the shared-slot invariant in
the doc-comment. The body can remain as-is, or for symmetry with the
neighbors, explicitly add the marker:

```rust
/// Phase-index slot for the shared trust-root step.
///
/// Both `--refresh-trust-root` and `--from-file` land in this slot per
/// the clap-mutex contract (`conflicts_with = "refresh_trust_root"`).
/// If the mutex is ever relaxed, this function MUST be updated to
/// reflect both flags consuming distinct slots.
fn trust_root_phase_index(&self) -> usize {
    #[cfg(target_os = "windows")]
    if !self.check_only {
        let mut index = 3
            + usize::from(self.register_wfp_service)
            + usize::from(self.install_wfp_service)
            + usize::from(self.install_wfp_driver)
            + usize::from(self.start_wfp_driver)
            + usize::from(self.start_wfp_service);
        if self.any_windows_wfp_action_requested() {
            index += 1;
        }
        return index;
    }
    3
}
```

---

### WR-06: Doc comment overclaims pipeline equivalence with `nono trust verify`

**File:** `crates/nono-cli/src/cli.rs:2370-2378` and
`crates/nono-cli/src/setup.rs:870-880`
**Issue:** The `SetupArgs.from_file` doc comment says: "Validates the
file via the same pipeline `nono trust verify` uses (`TrustedRoot::from_file`
parse + tlog freshness gate)." `nono trust verify` actually goes through
`nono::trust::load_production_trusted_root()` (which reads the cache),
not `nono::trust::bundle::load_trusted_root(src)`. The trust-root-loading
subpipeline (parse + freshness) is equivalent; the full verify pipeline
(Fulcio CA validation, Rekor inclusion proof, ECDSA signature, in-toto
subject digest match, policy publisher match) is NOT exercised on the
`--from-file` path.

A POC user reading the help text might believe the validation is
maximally strong. The real coverage is "schema-parsable JSON that
deserializes into a `TrustedRoot` struct AND has at least one tlog with
a non-expired `validFor.end`." There is no cryptographic verification of
the bytes — an attacker who controls the file the user supplies to
`--from-file` can inject ANY syntactically-valid JSON with a fresh
expiry date.

Severity: WARNING. The threat model is "user is the attacker" because
they're explicitly opting into a local-file path, so this isn't a
privilege escalation. But the doc-comment claim invites users to trust
the file as much as they trust `verify`, which they shouldn't.

**Fix:** Rephrase the comment to reflect the actual scope:

```rust
/// Populate the cached Sigstore trusted root from a local JSON file
/// (skips network fetch).
///
/// Validates the file by parsing it as a `TrustedRoot` and checking
/// that at least one tlog `validFor.end` is in the future. NOTE: this
/// is a SUBSET of `nono trust verify` — there is no cryptographic
/// verification of the file's authenticity. Use this flag only with
/// `trusted_root.json` obtained from a trusted source (the official
/// GitHub Release asset, covered by SHA256SUMS.txt).
```

The handoff doc (`docs/cli/development/windows-poc-handoff.mdx:208-223`)
correctly directs users to the release-asset path covered by
`SHA256SUMS.txt`; the cli.rs doc comment should match that scoping.

---

### WR-07: Documented `Invoke-WebRequest` fallback path bypasses validation entirely

**File:** `docs/cli/development/windows-poc-handoff.mdx:225-244`
**Issue:** The "Fallback path — direct `Invoke-WebRequest` into the
cache directory" block instructs operators to download the frozen
fixture from `raw.githubusercontent.com` directly into
`$env:USERPROFILE\.nono\trust-root\trusted_root.json`, bypassing
`nono setup --from-file` entirely. This means:

1. No `check_trusted_root_freshness` gate runs before the file lands in
   the cache.
2. No parse-validation step runs — a corrupted download (truncated
   HTTPS response, MITM-altered bytes if `-UseBasicParsing` is used on a
   stale-TLS host) lands in the cache as-is.
3. The user's subsequent `nono trust verify` invocation surfaces a parse
   error from deep in `sigstore-verify`, with no operator-actionable
   recovery hint pointing back at the bad download.

The fallback was designed to handle "cannot reach the GitHub Releases
page" but instructs users to reach `raw.githubusercontent.com`, which
has the SAME availability characteristics as Releases. The fallback path
therefore covers a narrower threat model than the docs suggest, while
weakening the safety properties of the primary `--from-file` path.

**Fix:** Either:
- (a) Remove the fallback and direct users to `nono setup --from-file`
  exclusively (after manually copying the file by whatever means).
- (b) Rewrite the fallback to: `Invoke-WebRequest` to a temp file, then
  run `nono setup --from-file <temp>`. The temp-file detour preserves
  the freshness gate and the parse validation.

Option (b) is preferred — concretely:

```powershell
$tmpFile = Join-Path $env:TEMP ("trusted_root-" + [Guid]::NewGuid().ToString("N") + ".json")
Invoke-WebRequest -UseBasicParsing `
  -Uri "https://raw.githubusercontent.com/oscarmackjr-twg/nono/main/crates/nono/tests/fixtures/trust-root-frozen.json" `
  -OutFile $tmpFile
nono setup --from-file $tmpFile
Remove-Item -LiteralPath $tmpFile -Force
```

This keeps the fail-closed contract on the only documented offline
recovery path.

---

## Info

### IN-01: `from_file_step` uses `&self` only for phase-index counters

**File:** `crates/nono-cli/src/setup.rs:887-936`
**Issue:** The `#[allow(clippy::wrong_self_convention)]` is annotated as
needed because the method genuinely uses `&self` for
`refresh_trust_root_phase_index()` / `total_phases()`. This is fine but
worth noting: if `refresh_trust_root_phase_index` is renamed per WR-05,
the comment block at lines 881-887 needs to be updated to match.

**Fix:** Update the comment block when WR-05 is addressed.

---

### IN-02: `from_file_step` `println!` calls precede the validation

**File:** `crates/nono-cli/src/setup.rs:894-898, 902-907`
**Issue:** The header line `"[X/N] Loading Sigstore trusted root from
file..."` is printed BEFORE the parse + freshness validation runs. If
validation fails, the user sees the "Loading..." header followed by an
error — slightly confusing UX. The `refresh_trust_root_step` has the
same pattern (line 834-838), so this is consistent. Minor style note
only.

**Fix:** Optional — move the `println!` after successful validation, or
make the header reflect the in-progress phase explicitly ("[X/N]
Validating Sigstore trusted root from file..." and then a separate
"  * Loaded and cached at..." line on success).

---

### IN-03: Smoke scripts execute `nono` from `$PATH` without provenance check

**File:** `scripts/verify-trust-root-cached.sh:34` and
`scripts/verify-trust-root-cached.ps1:43`
**Issue:** Both scripts invoke bare `nono` from `$PATH`. A maintainer
running the smoke against a candidate fixture, but with a tampered
`nono` binary earlier in `$PATH`, would get false-positive results. This
is the standard maintainer-machine threat model (out of scope for the
POC), but the script docstring claims "Pre-commit gate for rotation
template" — pre-commit gates that depend on the binary they're testing
have a circular trust dependency.

**Fix:** Optional — document the assumption ("assumes `nono` on `$PATH`
is the binary you want to test") or accept a `-NonoBinary` parameter to
override.

---

### IN-04: `--from-file` accepts any `PathBuf` without scheme/format checks

**File:** `crates/nono-cli/src/cli.rs:2378-2384`
**Issue:** The `from_file` arg has `value_name = "PATH"` but no
`value_parser` to validate the path format (absolute vs. relative,
extension, file vs. directory). Errors are deferred to the runtime in
`from_file_step`. This is standard clap practice for path args, but the
error message at `load_trusted_root` failure is a generic "invalid
Sigstore trusted root at <path>: <inner>" — for the common case of "you
pointed at a directory" or "you mistyped the path," it surfaces a
file-format error rather than the file-not-found / not-a-file
diagnostic.

**Fix:** Optional — add a `value_parser` that validates the path is an
existing file before reaching `from_file_step`. The current behavior is
correct (fail-closed); only the diagnostic quality could improve.

---

### IN-05: `release.yml` uses unpinned `cargo install cross` and `cargo install cargo-deb`

**File:** `.github/workflows/release.yml:71, 102`
**Issue:** Both `cargo install cross` and `cargo install cargo-deb` are
unpinned. A compromised crates.io publisher key on either crate would
inject malicious code into the release build chain. This is preexisting,
not Phase 49-specific, but worth flagging since the release workflow
ships signed binaries.

**Fix:** Pin both:
```yaml
- name: Install cross (Linux ARM64)
  if: matrix.target == 'aarch64-unknown-linux-gnu'
  run: cargo install cross --locked --version <pinned>
- name: Install cargo-deb
  if: runner.os == 'Linux' && ...
  run: cargo install cargo-deb --locked --version <pinned>
```

---

### IN-06: Integration test `from_file_phase_index_uses_shared_slot` has weak assertion

**File:** `crates/nono-cli/tests/setup_trust_root.rs:219-252`
**Issue:** The test ends with a tolerant assertion ("expected `[X/N]
Loading...` header (single shared phase-index slot)") that only verifies
the header LINE shape, not that the X value equals what
`--refresh-trust-root` would produce. The doc-comment for the test
explicitly says "The header MUST share the same X with the
--refresh-trust-root path," but no assertion compares against the
refresh-path's actual X.

The test as written would pass even if `from_file_step` printed
`[7/4] Loading...` (off-by-one in either direction) — only a header in
the shape `[anything/anything]` is required.

**Fix:** Run a parallel `--refresh-trust-root` invocation in the same
test (or extract the expected X from `total_phases` + the constructor
fields) and assert string equality of the `[X/...]` prefix. Skip on
networkless CI by gating the refresh-path test on `#[ignore]` and
asserting only on header literal value (e.g., expect `[3/4]` based on
the known field combination).

---

### IN-07: TestHomeGuard `clippy::disallowed_methods` allow is broad

**File:** `crates/nono/src/trust/bundle.rs:1187-1213`
**Issue:** `TestHomeGuard` annotates both `impl` blocks with
`#[allow(clippy::disallowed_methods)]` to permit `std::env::set_var` /
`remove_var`. This is the right escape hatch for the test-mutex pattern,
but the allow scope covers entire impl blocks (including methods that
don't touch env). A future contributor adding an unrelated method to the
impl could accidentally inherit the relaxed lint.

**Fix:** Optional — narrow the allow to per-method:
```rust
impl TestHomeGuard {
    fn set(val: &str) -> Self {
        let _lock = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let prev = std::env::var("NONO_TEST_HOME").ok();
        #[allow(clippy::disallowed_methods)]
        std::env::set_var("NONO_TEST_HOME", val);
        Self { _lock, prev }
    }
}
```

The `crates/nono-cli/src/test_env.rs::EnvVarGuard` pattern (referenced
by the existing comment) does the same.

---

_Reviewed: 2026-05-21T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
