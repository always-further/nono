---
phase: 43-upst5-sync-execution
reviewed: 2026-05-18T00:00:00Z
depth: standard
files_reviewed: 25
files_reviewed_list:
  - CHANGELOG.md
  - Cargo.toml
  - bindings/c/Cargo.toml
  - crates/nono-cli/Cargo.toml
  - crates/nono-cli/data/nono-profile.schema.json
  - crates/nono-cli/src/app_runtime.rs
  - crates/nono-cli/src/audit_attestation.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/cli_bootstrap.rs
  - crates/nono-cli/src/credential_runtime.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/pack_update_hint.rs
  - crates/nono-cli/src/package.rs
  - crates/nono-cli/src/package_cmd.rs
  - crates/nono-cli/src/platform.rs
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/src/registry_client.rs
  - crates/nono-cli/src/sandbox_prepare.rs
  - crates/nono-cli/src/session_commands_windows.rs
  - crates/nono-cli/tests/audit_attestation.rs
  - crates/nono-proxy/Cargo.toml
  - crates/nono-shell-broker/Cargo.toml
  - crates/nono/Cargo.toml
  - crates/nono/src/undo/snapshot.rs
findings:
  critical: 0
  warning: 6
  info: 5
  total: 11
status: issues_found
---

# Phase 43: Code Review Report

**Reviewed:** 2026-05-18T00:00:00Z
**Depth:** standard
**Files Reviewed:** 25
**Status:** issues_found

## Summary

Phase 43 absorbed upstream `v0.53.0..v0.54.0` via six plan executions
(MSRV bump 1.77→1.95, snapshot symlink fix, pack-mgmt CLI, release-ride,
platform detection foundation, Windows registry detection). The
security-critical core fix (`validate_restore_target` in
`crates/nono/src/undo/snapshot.rs`) is well-constructed: it uses
`Path::starts_with` (component-wise) and `fs::symlink_metadata` to
verify each parent component before any write, includes regression tests
for the two attack shapes, and the per-file gate runs before the
`create_dir_all` / `retrieve_to` / `set_permissions` sequence.

Unwrap-policy compliance is clean — every `.unwrap()` / `.expect()` in
the reviewed source files is inside `#[cfg(test)]` blocks. The new
`crates/nono-cli/src/platform.rs` adds no `unsafe` code (Windows
registry detection uses the `reg` subprocess + parser rather than
direct `windows-sys` FFI, avoiding the need for `SAFETY:` docs).

Remaining findings are split between **6 WARNINGS** (correctness bugs
in version comparison + REG_DWORD fallback, TOCTOU gap inherent to the
symlink validation, a UX regression on first-run synchronous pack-update
check, asymmetric ordering in `compare_versions`, and a false-positive
update hint for pre-release semver) and **5 INFO** items (non-atomic
state-file writes, redundant logic in `run_outdated`, etc.).

No CRITICAL findings.

## Warnings

### WR-01: `validate_restore_target` is best-effort against TOCTOU symlink swaps

**File:** `crates/nono/src/undo/snapshot.rs:595-687`
**Issue:** `validate_restore_target` walks each parent component with
`fs::symlink_metadata` to reject symlinks BEFORE the restore writes,
but between the check and the actual `fs::create_dir_all` /
`object_store.retrieve_to` / `fs::set_permissions` (lines 286-313)
there is a TOCTOU window. A local attacker who can write inside the
tracked tree (the threat model that motivated the fix in the first
place) can swap a directory for a symlink between validation and
write. The doc comment on the function does not flag this, and the
two new regression tests (`restore_rejects_symlinked_parent_directory`,
`restore_rejects_symlink_before_create_dir_all`) only exercise the
single-shot static case.

The phase plan correctly notes this is **inherent to a non-fd-based
approach** — closing the race would require `O_NOFOLLOW` / `openat()` /
fd-relative ops, which is a substantial refactor.

**Fix:** Document the residual TOCTOU window explicitly in the function
doc comment so future maintainers do not assume the validation is
race-free, and file a follow-up ticket to track a future fd-based hardening:

```rust
/// Validate the live filesystem path that restore will write through.
///
/// **Residual race window:** this check runs lexically against
/// `symlink_metadata` and is followed by `create_dir_all` / atomic
/// rename / `set_permissions` non-atomically. A local attacker with
/// write access inside the tracked tree CAN race the validation by
/// swapping a directory for a symlink between this function returning
/// `Ok(())` and the write. Full closure requires `O_NOFOLLOW` and
/// fd-relative ops; tracked as follow-up.
fn validate_restore_target(&self, path: &Path) -> Result<()> {
```

### WR-02: `parse_windows_registry_value` REG_DWORD fallback returns invalid raw hex on parse failure

**File:** `crates/nono-cli/src/platform.rs:146-169`
**Issue:** When a REG_DWORD value is present and starts with `0x` but the
hex body fails to parse (e.g., `0x` with empty body, `0xZZZ`, truncated
output), the code falls through to `return Some(value)` and returns the
raw string `"0xZZZ"` as if it were a decoded number. Downstream
`detect_windows_version` then renders this garbage into the version
string and feeds it into `compare_versions` (which parses each
dot-segment as `u64` and silently degrades to `Ordering::Less` on
parse failure — see WR-04).

```rust
if kind == "REG_DWORD" {
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        if let Ok(number) = u64::from_str_radix(hex, 16) {
            return Some(number.to_string());
        }
    }
}
return Some(value);   // <-- returns "0xZZZ" on malformed REG_DWORD
```

**Fix:** On REG_DWORD parse failure, return `None` to signal the value
is unusable rather than handing back invalid data:

```rust
if kind == "REG_DWORD" {
    if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok().map(|n| n.to_string());
    }
    // REG_DWORD without 0x prefix is malformed — bail rather than
    // returning a string that looks like a number but isn't.
    return None;
}
```

### WR-03: `is_newer` reports false update for installed semver pre-release versions

**File:** `crates/nono-cli/src/pack_update_hint.rs:290-304`
**Issue:** The `parse` closure splits on `.` and requires each of
`major`/`minor`/`patch` to parse as `u64`. For an installed version
like `"1.2.3-beta"`, the `patch` segment is `"3-beta"` which fails
`u64::parse`, so `parse(installed) == None`. Combined with the
`(None, Some(_)) => true` branch (commit `27c398ba` — "treat unparsable
installed as older"), this means:

- installed = `"1.2.3-beta"`, latest = `"1.2.3"` → `is_newer` returns
  `true` and the user sees a spurious "update available" hint, even
  though they are at the same numerical version (or even ahead, e.g.
  installed = `"2.0.0-rc1"` vs latest = `"1.9.0"`).

The same shape would surface for build-metadata semver
(`"1.2.3+build5"`) — the `+` breaks `u64` parse.

**Fix:** Strip semver pre-release / build-metadata suffixes before
parsing, OR treat unparsable-on-both-sides as "no hint" rather than
asymmetrically treating only-installed-unparsable as "older":

```rust
fn is_newer(installed: &str, latest: &str) -> bool {
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let s = s.strip_prefix('v').unwrap_or(s);
        // Strip pre-release / build metadata before splitting on '.'
        let core = s.split(['-', '+']).next().unwrap_or(s);
        let mut parts = core.splitn(3, '.');
        let major: u64 = parts.next()?.parse().ok()?;
        let minor: u64 = parts.next()?.parse().ok()?;
        let patch: u64 = parts.next()?.parse().ok()?;
        Some((major, minor, patch))
    };
    match (parse(installed), parse(latest)) {
        (Some(i), Some(l)) => l > i,
        // If either side is unparsable, suppress the hint rather
        // than false-positiving on pre-release installs.
        _ => false,
    }
}
```

(Note: if the original intent of `(None, Some(_)) => true` was to
handle truly legacy non-semver installed versions like git SHAs,
consider using the `semver` crate which the workspace already depends
on — `crates/nono-cli/Cargo.toml:71 semver = "1"`.)

### WR-04: `compare_versions` violates Ord symmetry on non-numeric segments

**File:** `crates/nono-cli/src/platform.rs:583-597`
**Issue:** The fallback arm for non-numeric segments returns
`Ordering::Less` unconditionally regardless of operand order:

```rust
let ordering = match (left_part.parse::<u64>(), right_part.parse::<u64>()) {
    (Ok(left_num), Ok(right_num)) => left_num.cmp(&right_num),
    _ if left_part == right_part => Ordering::Equal,
    _ => Ordering::Less,   // <-- not symmetric!
};
```

`compare_versions("a", "b") == Less` AND `compare_versions("b", "a") == Less`.
This violates `Ord`'s antisymmetry contract. Today the function is
only used inside `VersionConstraint::matches` where the conservative
result (predicates fail-closed when versions are unparsable) happens
to be defensible. But a future caller that calls this from a sort or
`.cmp()` will silently produce wrong orderings. The asymmetry is not
covered by any test (the existing `version_segments_compare_numerically_when_possible`
test only exercises one direction).

**Fix:** Make the comparison total by ordering non-numeric segments
lexicographically when they differ:

```rust
let ordering = match (left_part.parse::<u64>(), right_part.parse::<u64>()) {
    (Ok(left_num), Ok(right_num)) => left_num.cmp(&right_num),
    // Both unparseable: fall back to lexicographic comparison so
    // the result is symmetric. A mixed numeric/non-numeric pair
    // sorts non-numeric LESS (so "alpha" < "1") for fail-closed
    // version-predicate semantics.
    (Err(_), Err(_)) => left_part.cmp(right_part),
    (Ok(_), Err(_)) => Ordering::Greater,
    (Err(_), Ok(_)) => Ordering::Less,
};
```

Add a regression test asserting
`compare_versions("a", "b") == Less` ⇔ `compare_versions("b", "a") == Greater`.

### WR-05: First-run synchronous pack-update check adds up to ~5min startup latency

**File:** `crates/nono-cli/src/pack_update_hint.rs:84-99` (+ `sandbox_prepare.rs:108-112` call site)
**Issue:** When the pack-update-hint cache file does not exist (e.g.,
first `nono run` after install or CLI upgrade), `show_pack_update_hints`
calls `refresh_synchronous` which issues one HTTP request per pack in
the active extends chain. The `RegistryClient` is configured with
`timeout_global = 300s` (`registry_client.rs:17`). On a slow / dead
registry this means **`nono run` blocks for up to 5 minutes per pack
before launching the child process** — a stark regression in startup
latency, which CLAUDE.md explicitly flags as a constraint
("Performance: Zero startup latency must be maintained").

The synchronous path is only taken when the cache file is absent, so
the worst case is bounded to "first run only". But the call site is
inside `finalize_prepared_sandbox` (`sandbox_prepare.rs:111`) — after
capability collection and BEFORE the child exec — so the user-visible
TTFB hit is direct.

The `silent` flag suppresses the hint entirely (so scripted callers
are safe), but interactive first-run users will see the regression.

**Fix:** Either (a) cap the synchronous-first-run path with a shorter
per-request timeout (e.g. 2s) and skip silently on timeout, or
(b) drop the synchronous path entirely and live with a one-run lag
(matches the "background refresh" pattern used everywhere else in the
function). Option (b) is simpler and aligns with the rest of the file:

```rust
if !stale.is_empty() {
    // Always refresh in background — first-run users see no hint
    // until the second run, which is the same behavior as the
    // CLI's update-check mechanism. Avoids up-to-5min stalls when
    // the registry is unreachable.
    let shared = Arc::new(Mutex::new(state));
    refresh_in_background(stale, shared);
}
```

If keeping option (a), add a per-request `timeout_global` override:

```rust
fn refresh_synchronous(packs: &[(String, String)], state: &mut PackHintsState) {
    // Bound first-run synchronous check to 2s/pack so a dead
    // registry cannot stall nono run startup.
    const FIRST_RUN_TIMEOUT: Duration = Duration::from_secs(2);
    let client = RegistryClient::new_with_timeout(registry_url, FIRST_RUN_TIMEOUT);
    // ...
}
```

### WR-06: `parse_windows_registry_value` returns None for case-mismatched value names

**File:** `crates/nono-cli/src/platform.rs:146-169`
**Issue:** Registry value names are case-insensitive on Windows
(`reg query /v EditionID` succeeds even if the registry stores the
value as `EditionId`), but the output preserves the stored case.
`parse_windows_registry_value` does a case-sensitive equality check:

```rust
if parts.next() != Some(name) {
    continue;
}
```

If the stored name differs in case from the queried `name` constant
(e.g., the function is called with `"EditionID"` but the registry
stores `"EditionId"`), the loop never matches and the function
returns `None`. The Windows version string would then fall back to
`CurrentVersion`, which on Windows 10/11 always reports `"6.3"` —
silently masking the real platform detection.

**Fix:** Use case-insensitive comparison for the value name token:

```rust
let first = parts.next()?;
if !first.eq_ignore_ascii_case(name) {
    continue;
}
```

Add a regression test fixture with mixed-case stored name to lock
this in.

## Info

### IN-01: `pack_update_hint::save_state` writes JSON non-atomically

**File:** `crates/nono-cli/src/pack_update_hint.rs:263-274`
**Issue:** `save_state` uses `std::fs::write(&path, json)` directly,
not the atomic temp+rename pattern that `package::write_lockfile`
uses (`package.rs:373-377`). If the background refresh thread is
killed mid-write (process exits via `std::process::exit`), the JSON
file can be partially written and subsequent `load_state` calls
silently fall back to `PackHintsState::default()` via
`.ok().and_then(...).unwrap_or_default()`. Not a security issue —
the worst case is more-aggressive registry checking on the next run —
but inconsistent with the project's atomic-write discipline.
**Fix:** Mirror `write_lockfile`'s `tmp_path` + rename pattern.

### IN-02: `refresh_in_background` join handle is silently dropped

**File:** `crates/nono-cli/src/pack_update_hint.rs:183-218`
**Issue:** `let _ = thread::spawn(move || { ... })` discards the
`JoinHandle`, making the thread detached. If `nono` exits before the
HTTP request and `save_state` complete, the network request is killed
mid-flight and the cache may not be updated. Documented behavior, but
worth noting that there is no graceful-shutdown path.
**Fix:** Optional — file a follow-up to plumb a shutdown signal or
join-on-exit if observed in the wild.

### IN-03: `splitn(2, '/').collect()` accepts empty namespace / name

**File:** `crates/nono-cli/src/package_cmd.rs:341-346, 580-585`
**Issue:** `key.splitn(2, '/').collect::<Vec<_>>()` on string
`"namespace/"` yields `["namespace", ""]` (len 2, passes the
`!= 2` check). The function then constructs a `PackageRef` with
empty `name`, producing URLs like
`/api/v1/packages/namespace//status` that 404. Cosmetic; lockfile
keys should be validated on write so this branch should never fire,
but defense-in-depth would reject empty segments here too.
**Fix:** Add `|| parts[0].is_empty() || parts[1].is_empty()` to the
length check, with a `warning: skipping malformed lockfile key`
diagnostic.

### IN-04: Redundant terminal condition in `run_outdated`

**File:** `crates/nono-cli/src/package_cmd.rs:629-633`
**Issue:** The logic
```rust
let needs_attention = entries.iter().any(|e| e.status != "current" && e.status != "unknown");
if !needs_attention && entries.iter().all(|e| e.status == "current") {
```
double-evaluates the entries iterator. Behaviorally correct (the
combination intentionally distinguishes "all current" from "all
current-or-unknown"), but the conditions could be expressed more
clearly with one pass.
**Fix:** Either replace with a single classifier pass that returns
an enum, or add a comment explaining the asymmetry.

### IN-05: `parse_windows_registry_value` collapses multi-space values

**File:** `crates/nono-cli/src/platform.rs:153`
**Issue:** `parts.collect::<Vec<_>>().join(" ")` joins value tokens
with single spaces, dropping the original whitespace shape. A
Product Name like `"Windows 10   Pro"` (with tabs / multiple
spaces) would be normalized to `"Windows 10 Pro"`. Cosmetic only —
no security impact, and `reg query` output already uses tab-aligned
columns so the multi-space case is unlikely. Document or accept.

---

_Reviewed: 2026-05-18T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
