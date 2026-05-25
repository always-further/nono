---
phase: 48-upst6-sync-execution
reviewed: 2026-05-25T00:00:00Z
depth: standard
files_reviewed: 17
files_reviewed_list:
  - crates/nono-cli/data/nono-profile.schema.json
  - crates/nono-cli/src/capability_ext.rs
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/network_policy.rs
  - crates/nono-cli/src/policy.rs
  - crates/nono-cli/src/profile_cmd.rs
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/src/pty_proxy.rs
  - crates/nono-cli/src/sandbox_state.rs
  - crates/nono-cli/tests/deny_overlap_run.rs
  - crates/nono-proxy/src/config.rs
  - crates/nono-proxy/src/credential.rs
  - crates/nono-proxy/src/route.rs
  - crates/nono-proxy/src/server.rs
  - crates/nono/src/capability.rs
  - crates/nono/src/sandbox/linux.rs
  - crates/nono/src/sandbox/macos.rs
findings:
  critical: 1
  warning: 4
  info: 1
  total: 6
status: issues_found
---

# Phase 48: Code Review Report

**Reviewed:** 2026-05-25
**Depth:** standard
**Files Reviewed:** 17
**Status:** issues_found

## Summary

This review covers the Phase 48 sync execution wave: startup-timeout hardening, profile shadowing detection, Linux policy polish, macOS grant restore, PTY musl portability, proxy credential format, and package manifest. The codebase is well-structured with correct path comparison usage (`Path::starts_with` throughout, not string `starts_with`), good credential redaction in `Debug` impls, and thorough test coverage for deny-overlap semantics.

One critical issue was identified: the `regex_escape_path` helper in `capability_ext.rs` does not escape the double-quote character `"`, which is the Seatbelt `#"..."` raw-string delimiter. A filesystem path containing a literal `"` (permitted by POSIX) would break out of the regex literal and potentially inject arbitrary Seatbelt sandbox rules.

Four warnings were found: a silent drop of env vars containing null bytes (credential env vars silently lost), use of raw `env::var("HOME")` instead of `validated_home()` in one code path, `create(true)` instead of `create_new(true)` for a temp file (TOCTOU exposure), and a signal-exit-code detection range that misses signals above 15.

---

## Critical Issues

### CR-01: `regex_escape_path` Does Not Escape `"` — Seatbelt Rule Injection

**File:** `crates/nono-cli/src/capability_ext.rs:440-452`

**Issue:** The `regex_escape_path` function, used exclusively to build Seatbelt `(allow file-write* (regex #"..."))` rules for atomic-write paths (line 419), does not escape the double-quote character `"`. The Seatbelt DSL uses `#"..."` as a raw-string regex delimiter: an unescaped `"` inside the literal terminates the regex early.

A filesystem path containing a literal `"` character (which POSIX permits) such as `/tmp/my"dir/file` would produce:

```
(allow file-write* (regex #"^/tmp/my"dir/file\.tmp\.[0-9]+\.[0-9]+$"))
```

The `"` after `my` closes the `#"` literal. The remaining `dir/file\.tmp\.[0-9]+\.[0-9]+$"))` is passed to the Seatbelt parser as a continuation of the profile. Depending on what follows in the profile, this could cause:
1. `sandbox_init()` to fail with a parse error (sandbox fails to apply — the process runs unsandboxed), or
2. Injection of a rule fragment that matches as a valid Seatbelt expression (e.g., if a carefully constructed directory name forms a syntactically valid allow rule).

The companion function in `crates/nono/src/sandbox/macos.rs` (`regex_escape_path_for_seatbelt`, line 337) correctly escapes `"` as `\"`. The `capability_ext.rs` version is a separate, incomplete implementation that did not inherit this fix.

**Fix:** Add `"` to the match arm in `regex_escape_path`, escaping it as `\"`:

```rust
#[cfg(target_os = "macos")]
fn regex_escape_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    for c in path.chars() {
        match c {
            '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$'
            | '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}
```

Additionally, paths containing control characters (newlines, nulls, tabs) should be rejected, consistent with the behaviour of `escape_seatbelt_path` in `policy.rs`.

---

## Warnings

### WR-01: Silent Drop of Env Vars Containing Null Bytes — Credential Vars Lost Without Error

**File:** `crates/nono-cli/src/exec_strategy.rs:662-664` (and 683-685)

**Issue:** When building the child process environment, any key-value pair that contains a null byte causes `CString::new` to return `Err`, which is silently discarded via `if let Ok(cstr) = ...`. This applies to both inherited environment variables (line 662) and user-specified env vars (line 683):

```rust
if let Ok(cstr) = CString::new(format!("{}={}", k, v)) {
    env_c.push(cstr);
}
// silently drops the variable if it contains \0
```

For credential env vars (injected by the proxy via `credential_env_vars`), a null byte in the token or value would silently omit the credential from the child's environment. The child then fails with a confusing authentication error rather than a clear "env var could not be set" diagnostic. For the `NONO_CAP_FILE` path (line 671), silent omission breaks `nono why --self` without any error.

**Fix:** Either reject null bytes with an explicit error, or at minimum emit a `warn!` when a var is dropped. For security-critical vars like `NONO_CAP_FILE`, failing closed is preferable:

```rust
match CString::new(format!("{}={}", k, v)) {
    Ok(cstr) => env_c.push(cstr),
    Err(_) => {
        warn!(
            "Dropping env var {} containing null byte (cannot be passed to execve)",
            k
        );
    }
}
```

For `NONO_CAP_FILE` specifically, return an error rather than silently omitting it.

---

### WR-02: `apply_macos_keychain_db_exception` Uses Raw `env::var("HOME")` Instead of Validated Home

**File:** `crates/nono-cli/src/policy.rs:733`

**Issue:** This function reads `HOME` via `std::env::var("HOME")` directly, without going through `config::validated_home()` or equivalent path validation. All other code in `policy.rs` that depends on `HOME` uses the validated accessor, which checks that the value is an absolute path (guarding against `HOME=relative` or `HOME=` injections). The raw `env::var` approach accepts any string — including relative paths, empty strings, or adversarially crafted values — as the root of keychain DB path construction:

```rust
let user_keychain_dbs = std::env::var("HOME").ok().map(|home| {
    [
        Path::new(&home).join("Library/Keychains/login.keychain-db"),
        // ...
    ]
});
```

If `HOME` is unset or invalid, `ok()` silently maps to `None`, which means user keychain paths are skipped. That is fail-safe. However, if `HOME` is set to a relative path (e.g., `HOME=..`), the constructed paths `../Library/Keychains/login.keychain-db` are relative and would never match an absolute capability path, so the exception would silently not apply. This is inconsistent behavior rather than an outright exploit, but it violates the project's "validate env vars before use" principle.

**Fix:** Use the validated home accessor used elsewhere in the codebase:

```rust
let user_keychain_dbs = crate::config::validated_home().ok().map(|home| {
    [
        home.join("Library/Keychains/login.keychain-db"),
        home.join("Library/Keychains/metadata.keychain-db"),
    ]
});
```

---

### WR-03: `atomic_write_file` Uses `create(true)` Not `create_new(true)` for Temp File

**File:** `crates/nono-cli/src/profile_cmd.rs:151-155`

**Issue:** The temp file used during atomic profile writes is opened with `create(true).truncate(true)`, not `create_new(true)`. The temp file name is deterministic: `.<filename>.tmp.<PID>`. If a previous invocation of `nono profile` crashed after creating this temp file but before renaming it, the next run silently overwrites it with `truncate(true)` rather than failing. This is a minor TOCTOU window: between when the name is chosen and when the file is opened, a symlink could be placed at that path to redirect the write.

The contrast with `sandbox_state.rs` (line 155) is notable: `write_to_file` explicitly uses `create_new(true)` with a comment explaining the security rationale ("prevents symlink attacks"). The same reasoning applies here.

**Fix:** Use `create_new(true)` and handle `AlreadyExists` explicitly by removing the stale temp file and retrying, or by appending a nonce to the temp filename:

```rust
let mut file = std::fs::OpenOptions::new()
    .write(true)
    .create_new(true)  // fail if temp already exists
    .open(&tmp_path)
    .map_err(|e| nono::NonoError::ProfileRead {
        path: tmp_path.clone(),
        source: e,
    })?;
```

If backward compatibility with crashed-run temp files is needed, remove the stale temp file first with an explicit `fs::remove_file` before opening with `create_new`.

---

### WR-04: Signal Exit-Code Range `(129..=143)` Only Covers Signals 1–15

**File:** `crates/nono-cli/src/exec_strategy.rs:1505`

**Issue:** The heuristic for detecting signal-caused exits checks whether the exit code is in the range 129–143, which corresponds to POSIX signals 1–15 (SIGKILL=9, SIGTERM=15, etc.). However, Linux supports real-time signals up to SIGRTMAX (typically 64) and platform-specific signals above 15. For example, SIGUSR1=10, SIGUSR2=12 are within range, but SIGURG=23, SIGXCPU=24, SIGVTALRM=26, and all real-time signals (SIGRTMIN+n) are above signal 15.

When the supervised child is terminated by signal 16 or higher, the `WaitStatus::Signaled` arm (line 1511) correctly computes `128 + sig as i32` and prints the "[nono] Session stopped." message. But if the exit code 144+ is somehow received via `WaitStatus::Exited` (e.g., from a shell wrapper that translates signal exits), the diagnostic message is not printed. The immediate impact is cosmetic (missing diagnostic banner), not a security issue.

**Fix:** Use the POSIX-portable constant `NSIG` or expand the range to cover all plausible signal-derived exit codes (typically 129–191 on Linux):

```rust
let by_signal = (129..=191).contains(&code);
```

Or more defensively, use the POSIX convention that any exit code > 128 from a signal-killed process:

```rust
let by_signal = code > 128;
```

Note: The `WaitStatus::Signaled` arm already handles the canonical case correctly. This fix only addresses the rare `WaitStatus::Exited` path with a signal-derived code.

---

## Info

### IN-01: `credential_key` Uppercased as Env Var Name Without Sanitization

**File:** `crates/nono-proxy/src/server.rs:161`

**Issue:** When `route.env_var` is not set, the env var name for the phantom token is derived by uppercasing `credential_key` verbatim:

```rust
let api_key_name = cred_key.to_uppercase();
vars.push((api_key_name, self.token.to_string()));
```

If `credential_key` contains characters that are invalid in POSIX env var names (e.g., `/` from a URI like `op://vault/item/field`, or `-` from `keyring://service/account`), the resulting env var name is invalid. Most shells and `execve` implementations accept arbitrary strings as env var names (they are just `KEY=VALUE` strings in the environment block), but SDK env var lookups like `std::env::var("OP://VAULT/ITEM/FIELD")` would never be found by any SDK. The `env_var` field was added precisely to address this (per comment: "required for URI manager refs"), and the comment on line 161 explicitly acknowledges the problem. The code path is therefore only a footgun for users who forget to set `env_var` for URI-format `credential_key` values.

**Fix:** At proxy startup (in `CredentialStore::load` or `RouteStore::load`), validate that any route without `env_var` has a `credential_key` that, when uppercased, produces a valid POSIX env var name (matching `[A-Z_][A-Z0-9_]*`). Reject at startup rather than silently producing an unusable env var.

---

_Reviewed: 2026-05-25_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
