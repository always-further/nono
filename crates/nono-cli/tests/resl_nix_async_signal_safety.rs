//! Phase 25-03 / CR-01 regression: post-fork child branch must be async-signal-safe.
//!
//! The child branch of `execute_supervised` (between `Ok(ForkResult::Child)` and the
//! final `_exit(127)`) runs in a state where heap allocation is unsafe:
//! after `fork()` in a multi-threaded program, the child inherits whatever lock state
//! the parent's allocator held at the moment of `fork()`. If the parent thread held
//! the allocator mutex, the child inherits a locked mutex and any subsequent heap
//! allocation deadlocks.
//!
//! `format!()` allocates a `String` on the heap. So does any code path that goes
//! through `String`, `Vec::new()` followed by `push`, etc. The async-signal-safe
//! pattern is to use a pre-allocated `const MSG: &[u8]` static byte string and call
//! `libc::write` + `libc::_exit` directly — both are POSIX async-signal-safe.
//!
//! This test scans the source of `crates/nono-cli/src/exec_strategy.rs` and asserts:
//!   1. Within the lexical region of the `Ok(ForkResult::Child)` arm, there are zero
//!      `format!(` invocations.
//!   2. The child branch contains at least the expected number of `const MSG_*: &[u8]`
//!      static byte strings used for error reporting.
//!
//! This is a structural / static-analysis regression — it cannot detect runtime
//! deadlocks (those require a deliberate test of fork-while-allocator-locked, which
//! is platform-specific and inherently flaky), but it does detect the introduction
//! of any new `format!()` call into the child branch in code review long before
//! such a test would be possible.
//!
//! Located in the workspace tests because exec_strategy.rs is `#[cfg(unix)]` only,
//! but the source-text check works on any platform — we just read the file as text.

use std::path::PathBuf;

/// Read `crates/nono-cli/src/exec_strategy.rs` from the workspace.
fn read_exec_strategy() -> String {
    // CARGO_MANIFEST_DIR points at the nono-cli crate root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = PathBuf::from(manifest_dir)
        .join("src")
        .join("exec_strategy.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

/// Find the line range of the post-fork child arm by searching for the sentinel
/// comments `// CR-01-CHILD-ARM-START` and `// CR-01-CHILD-ARM-END`.
///
/// Returns `(start_line, end_line)` (1-indexed, inclusive) — the lines BETWEEN
/// the sentinels (not including the sentinel comments themselves).
///
/// Panics if either sentinel is missing — that indicates the production code
/// was refactored and the sentinels need to be re-placed.
///
/// This replaces the previous brace-counting + first-match-find approach
/// (WR-A + WR-B in 25-REVIEW-GAPS.md): brace counting ignored string literals
/// and block comments; first-match-find could be silently misaimed by a
/// future test-helper child arm added before line 844.
fn find_child_branch_lines(src: &str) -> (usize, usize) {
    const START_SENTINEL: &str = "CR-01-CHILD-ARM-START";
    const END_SENTINEL: &str = "CR-01-CHILD-ARM-END";

    let start_byte = src.find(START_SENTINEL).unwrap_or_else(|| {
        panic!(
            "expected `{START_SENTINEL}` sentinel in exec_strategy.rs — \
             production child arm is missing its scoping sentinel; \
             see 25-VERIFICATION.md CR-01-RESIDUAL fix"
        )
    });
    let end_byte = src.find(END_SENTINEL).unwrap_or_else(|| {
        panic!(
            "expected `{END_SENTINEL}` sentinel in exec_strategy.rs — \
             production child arm is missing its closing sentinel; \
             see 25-VERIFICATION.md CR-01-RESIDUAL fix"
        )
    });
    assert!(
        end_byte > start_byte,
        "CR-01-CHILD-ARM-END must appear after CR-01-CHILD-ARM-START in source order \
         (got start={start_byte}, end={end_byte})"
    );

    // Convert byte offsets to 1-indexed line numbers. The returned range covers
    // the lines BETWEEN the two sentinels (exclusive of the sentinel lines
    // themselves), so line-comment stripping in the caller does not eat the
    // sentinels' own contents.
    let start_line = src[..start_byte].matches('\n').count() + 1;
    let end_line = src[..end_byte].matches('\n').count() + 1;
    (start_line + 1, end_line - 1)
}

/// Return the body (everything between the opening `{` and matching closing `}`)
/// of a function whose signature begins with `fn_signature_prefix`. Used for
/// per-helper assertions (e.g. clear_close_on_exec) so the regression test can
/// reach beyond the lexical child arm region.
///
/// `fn_signature_prefix` should be a stable, unique substring of the function
/// signature line — e.g. `"fn clear_close_on_exec(fd: i32) -> std::io::Result<()>"`.
///
/// Panics if the signature is not found.
fn slice_function_body(src: &str, fn_signature_prefix: &str) -> String {
    let sig_byte = src.find(fn_signature_prefix).unwrap_or_else(|| {
        panic!(
            "expected function signature `{fn_signature_prefix}` in exec_strategy.rs — \
             if this helper was renamed or its signature changed, update the \
             strengthened CR-01-RESIDUAL test in resl_nix_async_signal_safety.rs"
        )
    });
    // Locate the opening `{` after the signature.
    let body_start = src[sig_byte..]
        .find('{')
        .map(|off| sig_byte + off)
        .expect("function signature without an opening brace");

    // Brace counting is safe here because we are scanning a *small, named function*
    // body, not an arbitrary match arm. The function signature is a stable anchor;
    // string-literal/comment fragility (WR-B's concern about the broader child arm)
    // is unlikely to materialize inside this single helper. If a future commit
    // introduces a `{` inside a string literal here, the test failure will be loud.
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    let mut end_byte = body_start;
    for (i, b) in bytes.iter().enumerate().skip(body_start) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end_byte = i;
                    break;
                }
            }
            _ => {}
        }
    }
    assert!(
        end_byte > body_start,
        "could not find matching `}}` for `{fn_signature_prefix}`"
    );
    src[body_start..=end_byte].to_string()
}

/// Extract the substring of `src` covering the lexical region `[start_line..=end_line]`
/// (1-indexed, inclusive).
fn slice_lines(src: &str, start_line: usize, end_line: usize) -> String {
    src.lines()
        .enumerate()
        .filter(|(i, _)| {
            let lineno = i + 1;
            lineno >= start_line && lineno <= end_line
        })
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n")
}

/// CR-01: zero `format!(` invocations inside the post-fork child branch.
#[test]
fn cr_01_no_format_macro_in_post_fork_child_branch() {
    let src = read_exec_strategy();
    let (start, end) = find_child_branch_lines(&src);
    let region = slice_lines(&src, start, end);

    // Strip line comments so a comment that mentions `format!(...)` (e.g. in a
    // SAFETY rationale or doc remark) doesn't false-positive the test.
    let stripped: String = region
        .lines()
        .map(|line| match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");

    let count = stripped.matches("format!(").count();
    assert_eq!(
        count, 0,
        "CR-01 regression: found {count} `format!(` invocation(s) in the post-fork \
         child branch of execute_supervised (lines {start}..={end} of \
         crates/nono-cli/src/exec_strategy.rs).\n\
         \n\
         The child branch runs in async-signal-unsafe context — `format!()` allocates \
         on the heap and can deadlock if the parent held the allocator mutex at fork() \
         time. Replace each `format!()` with a `const MSG_*: &[u8] = b\"...\\n\";` \
         static byte string written via `libc::write(libc::STDERR_FILENO, ...)`.\n\
         \n\
         See the already-correct chdir handler near the bottom of the child arm for \
         the reference pattern."
    );

    // CR-01-RESIDUAL: clear_close_on_exec is reachable from the post-fork child
    // arm (line 950 call site). Its body must not allocate. This per-helper
    // scan closes the call-graph gap that the lexical region scan above misses.
    // See 25-VERIFICATION.md CR-01-RESIDUAL gaps.missing block, option (b).
    let helper_body = slice_function_body(
        &src,
        "fn clear_close_on_exec(fd: i32) -> std::io::Result<()>",
    );
    // Strip line comments so SAFETY/doc remarks that mention `format!(...)`
    // do not false-positive.
    let helper_stripped: String = helper_body
        .lines()
        .map(|line| match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");
    let helper_format_count = helper_stripped.matches("format!(").count();
    assert_eq!(
        helper_format_count, 0,
        "CR-01-RESIDUAL regression: found {helper_format_count} `format!(` \
         invocation(s) inside `clear_close_on_exec` body. This helper is called \
         from the post-fork child arm of execute_supervised (line 950 call site), \
         so any heap allocation here re-opens the allocator-mutex-deadlock \
         primitive that CR-01 was supposed to eliminate.\n\
         \n\
         Replace `format!(...)` with `std::io::Error::last_os_error()` \
         (which captures errno into a stack-resident io::Error::Repr without \
         allocating). The function signature must remain `fn clear_close_on_exec(fd: i32) \
         -> std::io::Result<()>` so the call site discards the io::Error via \
         `if let Err(_e) = ...`.\n\
         \n\
         See 25-VERIFICATION.md gaps.missing block for the canonical fix."
    );
}

/// CR-01 / WR-02: at least 11 `const MSG_*: &[u8]` declarations in the file
/// (9 from CR-01 child-branch sites + 2 from WR-02 rlimit-failure handlers).
///
/// This is a structural assertion that the consts WERE introduced rather than the
/// `format!()` calls being silently removed without a replacement.
#[test]
fn cr_01_and_wr_02_const_msg_byte_strings_present() {
    let src = read_exec_strategy();
    // Match `const MSG_<NAME>: &[u8]` declarations (any uppercase suffix).
    let count = src
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            // Cheap check: starts with `const MSG_` and contains `: &[u8]`.
            t.starts_with("const MSG_") && t.contains(": &[u8]")
        })
        .count();
    assert!(
        count >= 11,
        "expected at least 11 `const MSG_*: &[u8]` declarations in exec_strategy.rs \
         (9 for CR-01 child-branch sites + 2 for WR-02 rlimit-failure handlers); \
         found {count}.\n\
         \n\
         Each `format!()` removed for CR-01 must be replaced with a named static \
         byte string declared immediately before the `unsafe` block that uses it. \
         See the plan 25-03 task action for the canonical names \
         (MSG_CGROUP, MSG_SOCK, MSG_SANDBOX_LINUX, MSG_SANDBOX_OTHER, \
         MSG_SECCOMP_SEND, MSG_SECCOMP_FAIL, MSG_PROXY_SEND, MSG_PROXY_FAIL, \
         MSG_DUMPABLE, MSG_RLIMIT_AS_FAIL, MSG_RLIMIT_NPROC_FAIL)."
    );
}

/// CR-02: `--timeout` in Direct mode must surface a `warn!` invocation that names
/// the limitation. The doc comment in `execute_direct` mentions the same phrase, so
/// the assertion targets the macro invocation specifically (`warn!(...)`).
#[test]
fn cr_02_direct_mode_timeout_emits_warn_macro() {
    let src = read_exec_strategy();
    let mut found_warn = false;
    let mut found_eprintln = false;
    // Walk the file with a small window so a multi-line warn!(...) call counts.
    let bytes = src.as_bytes();
    let needle_warn = b"warn!(";
    let needle_eprintln = b"eprintln!(";
    let mut i = 0usize;
    while i + needle_warn.len() < bytes.len() {
        if &bytes[i..i + needle_warn.len()] == needle_warn {
            // Look at the next ~200 bytes for `timeout` and `not enforced`.
            let end = (i + 400).min(bytes.len());
            let window = &src[i..end];
            if window.contains("timeout") && window.contains("not enforced") {
                found_warn = true;
            }
        }
        if i + needle_eprintln.len() < bytes.len()
            && &bytes[i..i + needle_eprintln.len()] == needle_eprintln
        {
            let end = (i + 400).min(bytes.len());
            let window = &src[i..end];
            if window.contains("--strategy supervised") {
                found_eprintln = true;
            }
        }
        i += 1;
    }
    assert!(
        found_warn,
        "CR-02 regression: expected a `warn!(...)` invocation in exec_strategy.rs \
         whose body mentions both `timeout` and `not enforced`. The doc comment \
         in execute_direct that mentions `--timeout is NOT enforced in Direct mode` \
         is plain text, not a macro invocation, and does not satisfy this check."
    );
    assert!(
        found_eprintln,
        "CR-02 regression: expected an `eprintln!(...)` invocation in exec_strategy.rs \
         whose body mentions `--strategy supervised`. The user-visible warning to \
         stderr must fire even when `RUST_LOG` is not set."
    );
}

/// WR-04: no `unwrap_or(child)` PID fallback inside the macOS watchdog spawn.
/// The replacement is a `match getpgid(...)` that returns `None` on `Err`.
#[test]
fn wr_04_no_pid_fallback_on_getpgid_failure() {
    let src = read_exec_strategy();
    assert!(
        !src.contains("unwrap_or(child)"),
        "WR-04 regression: found `unwrap_or(child)` in exec_strategy.rs. \
         Falling back to the child PID as the process group target is unsafe under \
         PID reuse — `kill(-child_pid, SIGKILL)` could target an unrelated process \
         group. Replace with a `match getpgid(Some(child)) {{ Ok(pgrp) => ..., \
         Err(e) => {{ warn!(...); None }} }}` and let the watchdog be skipped on Err."
    );
    assert!(
        src.contains("match getpgid("),
        "WR-04 regression: expected a `match getpgid(...)` arm in exec_strategy.rs \
         (replacing the `unwrap_or(child)` PID fallback)."
    );
}

/// WR-02: no silent `let _ = setrlimit(...)` discards in exec_strategy.rs.
#[test]
fn wr_02_no_silent_setrlimit_discards() {
    let src = read_exec_strategy();
    let count = src.matches("let _ = setrlimit").count();
    assert_eq!(
        count, 0,
        "WR-02 regression: found {count} silent `let _ = setrlimit(...)` discard(s) \
         in exec_strategy.rs. Each setrlimit failure in the post-fork child must be \
         fail-closed (`MSG_RLIMIT_*_FAIL` static + `_exit(126)`)."
    );
}
