//! Linux seccomp-notify supervisor boundary.
//!
//! Threat model:
//! - The child process is sandboxed but untrusted.
//! - All seccomp notifications must be fail-closed on parse/validation errors.
//! - Path opens performed by the supervisor must re-validate policy boundaries.
//! - Security boundary: the supervisor's `open_path_for_access()` + `inject_fd()`
//!   is authoritative. `notif_id_valid()` only proves notification liveness.

use super::*;

/// Token-bucket rate limiter for supervisor expansion requests.
///
/// Prevents a compromised agent from flooding the terminal with approval prompts.
/// Defaults to 10 requests/second with a burst of 5.
pub(super) struct RateLimiter {
    /// Maximum tokens (burst capacity)
    capacity: u32,
    /// Current available tokens
    tokens: u32,
    /// Tokens added per second
    rate: u32,
    /// Last token refill time
    last_refill: std::time::Instant,
}

impl RateLimiter {
    pub(super) fn new(rate: u32, burst: u32) -> Self {
        Self {
            capacity: burst,
            tokens: burst,
            rate,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Try to consume one token. Returns true if allowed, false if rate limited.
    pub(super) fn try_acquire(&mut self) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        // Refill tokens based on elapsed time
        let new_tokens = (elapsed.as_millis() as u64)
            .saturating_mul(self.rate as u64)
            .saturating_div(1000);
        if new_tokens > 0 {
            self.tokens = self.capacity.min(
                self.tokens
                    .saturating_add(u32::try_from(new_tokens).unwrap_or(u32::MAX)),
            );
            self.last_refill = now;
        }

        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Handle a seccomp notification on Linux.
///
/// Flow:
/// 1. Receive notification (blocking recv from kernel)
/// 2. Read path from child's /proc/PID/mem
/// 3. TOCTOU check: verify notification still valid
/// 4. Check never_grant -> deny (BEFORE initial-set fast-path)
/// 5. Fast-path: if path is in initial set, open + inject fd immediately
/// 6. Rate limit check -> deny if exceeded
/// 7. Delegate to approval backend
/// 8. Second TOCTOU check before inject/deny
/// 9. If approved: open path + inject fd. If denied: deny notification.
///
/// TOCTOU boundary note:
/// - The child controls userspace pointers until syscall completion.
/// - We treat notification ID validation as a liveness guard only.
/// - Authorization is bound to the file descriptor opened by the supervisor.
///
/// The initial_caps parameter contains (path, is_file) tuples:
/// - For files (is_file=true): only exact path matches are allowed
/// - For directories (is_file=false): subpath matches via starts_with are allowed
pub(super) fn handle_seccomp_notification(
    notify_fd: std::os::fd::RawFd,
    child: Pid,
    config: &SupervisorConfig<'_>,
    initial_caps: &[(std::path::PathBuf, bool)],
    rate_limiter: &mut RateLimiter,
    denials: &mut Vec<DenialRecord>,
) -> Result<()> {
    use nono::sandbox::{
        classify_access_from_flags, deny_notif, inject_fd, notif_id_valid, read_notif_path,
        read_open_how, recv_notif, validate_openat2_size, SYS_OPENAT, SYS_OPENAT2,
    };

    // 1. Receive the notification
    let notif = recv_notif(notify_fd)?;

    // 2. Read the path from the child's memory (args[1] = pathname for openat/openat2)
    let path = match read_notif_path(notif.pid, notif.data.args[1]) {
        Ok(p) => p,
        Err(e) => {
            debug!("Failed to read path from seccomp notification: {}", e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // 3. First TOCTOU check: verify notification still valid
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Seccomp notification expired (first TOCTOU check)");
        return Ok(());
    }

    // Determine access mode from open flags. The two syscalls have different layouts:
    //   - openat(dirfd, pathname, flags, mode): args[2] is the flags integer
    //   - openat2(dirfd, pathname, how, size): args[2] is a pointer to struct open_how
    let access = match notif.data.nr {
        SYS_OPENAT => {
            // openat: args[2] is the flags integer directly
            classify_access_from_flags(notif.data.args[2] as i32)
        }
        SYS_OPENAT2 => {
            // openat2: args[2] is a pointer to struct open_how, args[3] is the size
            let how_size = notif.data.args[3] as usize;
            if !validate_openat2_size(how_size) {
                debug!(
                    "openat2 size {} outside accepted range, denying malformed request",
                    how_size
                );
                let _ = deny_notif(notify_fd, notif.id);
                return Ok(());
            }

            match read_open_how(notif.pid, notif.data.args[2]) {
                Ok(open_how) => classify_access_from_flags(open_how.flags as i32),
                Err(e) => {
                    // Fail closed: deny when flags cannot be determined
                    warn!("Failed to read open_how struct for openat2, denying: {}", e);
                    let _ = deny_notif(notify_fd, notif.id);
                    return Ok(());
                }
            }
        }
        other => {
            // Unexpected syscall (shouldn't happen with our BPF filter)
            warn!("Unexpected syscall {} in seccomp handler, denying", other);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    let canonicalized = std::fs::canonicalize(&path).unwrap_or_else(|_| path.clone());

    // 4. Check never_grant BEFORE initial-set fast-path.
    let never_grant_check = config.never_grant.check(&canonicalized);
    if !never_grant_check.is_blocked() {
        let never_grant_original = config.never_grant.check(&path);
        if never_grant_original.is_blocked() {
            debug!(
                "Seccomp: path {} (via {}) blocked by never_grant",
                canonicalized.display(),
                path.display()
            );
            record_denial(
                denials,
                DenialRecord {
                    path: path.clone(),
                    access,
                    reason: DenialReason::PolicyBlocked,
                },
            );
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    } else {
        debug!(
            "Seccomp: path {} blocked by never_grant",
            canonicalized.display()
        );
        record_denial(
            denials,
            DenialRecord {
                path: canonicalized.clone(),
                access,
                reason: DenialReason::PolicyBlocked,
            },
        );
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    }

    // 5. Fast-path: check if path is in the initial capability set.
    // File capabilities require exact match; directory capabilities allow subpaths.
    let in_initial_set = initial_caps.iter().any(|(cap_path, is_file)| {
        if *is_file {
            // File capability: exact match only
            canonicalized == *cap_path
        } else {
            // Directory capability: subpath match
            canonicalized.starts_with(cap_path)
        }
    });

    if in_initial_set {
        match open_path_for_access(&canonicalized, &access, config.never_grant) {
            Ok(file) => {
                if notif_id_valid(notify_fd, notif.id)? {
                    inject_fd(notify_fd, notif.id, file.as_raw_fd())?;
                }
            }
            Err(e) => {
                debug!("Failed to open initial-set path {}: {}", path.display(), e);
                let _ = deny_notif(notify_fd, notif.id);
            }
        }
        return Ok(());
    }

    // 6. Rate limit check
    if !rate_limiter.try_acquire() {
        debug!("Rate limited seccomp notification for {}", path.display());
        record_denial(
            denials,
            DenialRecord {
                path: path.clone(),
                access,
                reason: DenialReason::RateLimited,
            },
        );
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    }

    // 7. Delegate to approval backend
    let request = nono::supervisor::CapabilityRequest {
        request_id: format!("seccomp-{}", unique_request_id()),
        path: path.clone(),
        access,
        reason: Some("Sandbox intercepted file operation (seccomp-notify)".to_string()),
        child_pid: child.as_raw() as u32,
        session_id: config.session_id.to_string(),
    };

    let decision = match config.approval_backend.request_capability(&request) {
        Ok(d) => {
            if d.is_denied() {
                record_denial(
                    denials,
                    DenialRecord {
                        path: path.clone(),
                        access,
                        reason: DenialReason::UserDenied,
                    },
                );
            }
            d
        }
        Err(e) => {
            warn!("Approval backend error for seccomp notification: {}", e);
            record_denial(
                denials,
                DenialRecord {
                    path: path.clone(),
                    access,
                    reason: DenialReason::BackendError,
                },
            );
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // 8. Second TOCTOU check before acting on the decision
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Seccomp notification expired (second TOCTOU check)");
        return Ok(());
    }

    // 9. Act on the decision
    if decision.is_granted() {
        match open_path_for_access(&canonicalized, &access, config.never_grant) {
            Ok(file) => {
                inject_fd(notify_fd, notif.id, file.as_raw_fd())?;
            }
            Err(e) => {
                warn!(
                    "Failed to open approved path {}: {}",
                    canonicalized.display(),
                    e
                );
                let _ = deny_notif(notify_fd, notif.id);
            }
        }
    } else {
        let _ = deny_notif(notify_fd, notif.id);
    }

    Ok(())
}

/// Check if a path matches any capability in the initial set.
///
/// - File capabilities (is_file=true): require exact path match
/// - Directory capabilities (is_file=false): allow subpath matches via starts_with
///
/// This is the same logic used in the fast-path, extracted for testing.
#[cfg(test)]
fn path_matches_initial_caps(
    path: &std::path::Path,
    initial_caps: &[(std::path::PathBuf, bool)],
) -> bool {
    initial_caps.iter().any(|(cap_path, is_file)| {
        if *is_file {
            path == cap_path
        } else {
            path.starts_with(cap_path)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_rate_limiter_allows_burst() {
        let mut limiter = RateLimiter::new(10, 5);
        for _ in 0..5 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_rate_limiter_refills_over_time() {
        let mut limiter = RateLimiter::new(10, 3);
        for _ in 0..3 {
            assert!(limiter.try_acquire());
        }
        assert!(!limiter.try_acquire());
        limiter.last_refill -= std::time::Duration::from_millis(500);
        assert!(limiter.try_acquire());
    }

    #[test]
    fn test_file_capability_exact_match_only() {
        let caps = vec![(PathBuf::from("/home/user/config.json"), true)];

        // Exact match should succeed
        assert!(path_matches_initial_caps(
            &PathBuf::from("/home/user/config.json"),
            &caps
        ));

        // Subpath should NOT match for file capability
        assert!(!path_matches_initial_caps(
            &PathBuf::from("/home/user/config.json/subpath"),
            &caps
        ));

        // Different file should not match
        assert!(!path_matches_initial_caps(
            &PathBuf::from("/home/user/other.json"),
            &caps
        ));
    }

    #[test]
    fn test_directory_capability_allows_subpaths() {
        let caps = vec![(PathBuf::from("/home/user/project"), false)];

        // Exact match should succeed
        assert!(path_matches_initial_caps(
            &PathBuf::from("/home/user/project"),
            &caps
        ));

        // Subpath should match for directory capability
        assert!(path_matches_initial_caps(
            &PathBuf::from("/home/user/project/src/main.rs"),
            &caps
        ));

        // Sibling directory should not match
        assert!(!path_matches_initial_caps(
            &PathBuf::from("/home/user/other"),
            &caps
        ));
    }

    #[test]
    fn test_file_capability_does_not_authorize_fake_subpath() {
        // Regression test: a file capability for "/foo/bar" must NOT
        // authorize access to "/foo/bar/subpath" - files don't have children.
        let caps = vec![(PathBuf::from("/foo/bar"), true)];

        assert!(path_matches_initial_caps(&PathBuf::from("/foo/bar"), &caps));
        assert!(!path_matches_initial_caps(
            &PathBuf::from("/foo/bar/subpath"),
            &caps
        ));
        assert!(!path_matches_initial_caps(
            &PathBuf::from("/foo/bar/deep/nested/path"),
            &caps
        ));
    }

    #[test]
    fn test_mixed_file_and_directory_capabilities() {
        let caps = vec![
            (PathBuf::from("/etc/passwd"), true),         // file
            (PathBuf::from("/home/user/project"), false), // directory
        ];

        // File capability: exact match only
        assert!(path_matches_initial_caps(
            &PathBuf::from("/etc/passwd"),
            &caps
        ));
        assert!(!path_matches_initial_caps(
            &PathBuf::from("/etc/passwd/fake"),
            &caps
        ));

        // Directory capability: subpaths allowed
        assert!(path_matches_initial_caps(
            &PathBuf::from("/home/user/project"),
            &caps
        ));
        assert!(path_matches_initial_caps(
            &PathBuf::from("/home/user/project/src/lib.rs"),
            &caps
        ));
    }
}
