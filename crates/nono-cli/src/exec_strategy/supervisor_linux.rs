//! Linux seccomp-notify supervisor boundary.
//!
//! Threat model:
//! - The child process is sandboxed but untrusted.
//! - All seccomp notifications must be fail-closed on parse/validation errors.
//! - Path opens performed by the supervisor must re-validate policy boundaries.
//! - Security boundary: the supervisor's `open_path_for_access()` + `inject_fd()`
//!   is authoritative. `notif_id_valid()` only proves notification liveness.
//! - Instruction files undergo trust verification with TOCTOU protection via
//!   digest re-check at fd open time.

use super::*;
use crate::trust_intercept::TrustInterceptor;
use nono::AccessMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InitialCapability {
    pub(super) path: std::path::PathBuf,
    pub(super) access: AccessMode,
    pub(super) is_file: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitialCapabilityMatch<'a> {
    Sufficient(&'a InitialCapability),
    Insufficient(&'a InitialCapability),
    None,
}

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
/// 4. Check protected nono state roots -> deny (BEFORE initial-set fast-path)
/// 5. Fast-path: if path is in initial set, open + inject fd immediately
/// 6. Rate limit check -> deny if exceeded
/// 7. Trust verification for instruction files (if trust_interceptor present)
/// 8. Delegate to approval backend
/// 9. Second TOCTOU check before inject/deny
/// 10. If approved: open path + inject fd (with TOCTOU digest re-check for
///     instruction files). If denied: deny notification.
///
/// TOCTOU boundary note:
/// - The child controls userspace pointers until syscall completion.
/// - We treat notification ID validation as a liveness guard only.
/// - Authorization is bound to the file descriptor opened by the supervisor.
/// - Instruction files undergo additional TOCTOU protection: the verified
///   digest is re-checked against the opened fd to detect races between
///   trust verification and file open.
///
/// The initial_caps parameter contains the static capabilities applied to the
/// sandbox, allowing the supervisor to distinguish "path not granted" from
/// "path granted, but only with a narrower access mode".
pub(super) fn handle_seccomp_notification(
    notify_fd: std::os::fd::RawFd,
    child: Pid,
    config: &SupervisorConfig<'_>,
    initial_caps: &[InitialCapability],
    rate_limiter: &mut RateLimiter,
    denials: &mut Vec<DenialRecord>,
    mut trust_interceptor: Option<&mut TrustInterceptor>,
) -> Result<()> {
    use nono::sandbox::{
        classify_access_from_flags, continue_notif, deny_notif, inject_fd, notif_id_valid,
        read_notif_path, read_open_how, recv_notif, resolve_notif_path, respond_notif_errno,
        validate_openat2_size, SYS_OPENAT, SYS_OPENAT2,
    };

    // 1. Receive the notification
    let notif = recv_notif(notify_fd)?;

    // 2. Read the path from the child's memory (args[1] = pathname for openat/openat2)
    //    Then resolve dirfd-relative paths using /proc/PID/fd/DIRFD or /proc/PID/cwd.
    let path = match read_notif_path(notif.pid, notif.data.args[1]) {
        Ok(raw_path) => {
            // args[0] is dirfd for both openat and openat2
            match resolve_notif_path(notif.pid, notif.data.args[0], &raw_path) {
                Ok(resolved) => resolved,
                Err(e) => {
                    debug!(
                        "Failed to resolve dirfd-relative path '{}': {}",
                        raw_path.display(),
                        e
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                    return Ok(());
                }
            }
        }
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

    let procfs_context = ProcfsAccessContext::new(child.as_raw() as u32, Some(notif.pid));
    let resolved_path = match resolve_procfs_path_for_child(&path, Some(procfs_context)) {
        Ok(resolved) => resolved,
        Err(e) => {
            debug!("Failed to resolve procfs path '{}': {}", path.display(), e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };
    let canonicalized =
        std::fs::canonicalize(&resolved_path).unwrap_or_else(|_| resolved_path.clone());

    // 4. Check protected roots BEFORE initial-set fast-path.
    let protected_root = crate::protected_paths::overlapping_protected_root(
        &canonicalized,
        false,
        config.protected_roots,
    )
    .or_else(|| {
        crate::protected_paths::overlapping_protected_root(
            &resolved_path,
            false,
            config.protected_roots,
        )
    });
    if let Some(protected_root) = protected_root {
        debug!(
            "Seccomp: path {} blocked by protected root {}",
            canonicalized.display(),
            protected_root.display()
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

    // 5. Fast-path: if the path is covered by the initial capability set and
    // the requested access mode is already granted, proceed immediately. If the
    // path matches but only with narrower access, record the denial here so the
    // footer can explain the near-miss precisely.
    match match_initial_capability(&canonicalized, access, initial_caps) {
        InitialCapabilityMatch::Insufficient(cap) => {
            debug!(
                "Seccomp: path {} matched initial capability {} but {} access was requested",
                canonicalized.display(),
                cap.path.display(),
                access,
            );
            record_denial(
                denials,
                DenialRecord {
                    path: canonicalized.clone(),
                    access,
                    reason: DenialReason::InsufficientAccess,
                },
            );
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
        InitialCapabilityMatch::Sufficient(_) => {
            if canonicalized.starts_with("/proc") {
                match open_path_for_access(
                    &path,
                    &access,
                    config.protected_roots,
                    None,
                    Some(procfs_context),
                ) {
                    Ok(file) => {
                        if notif_id_valid(notify_fd, notif.id)? {
                            if let Err(e) = inject_fd(notify_fd, notif.id, file.as_raw_fd()) {
                                debug!(
                                    "inject_fd failed for initial-set proc path {}: {}",
                                    path.display(),
                                    e
                                );
                                let _ = deny_notif(notify_fd, notif.id);
                            }
                        }
                    }
                    Err(e) => {
                        debug!(
                            "Failed to open initial-set proc path {}: {}",
                            path.display(),
                            e
                        );
                        if e.is_policy_blocked() {
                            record_denial(
                                denials,
                                DenialRecord {
                                    path: canonicalized.clone(),
                                    access,
                                    reason: DenialReason::PolicyBlocked,
                                },
                            );
                            let _ = deny_notif(notify_fd, notif.id);
                        } else {
                            let _ = respond_notif_errno(notify_fd, notif.id, e.errno());
                        }
                    }
                }
            } else if notif_id_valid(notify_fd, notif.id)? {
                if let Err(e) = continue_notif(notify_fd, notif.id) {
                    debug!(
                        "continue_notif failed for initial-set path {}: {}",
                        path.display(),
                        e
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                }
            }
            return Ok(());
        }
        InitialCapabilityMatch::None => {}
    }

    // Preserve native ENOENT/ENOTDIR behavior for nonexistent paths. Runtimes
    // frequently probe optional locations (e.g. Bun's /$bunfs assets) and
    // expect a normal "not found" result rather than a policy denial. This is
    // safe because Landlock will still block any path that appears after the
    // check but remains outside the initial allow-list.
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            if notif_id_valid(notify_fd, notif.id)? {
                if let Err(send_err) = continue_notif(notify_fd, notif.id) {
                    debug!(
                        "continue_notif failed for missing path {}: {}",
                        path.display(),
                        send_err
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                }
            }
            return Ok(());
        }
        Err(_) => {}
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

    // 7. Trust verification for instruction files (TOCTOU protection)
    // If the path is an instruction file, verify it and stash the digest
    // for re-verification at open time. Failed verification results in early denial.
    let verified_digest: Option<String> = if let Some(trust_result) = trust_interceptor
        .as_mut()
        .and_then(|ti| ti.check_path(&path))
    {
        match trust_result {
            Ok(verified) => {
                debug!(
                    "Seccomp: instruction file {} verified (publisher: {})",
                    path.display(),
                    verified.publisher,
                );
                Some(verified.digest)
            }
            Err(reason) => {
                // Instruction file failed trust verification — auto-deny
                debug!(
                    "Seccomp: instruction file {} failed trust verification: {}",
                    path.display(),
                    reason
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
        }
    } else {
        None
    };

    // 8. Delegate to approval backend (for both instruction and non-instruction files)
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

    // 9. Second TOCTOU check before acting on the decision
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Seccomp notification expired (second TOCTOU check)");
        return Ok(());
    }

    // 10. Act on the decision
    // Pass verified_digest to enable TOCTOU re-verification for instruction files
    if decision.is_granted() {
        match open_path_for_access(
            &path,
            &access,
            config.protected_roots,
            verified_digest.as_deref(),
            Some(procfs_context),
        ) {
            Ok(file) => {
                if let Err(e) = inject_fd(notify_fd, notif.id, file.as_raw_fd()) {
                    debug!(
                        "inject_fd failed for approved path {}: {}",
                        canonicalized.display(),
                        e
                    );
                    let _ = deny_notif(notify_fd, notif.id);
                }
            }
            Err(e) => {
                warn!(
                    "Failed to open approved path {}: {}",
                    canonicalized.display(),
                    e
                );
                if e.is_policy_blocked() {
                    let _ = deny_notif(notify_fd, notif.id);
                } else {
                    let _ = respond_notif_errno(notify_fd, notif.id, e.errno());
                }
            }
        }
    } else {
        let _ = deny_notif(notify_fd, notif.id);
    }

    Ok(())
}

/// Handle a seccomp notification for connect() or bind() syscalls.
///
/// This is the proxy-only fallback for kernels without Landlock AccessNet.
/// The BPF filter routes connect/bind to USER_NOTIF; this function reads
/// the sockaddr from the child's memory and allows or denies based on
/// the configured proxy port and bind ports.
///
/// For connect: allow only loopback + proxy port. Deny everything else.
/// For bind: allow only ports in the bind_ports list. Deny everything else.
///
/// Uses SECCOMP_USER_NOTIF_FLAG_CONTINUE on approval (safe for connect/bind
/// because the kernel has already copied sockaddr into kernel memory).
pub(super) fn handle_network_notification(
    notify_fd: std::os::fd::RawFd,
    config: &SupervisorConfig<'_>,
    rate_limiter: &mut RateLimiter,
) -> nono::error::Result<()> {
    use nono::sandbox::{
        continue_notif, deny_notif, notif_id_valid, read_notif_sockaddr, recv_notif,
        respond_notif_errno, SYS_BIND, SYS_CONNECT,
    };

    let notif = recv_notif(notify_fd)?;

    // Rate limit to prevent flooding
    if !rate_limiter.try_acquire() {
        debug!("Rate limited network seccomp notification, denying");
        let _ = deny_notif(notify_fd, notif.id);
        return Ok(());
    }

    // Read sockaddr from child's memory: args[1] = sockaddr*, args[2] = addrlen
    let sockaddr = match read_notif_sockaddr(notif.pid, notif.data.args[1], notif.data.args[2]) {
        Ok(info) => info,
        Err(e) => {
            debug!("Failed to read sockaddr from seccomp notification: {}", e);
            let _ = deny_notif(notify_fd, notif.id);
            return Ok(());
        }
    };

    // TOCTOU check
    if !notif_id_valid(notify_fd, notif.id)? {
        debug!("Network seccomp notification expired (TOCTOU check)");
        return Ok(());
    }

    let allowed = match notif.data.nr {
        SYS_CONNECT => {
            // Allow connect only to loopback + proxy port
            let port_match = sockaddr.port == config.proxy_port;
            if sockaddr.is_loopback && port_match {
                debug!(
                    "Proxy seccomp: allowing connect to loopback:{}",
                    sockaddr.port
                );
                true
            } else {
                debug!(
                    "Proxy seccomp: denying connect to family={} port={} loopback={}",
                    sockaddr.family, sockaddr.port, sockaddr.is_loopback
                );
                false
            }
        }
        SYS_BIND => {
            // Allow bind only on configured bind ports
            let port_allowed = config.proxy_bind_ports.contains(&sockaddr.port);
            if port_allowed {
                debug!("Proxy seccomp: allowing bind on port {}", sockaddr.port);
                true
            } else {
                debug!(
                    "Proxy seccomp: denying bind on port {} (allowed: {:?})",
                    sockaddr.port, config.proxy_bind_ports
                );
                false
            }
        }
        other => {
            warn!(
                "Unexpected syscall {} in proxy seccomp handler, denying",
                other
            );
            false
        }
    };

    if allowed {
        // SECCOMP_USER_NOTIF_FLAG_CONTINUE: let the kernel proceed with its
        // already-copied sockaddr. Safe for connect/bind (move_addr_to_kernel).
        if let Err(e) = continue_notif(notify_fd, notif.id) {
            debug!("continue_notif failed for network notification: {}", e);
            // Must respond to avoid leaving the child blocked. Propagate if
            // deny also fails — the notification is orphaned.
            return deny_notif(notify_fd, notif.id);
        }
    } else {
        respond_notif_errno(notify_fd, notif.id, libc::EACCES)?;
    }

    Ok(())
}

/// Check if a path matches any capability in the initial set.
///
/// Prefers the most specific capability. If the path is covered but the
/// requested access mode is not granted, returns
/// `InitialCapabilityMatch::Insufficient`.
fn match_initial_capability<'a>(
    path: &std::path::Path,
    requested: AccessMode,
    initial_caps: &'a [InitialCapability],
) -> InitialCapabilityMatch<'a> {
    let mut best_covering: Option<&'a InitialCapability> = None;
    let mut best_sufficient: Option<&'a InitialCapability> = None;
    let mut best_covering_score = 0usize;
    let mut best_sufficient_score = 0usize;

    for cap in initial_caps {
        let covers = if cap.is_file {
            path == cap.path
        } else {
            path.starts_with(&cap.path)
        };

        if !covers {
            continue;
        }

        let score = cap.path.as_os_str().len();
        if score >= best_covering_score {
            best_covering = Some(cap);
            best_covering_score = score;
        }

        if cap.access.contains(requested) && score >= best_sufficient_score {
            best_sufficient = Some(cap);
            best_sufficient_score = score;
        }
    }

    if let Some(cap) = best_sufficient {
        InitialCapabilityMatch::Sufficient(cap)
    } else if let Some(cap) = best_covering {
        InitialCapabilityMatch::Insufficient(cap)
    } else {
        InitialCapabilityMatch::None
    }
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
        let caps = vec![InitialCapability {
            path: PathBuf::from("/home/user/config.json"),
            access: AccessMode::Read,
            is_file: true,
        }];

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/config.json"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/config.json/subpath"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::None
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/other.json"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::None
        ));
    }

    #[test]
    fn test_directory_capability_allows_subpaths() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/home/user/project"),
            access: AccessMode::Read,
            is_file: false,
        }];

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project/src/main.rs"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));

        assert!(matches!(
            match_initial_capability(&PathBuf::from("/home/user/other"), AccessMode::Read, &caps),
            InitialCapabilityMatch::None
        ));
    }

    #[test]
    fn test_file_capability_does_not_authorize_fake_subpath() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/foo/bar"),
            access: AccessMode::Read,
            is_file: true,
        }];

        assert!(matches!(
            match_initial_capability(&PathBuf::from("/foo/bar"), AccessMode::Read, &caps),
            InitialCapabilityMatch::Sufficient(_)
        ));
        assert!(matches!(
            match_initial_capability(&PathBuf::from("/foo/bar/subpath"), AccessMode::Read, &caps),
            InitialCapabilityMatch::None
        ));
        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/foo/bar/deep/nested/path"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::None
        ));
    }

    #[test]
    fn test_mixed_file_and_directory_capabilities() {
        let caps = vec![
            InitialCapability {
                path: PathBuf::from("/etc/passwd"),
                access: AccessMode::Read,
                is_file: true,
            },
            InitialCapability {
                path: PathBuf::from("/home/user/project"),
                access: AccessMode::Read,
                is_file: false,
            },
        ];

        assert!(matches!(
            match_initial_capability(&PathBuf::from("/etc/passwd"), AccessMode::Read, &caps),
            InitialCapabilityMatch::Sufficient(_)
        ));
        assert!(matches!(
            match_initial_capability(&PathBuf::from("/etc/passwd/fake"), AccessMode::Read, &caps),
            InitialCapabilityMatch::None
        ));

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));
        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project/src/lib.rs"),
                AccessMode::Read,
                &caps
            ),
            InitialCapabilityMatch::Sufficient(_)
        ));
    }

    #[test]
    fn test_directory_capability_reports_insufficient_access() {
        let caps = vec![InitialCapability {
            path: PathBuf::from("/home/user/project"),
            access: AccessMode::Read,
            is_file: false,
        }];

        assert!(matches!(
            match_initial_capability(
                &PathBuf::from("/home/user/project/output.txt"),
                AccessMode::Write,
                &caps
            ),
            InitialCapabilityMatch::Insufficient(_)
        ));
    }
}
