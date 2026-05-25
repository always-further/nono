---
plan_id: 48-06
cluster: C7
wave: 2
upstream_sha_range: 1f552106..279af554
upstream_commit_count: 4
upstream_tag: v0.55.0
disposition: will-sync
---

# Plan 48-06 PR Section: PTY Proxy + musl Portability (Cluster C7)

## Summary

Cherry-picks Cluster C7 (4 commits): PTY proxy UX fixes + musl libc `Ioctl` type
portability. Wave 2 plan; surface-disjoint from C5/C6/C8/C9.

## Upstream commits absorbed

| # | Upstream SHA | Subject | Tag |
|---|-------------|---------|-----|
| C7-01 | `1f552106` | `fix: preserve child output without trailing newline (#881)` | v0.55.0 |
| C7-02 | `3cd22aa5` | `fix(musl): fix libc::Ioctl type mismatches for x86_64-unknown-linux-musl target` | v0.55.0 |
| C7-03 | `3d0ff87f` | `fix(musl): use as _ for TIOCSCTTY ioctl cast to support all platforms` | v0.55.0 |
| C7-04 | `279af554` | `fix(pty): forward bare ESC immediately in filter_client_input` | v0.55.0 |

Cherry-pick order follows upstream topo-chronological order (not ledger row order).

## Fork adaptations

1. **C7-01 (`1f552106`):** Fork's `release_terminal_for_prompt` calls `leave_attach_screen()`
   without `in_alt_screen` parameter (upstream passes it). Added `let in_alt_screen = self.screen.alternate_screen_active()` local capture before the call. The `prepare_parent_output_area()` call is absent in the fork's function — the newline-emit logic is wired immediately after `restore_terminal()` which achieves the same effect.

2. **C7-02 (`3cd22aa5`):** Fork's `setup_child_pty` is `pub unsafe fn`; the inner `unsafe { }` wrapper from upstream's version is omitted as redundant. The `TIOCSCTTY` cast was applied as `as _` (from C7-03) rather than bare removal, since macOS requires an explicit coercion from `u32` to `c_ulong`. Docker Dockerfiles placed in `docker/` (no `docker/` in upstream commit; fork organizes infra in `docker/`).

3. **C7-03 (`3d0ff87f`):** Effectively a no-op on the fork since `as _` was already applied in C7-02 resolution. Comment updated to document the platform-inference rationale. Fork structure (no inner `unsafe { }` block) preserved.

4. **C7-04 (`279af554`):** Applied cleanly with auto-merge.

## D-48-D4 musl-target verdict

`cargo check --target x86_64-unknown-linux-musl` **PARTIAL `_environmental`**: musl
cross-toolchain not installed on macOS dev host. Deferred to live CI.

The intent of the musl fixes (C7-02 + C7-03) is structurally verified: `as libc::c_ulong`
removed from TIOCSWINSZ/TIOCSCTTY ioctl calls; `u32 as libc::Ioctl` substituted for
SECCOMP_IOCTL_NOTIF_RECV/SEND overflow-safe casts. Both are correct for musl `c_int` Ioctl type.

## Key decisions

- Topo-chronological order used: `1f552106 → 3cd22aa5 → 3d0ff87f → 279af554` (ledger row order differs from date order).
- `as _` applied in C7-02 for macOS compilation safety (pre-empting C7-03 refinement).
- Docker Dockerfiles included in `docker/` directory per fork's organization convention.
- Windows invariant D-48-E1 HONORED: 0 files in exec_strategy_windows/ or nono-shell-broker/ touched.

## Files modified

- `crates/nono-cli/src/pty_proxy.rs` — C7-01 through C7-04
- `crates/nono-cli/src/exec_strategy.rs` — C7-02 (TIOCSWINSZ cast removal)
- `crates/nono/src/sandbox/linux.rs` — C7-02 (SECCOMP_IOCTL u32 cast)
- `docker/Dockerfile-musl` — C7-02 (new file)
- `docker/Dockerfile-musl-cross` — C7-02 (new file)
- `CHANGELOG.md` — C7-04 (bare ESC forwarding entry)
