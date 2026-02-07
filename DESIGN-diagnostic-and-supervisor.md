# Design: Process Model Evolution (Diagnostic, Undo, Supervisor)

**Status**: Monitor mode complete, Supervised mode pending
**Date**: 2026-02-04
**Updated**: 2026-02-07

## Problem

When nono blocks an operation, the AI agent sees a raw kernel error:

```
sh: /tmp/outside.txt: Operation not permitted
```

There is no indication this came from nono. The current workaround requires the agent to:

1. Check `NONO_CAP_FILE` environment variable
2. Run `nono why --self --path <path> --op <op> --json`
3. Parse the JSON response

This produces a poor UX: the agent fumbles through env var lookups and diagnostic commands, all visible to the user as confusing tool calls. The user has no idea what `NONO_CAP_FILE` is, gets concerned, and denies access. The agent then explains it was nono all along. This flow is unacceptable.

## Solution: Fork+Wait with Diagnostic Footer

**Status**: Implemented (v0.2.7+, Monitor mode)

The `exec()` model has been replaced with `fork()+waitpid()` so nono stays alive as a parent process. When the child exits non-zero, nono prints a self-explanatory diagnostic to stderr. This works universally for any agent, not just Claude Code.

### What the agent sees

```
$ nono run --allow . -- sh -c "echo test > /tmp/outside.txt"
sh: /tmp/outside.txt: Operation not permitted

[nono] Command exited with code 1. This may be due to sandbox restrictions.
[nono]
[nono] Sandbox policy:
[nono]   Allowed paths:
[nono]     /Users/luke/project (read+write)
[nono]   Network: blocked
[nono]
[nono] To grant additional access, re-run with:
[nono]   --allow <path>     read+write access
[nono]   --read <path>      read-only access
[nono]   --write <path>     write-only access
[nono]   --allow-net        network access
```

The `[nono]` prefix is unmistakable. The agent immediately knows:
- This is a nono sandbox issue (not a regular permission error)
- What the current policy allows
- Exactly what flags to suggest to the user

No CLAUDE.md instructions needed. No env var lookups. No extra tool calls. Works with any AI agent that reads stderr.

---

## Implemented: Claude Code Hook Integration

**Status**: Complete (v0.2.7+)

While the fork+wait process model is pending, we have implemented an interim solution specifically for Claude Code using its native hooks system. This provides immediate value without requiring changes to nono's process model.

### How It Works

1. **Profile-driven installation**: The `claude-code` profile defines a hook in `[hooks.claude-code]`
2. **Automatic setup**: When `nono run --profile claude-code` is invoked, nono:
   - Installs `~/.claude/hooks/nono-hook.sh` (embedded in binary)
   - Registers the hook in `~/.claude/settings.json`
   - Adds sandbox instructions to `~/.claude/CLAUDE.md`
3. **Runtime injection**: When Claude's tools fail, the hook reads `$NONO_CAP_FILE` and injects context about allowed paths and required actions

### What Claude Sees

On a sandbox error, Claude receives:

```
[NONO SANDBOX - PERMISSION DENIED]

STOP. Do not try alternative approaches. This is a hard security boundary.

You are running inside the nono security sandbox. The operation you just
attempted is PERMANENTLY BLOCKED for this session.

ALLOWED PATHS (everything else is blocked):
  /Users/luke/project (readwrite)
  /Users/luke/.claude (readwrite)
Network: allowed

REQUIRED ACTION:
Tell the user they must EXIT this Claude session and restart with:
  nono run --allow /path/to/needed -- claude
```

### Relationship to Fork+Wait

This hook-based approach:
- Is Claude Code-specific (uses its hooks API)
- Complements the fork+wait diagnostic footer (now implemented)

The fork+wait model (Monitor mode) provides:
- Universal diagnostics for any agent (via stderr footer)
- No hook installation required
- Foundation for undo and supervisor features

Both coexist: the hook provides richer, immediate context via Claude's hook system, while the stderr footer catches anything the hook misses and works for all agents.

---

### Design rules

- **Only on error.** Successful runs (exit code 0) produce no extra output.
- **Phrased as "may be due to"**, not "was caused by" -- the non-zero exit could be unrelated to the sandbox.
- **Signal kills skip diagnostic.** If the child was killed by a signal (SIGKILL, SIGTERM, etc.), don't print the footer -- it wasn't a sandbox issue.
- **`--no-diagnostics` flag.** For scripts that parse stderr and don't want the footer.
- **`nono why --self` remains.** The diagnostic footer handles the common case; `nono why --self` is still available for detailed per-path queries.

### Signal forwarding

The parent process must forward signals to the child:
- SIGINT, SIGTERM, SIGTSTP forwarded to child process group
- Parent blocked in `waitpid()`, wakes on child exit or signal
- Use `nix::sys::signal` and `nix::sys::wait` in Rust

### Implementation: Async-Signal-Safe Fork+Exec

**Status**: Implemented in `src/exec_strategy.rs`

The Monitor mode implementation carefully handles fork() in a potentially multi-threaded process (when keyring backend threads are present). After fork(), the child can only safely call async-signal-safe functions until exec(). The implementation:

1. **Path resolution in parent**: Uses the `which` crate to resolve the program path before fork, since PATH searching allocates memory.

2. **CString preparation in parent**: All strings (program, argv, envp) are converted to CString before fork. The child uses only the pre-prepared pointers.

3. **Raw libc calls in child**: The child uses only `libc::close()`, `libc::dup2()`, `libc::execve()`, and `libc::_exit()`. No Rust standard library calls that might allocate.

4. **ManuallyDrop for OwnedFd**: Pipe file descriptors are wrapped in `ManuallyDrop` to prevent Rust's destructor from running in the child (destructors may allocate).

5. **ThreadingContext for keyring compatibility**: The keyring crate may spawn D-Bus/Security.framework threads that persist after loading secrets. A `ThreadingContext` enum allows elevated thread counts (up to 4) when secrets are loaded, since these threads don't hold locks the child needs.

```rust
pub enum ThreadingContext {
    Strict,          // Require exactly 1 thread (default)
    KeyringExpected, // Allow up to 4 threads (keyring backend)
}
```

6. **FD cleanup before fork**: `get_max_fd()` is called in the parent to avoid `/proc` reads in the child (which allocate on Linux).

---

## Relationship to the Undo System

The undo system (see `DESIGN-undo-system.md`) was designed around the `exec()` model. It uses a three-process architecture: parent (execs away), background monitor (forked before exec), and child (sandboxed command). The move to fork+wait changes this relationship significantly.

### The snapshot storage problem

The undo monitor needs write access to `~/.nono/undo/<session>/` to store snapshots. This creates a fork-order dilemma:

**If we sandbox before fork (diagnostic model):**
- Both parent and child are sandboxed
- The parent cannot write to `~/.nono/undo/` -- it's outside the sandbox's allowed paths
- We could auto-add `~/.nono/undo/` to allowed paths, but then the child also gets access
- A malicious child could tamper with snapshots: delete them (sabotage undo), modify them (make undo restore malicious content), or read them (discover previous file states)
- This is a real security concern. Snapshot integrity depends on the child NOT having access.

**If we fork before sandbox (supervisor model):**
- The parent is unsandboxed and can safely write snapshots to `~/.nono/undo/`
- The child is sandboxed and has no access to snapshot storage
- Snapshot integrity is preserved

**Conclusion: The undo system requires an unsandboxed parent.** This pushes the architecture toward the supervisor model even for the diagnostic-only case when `--undo` is enabled.

### Three features, one architecture

The diagnostic footer, undo monitoring, and capability expansion all converge on the same process model:

| Feature | Needs persistent parent? | Needs unsandboxed parent? |
|---------|------------------------|--------------------------|
| Diagnostic footer | Yes (waitpid + print) | No |
| Undo snapshots | Yes (watch + snapshot) | Yes (write to ~/.nono/undo/) |
| Capability expansion | Yes (IPC + proxy) | Yes (open files, pass fds) |

All three are functions of a single persistent parent process. Two of the three require that parent to be unsandboxed. Rather than implementing them as separate process models, they should be unified into a single parent architecture.

### Undo simplification under fork+wait

The undo system's original "two-process model" (nono execs away, separate monitor fork, orphaned monitor reparented to init) becomes cleaner under fork+wait:

**Before (exec model, from DESIGN-undo-system.md):**
```
nono (parent)
  ├── fork -> background monitor (unsandboxed, orphaned when parent execs)
  │           - must poll for parent death via getppid()
  │           - orphan cleanup complexity
  └── exec() -> child command (sandboxed, nono is gone)

3 processes briefly, 2 running (monitor + child), parent gone
```

**After (fork+wait model):**
```
nono (parent, unsandboxed)
  ├── undo monitor logic runs IN the parent (no separate fork)
  │   - filesystem watcher (inotify/FSEvents) in parent event loop
  │   - snapshot creation in parent
  │   - no orphan problem -- parent exits when child exits
  └── fork -> child (sandboxed) -> exec(command)

2 processes, parent owns the child's lifetime
```

This eliminates:
- The separate monitor fork (undo logic lives in the parent)
- The orphan detection problem (`is_parent_alive()` polling)
- The stale process cleanup for monitor processes
- The race between monitor forking and parent exec'ing

The parent's event loop becomes: wait for child (WNOHANG) + poll filesystem watcher + take snapshots when triggered. When the child exits, take a final snapshot, print diagnostic if error, exit.

### Revised undo architecture note

The undo system's `DESIGN-undo-system.md` should be read with the understanding that:
- "Preserves exec() Model" is no longer a constraint -- we are moving to fork+wait
- The "Background Monitor (forked from parent)" becomes logic in the parent process, not a separate fork
- The `is_parent_alive()` polling is eliminated -- the parent IS the monitor
- The snapshot storage, metadata, restoration, and UI designs remain unchanged
- The `SnapshotManager`, `nono undo` command, and all user-facing behavior remain the same

---

## Execution Strategy and Fork Order

### The fork-order decision

The original plan was a phased approach:
1. Phase 2: Sandbox then fork (both sandboxed, diagnostic only)
2. Phase 3: Fork then sandbox (parent unsandboxed, supervisor)

The undo system changes this calculus. Since `--undo` requires an unsandboxed parent, we have two options:

**Option A: Two execution modes based on flags**
```
nono run --allow . -- command           -> sandbox-then-fork (both sandboxed)
nono run --allow . --undo -- command    -> fork-then-sandbox (parent unsandboxed)
```
Pro: Minimal attack surface when undo isn't used.
Con: Two code paths to maintain. The diagnostic formatting must work in both modes.

**Option B: Always fork-then-sandbox**
```
nono run --allow . -- command           -> fork-then-sandbox (parent unsandboxed)
nono run --allow . --undo -- command    -> same, plus undo logic in parent
```
Pro: Single code path. Natural evolution to supervisor.
Con: Unsandboxed parent even when not needed. Slightly larger attack surface.

**Recommendation: Option A**, with the execution strategy abstraction making it a small, isolated difference:

```rust
enum ExecStrategy {
    /// Current: apply sandbox, exec into command. nono ceases to exist.
    Direct,
    /// Diagnostic only: apply sandbox, fork, wait, diagnose on error.
    /// Both parent and child are sandboxed. No undo support.
    Monitor,
    /// Undo and/or supervisor: fork first, sandbox only child.
    /// Parent is unsandboxed. Supports undo, diagnostics, and future IPC.
    Supervised,
}
```

Selection logic:
- `--undo` or future `--supervised` -> `Supervised`
- Default `nono run` -> `Monitor`
- `--exec` flag for backward compat -> `Direct`

The diagnostic formatting code is shared between `Monitor` and `Supervised`. The only difference is the fork order and what the parent is allowed to do.

### Execution flows

**Monitor mode** (default, no undo):
```
run_sandbox():
    build capabilities (CapabilitySet)
    apply sandbox to self (irreversible)
    fork()
      child:
        set NONO_CAP_FILE env var
        exec(target command)
      parent (sandboxed):
        waitpid(child)
        if child exited non-zero:
            print diagnostic footer to stderr
        exit with child's exit code
```

**Supervised mode** (--undo, or future --supervised):
```
run_sandbox():
    build capabilities (CapabilitySet)
    if --undo: take initial snapshot (snapshot 0)
    fork()
      child:
        apply sandbox to self (irreversible)
        set NONO_CAP_FILE env var
        exec(target command)
      parent (unsandboxed):
        start filesystem watcher (if --undo)
        loop:
            waitpid(child, WNOHANG)
            if --undo: check for fs events, take snapshots
            if child exited:
                if --undo: take final snapshot
                if child exited non-zero: print diagnostic
                exit with child's exit code
```

### Security posture by mode

| Mode | Parent | Child | Attack surface | Use case |
|------|--------|-------|----------------|----------|
| Direct | gone (exec'd) | sandboxed | Minimal | Backward compat, scripts |
| Monitor | sandboxed | sandboxed | Small (parent in waitpid) | Default for AI agents |
| Supervised | unsandboxed | sandboxed | Larger (parent active) | Undo, cap expansion |

In Monitor mode, even if the child compromises the parent via ptrace, the parent is equally sandboxed -- no escalation. In Supervised mode, ptrace protection is critical (see below).

---

## Security Considerations

### Monitor mode (both sandboxed)

**Negligible additional risk.** The parent is sandboxed with the same restrictions as the child. It sits in `waitpid()` with no input channels. The diagnostic footer prints the policy summary to stderr -- information the child could discover by probing.

Hardening: set `PR_SET_DUMPABLE(0)` on both processes.

### Supervised mode (unsandboxed parent)

**Requires active hardening.** The unsandboxed parent is a high-value target for a malicious child.

- **Ptrace protection** (critical): The child must not be able to ptrace the unsandboxed parent.
  - Set `PR_SET_DUMPABLE(0)` on the parent immediately after fork
  - On Linux, ensure `ptrace_scope >= 1` or use seccomp to block `PTRACE_ATTACH` in the child
  - On macOS, the sandbox profile blocks `process-exec` which limits ptrace utility

- **Signal restriction**: The child can send signals to the parent (same UID). The parent should only act on expected signals (SIGCHLD, forwarded SIGINT/SIGTERM). Ignore unexpected signals.

- **Snapshot storage isolation**: `~/.nono/undo/` must have 0700 permissions. The child's sandbox must NOT include this path. Verify this is enforced at sandbox application time.

- **Filesystem watcher scope**: The parent watches only paths in the `CapabilitySet`. It must not watch paths outside the granted scope, even though it's unsandboxed.

- **Parent minimality**: The unsandboxed parent should do as little as possible. Its event loop should be: wait for child, watch filesystem (if undo), take snapshots (if undo). No network access, no user input reading (except future supervisor IPC), no file operations outside `~/.nono/undo/`.

---

## SDK/Library Layering

This project will migrate to offer both a CLI and an SDK/library. The fork+wait change is purely a CLI concern. The library boundary:

```
Library (nono-lib):
    CapabilitySet           build and manipulate sandbox policies
    Sandbox::apply()        apply sandbox to current process (irreversible)
    Sandbox::explain()      query why a path/operation is allowed or denied
    SandboxState            serialize/deserialize policy for introspection
    SnapshotManager         create/restore filesystem snapshots (undo)
    DiagnosticFormatter     format policy into human/agent-readable output

CLI (nono):
    Argument parsing
    Execution strategy (Direct / Monitor / Supervised)
    Signal forwarding
    Filesystem watcher integration
    Parent event loop
    Output / UX
```

The `SnapshotManager` and `DiagnosticFormatter` are library code -- they don't fork, exec, or manage processes. The CLI orchestrates them within the appropriate execution strategy.

An SDK consumer could use `SnapshotManager` directly for their own undo needs without any of the fork+wait machinery. Similarly, `DiagnosticFormatter` could be used by any parent process that wants to explain sandbox denials.

---

## Future: Supervisor + Runtime Capability Expansion

### Goal

Allow the user (or an AI agent) to grant additional capabilities without restarting the sandboxed process. For example, granting access to `../other-project` mid-session.

### Architecture

The supervisor is a natural extension of the `Supervised` execution strategy. The parent is already unsandboxed and running an event loop. Adding IPC is incremental:

```
nono (parent, unsandboxed)
  - Unix socket IPC server
  - User prompt UI
  - Capability expansion handler
  - File operation proxy
  - Filesystem watcher + snapshots (if --undo)
  - Diagnostic on error
  |
  fork()
  |
  v
Child (sandboxed)
  - apply_sandbox()
  - connect to supervisor socket
  - exec(target command)
  - inherits sandbox + IPC socket fd
```

### How undo and supervisor interact

When both `--undo` and supervisor IPC are active:

1. Child requests capability expansion (e.g., read access to `/data/`)
2. Supervisor prompts user, user approves
3. Supervisor passes fd for `/data/` to child via `SCM_RIGHTS`
4. Supervisor adds `/data/` to its filesystem watcher scope
5. Subsequent snapshots include `/data/` contents
6. If user later runs `nono undo`, snapshots reflect the full history including dynamically-granted paths

The undo system naturally tracks whatever the supervisor grants, because the parent controls both the watcher and the snapshot logic.

### IPC Protocol

Unix domain socket created by supervisor before fork. Child inherits the socket fd.

**Capability request** (child -> supervisor):
```json
{
    "type": "capability_request",
    "path": "/Users/luke/other-project",
    "access": "read",
    "reason": "Agent needs to read files from adjacent project"
}
```

**Supervisor prompts user:**
```
[nono] The sandboxed process is requesting additional access:
[nono]   Path: /Users/luke/other-project
[nono]   Access: read-only
[nono]   Reason: Agent needs to read files from adjacent project
[nono]
[nono] Grant access? [y/N]
```

**Response** (supervisor -> child):
```json
{
    "type": "capability_response",
    "granted": true,
    "proxy_fd": 7
}
```

### Capability expansion mechanism

Landlock and Seatbelt do not allow expanding sandbox permissions after `restrict_self()` / `sandbox_init()`. Once applied, the sandbox can only be tightened, never loosened. This means the child cannot directly gain new filesystem access.

Two approaches:

1. **File descriptor proxy**: The supervisor (unsandboxed) opens the requested file/directory and passes the fd to the child over the Unix socket using `SCM_RIGHTS` (ancillary data). The child can read/write through the fd without needing its own filesystem access. This works for individual files but is complex for directory trees.

2. **Operation proxy**: The child sends read/write requests to the supervisor, which performs them on the child's behalf and returns the results over the socket. This is more flexible but adds latency and complexity.

The fd-passing approach is preferred for simplicity and because it doesn't require the supervisor to understand file operation semantics.

### Security considerations for Supervisor

- **Ptrace protection**: The child must not be able to ptrace the unsandboxed supervisor. Set `PR_SET_DUMPABLE(0)` on the supervisor. On Linux, use `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` carefully or rely on `ptrace_scope >= 1`.
- **IPC authentication**: The socket should validate that requests come from the expected child PID (using `SO_PEERCRED` on Linux, `LOCAL_PEERPID` on macOS).
- **Rate limiting**: Prevent the child from flooding the supervisor with requests.
- **Scope validation**: The supervisor should enforce its own policy about what can be granted (e.g., never grant access to sensitive paths regardless of user confirmation).
- **User confirmation**: Every capability expansion must be explicitly confirmed by the user. No auto-grant.

---

## Migration Path

```
Phase 1 (complete):
    exec() model (default)
    Direct mode for interactive apps (claude-code profile)
    Claude Code hook integration for sandbox-aware diagnostics
    nono why --self for diagnosis (all agents)

Phase 1.5 (complete):
    ExecStrategy enum (Direct, Monitor, Supervised stub)
    Profile-driven interactive mode (interactive = true)
    Hook auto-installation via profiles
    CLAUDE.md managed sections

Phase 2 (in progress):
    Monitor mode: sandbox-then-fork, diagnostic footer on error [COMPLETE]
    Async-signal-safe fork+exec with keyring compatibility [COMPLETE]
    Supervised mode: fork-then-sandbox, undo snapshots + diagnostic [PENDING]
    --undo flag activates Supervised mode [PENDING]
    Library/CLI separation [NEXT]

Phase 3 (future):
    Supervised mode gains IPC socket
    Capability expansion via fd-passing
    User prompt UI
    Undo watcher scope expands with granted capabilities
    nono why --self becomes optional (diagnostic footer + IPC cover most cases)
```

Phase 2 is not throwaway work. Everything carries forward:
- Diagnostic formatting -> used by all modes
- Signal forwarding -> used by Monitor and Supervised
- ExecStrategy abstraction -> Supervised gains IPC, same fork structure
- SnapshotManager -> unchanged, just called from the parent event loop
- Library/CLI separation -> required for SDK
- Fork-order isolation -> Supervised already exists, just gains new features

The only thing that changes between Phase 2 Supervised and Phase 3 Supervised is the addition of the IPC socket and capability expansion handler in the parent's event loop.

---

## Next Step: Library/CLI Separation

**Status**: Ready to implement

With Monitor mode complete, the next step is extracting the core sandbox functionality into a reusable library (`nono-lib`). This enables:

1. **SDK consumers** to embed sandboxing in their own tools without the CLI
2. **Clean abstractions** for undo (SnapshotManager) and diagnostics
3. **Better testing** with isolated library code

### Proposed crate structure

```
nono/
├── Cargo.toml              # Workspace root
├── nono-lib/
│   ├── Cargo.toml          # Library crate
│   └── src/
│       ├── lib.rs          # Public API
│       ├── capability.rs   # CapabilitySet, FsCapability
│       ├── sandbox/        # Platform sandbox implementations
│       ├── state.rs        # SandboxState serialization
│       ├── diagnostic.rs   # DiagnosticFormatter
│       └── query.rs        # Path query/explain logic
└── nono-cli/
    ├── Cargo.toml          # CLI crate, depends on nono-lib
    └── src/
        ├── main.rs         # Entry point
        ├── cli.rs          # Clap definitions
        ├── exec_strategy.rs # Direct/Monitor/Supervised
        ├── hooks.rs        # Claude Code hooks
        ├── profile.rs      # Profile loading
        └── output.rs       # TUI output formatting
```

### What moves to the library

| Module | Current Location | Library? | Notes |
|--------|-----------------|----------|-------|
| CapabilitySet | capability.rs | ✅ Yes | Core abstraction |
| FsCapability | capability.rs | ✅ Yes | Core abstraction |
| Sandbox::apply() | sandbox/*.rs | ✅ Yes | Platform implementations |
| SandboxState | sandbox_state.rs | ✅ Yes | Serialization |
| DiagnosticFormatter | diagnostic.rs | ✅ Yes | Reusable formatting |
| Query logic | query.rs | ✅ Yes | Path explain |
| Security lists | config/security_lists.rs | ✅ Yes | Sensitive paths |
| ExecStrategy | exec_strategy.rs | ❌ No | CLI process model |
| Profile loading | profile.rs | ❌ No | CLI configuration |
| Hooks | hooks.rs | ❌ No | Claude Code specific |
| CLI args | cli.rs | ❌ No | CLI only |

### Public API sketch

```rust
// nono-lib public API
pub use capability::{CapabilitySet, FsCapability, AccessMode};
pub use sandbox::{Sandbox, SandboxSupport};
pub use state::SandboxState;
pub use diagnostic::DiagnosticFormatter;
pub use query::{QueryResult, query_path, query_network};

// Primary use case: apply sandbox to current process
let caps = CapabilitySet::builder()
    .allow_path("/project", AccessMode::ReadWrite)?
    .allow_network(false)
    .build()?;

Sandbox::apply(&caps)?; // Irreversible
```

### Migration approach

1. Create workspace with `nono-lib` and `nono-cli` crates
2. Move core modules to `nono-lib` with `pub` exports
3. Update `nono-cli` to depend on `nono-lib`
4. Ensure `cargo build` still produces a `nono` binary
5. Add `nono-lib` to crates.io publish workflow
