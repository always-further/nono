# nono Implementation Plan

> Technical implementation details for the nono capability shell.

---

## Research Summary

### Linux: Landlock

**Landlock** is a Linux Security Module that allows unprivileged processes to sandbox themselves.

| ABI Version | Kernel | Features |
|-------------|--------|----------|
| 1 | 5.13 | Filesystem access control |
| 2 | 5.19 | `LANDLOCK_ACCESS_FS_REFER` (file rename across dirs) |
| 3 | 6.2 | `LANDLOCK_ACCESS_FS_TRUNCATE` |
| 4 | 6.7 | **TCP network support** (`BIND_TCP`, `CONNECT_TCP`) |
| 5 | 6.10 | `LANDLOCK_ACCESS_FS_IOCTL_DEV` |
| 6 | 6.12 | Abstract Unix socket scoping, signal scoping |

**Key insight:** Landlock ABI v4 (kernel 6.7+) provides native TCP network filtering. No seccomp required for basic network control.

**Rust crate:** [landlock](https://crates.io/crates/landlock) - safe Rust bindings.

**References:**
- [Landlock kernel docs](https://docs.kernel.org/userspace-api/landlock.html)
- [landlock(7) man page](https://www.man7.org/linux/man-pages/man7/landlock.7.html)

### Linux: seccomp (for older kernels)

For kernels < 6.7, we need seccomp to filter network access:

**libseccomp-rs** provides:
- `ScmpAction::Notify` for `SECCOMP_RET_USER_NOTIF`
- `ScmpNotifReq` / `ScmpNotifResp` for userspace notification handling
- Ability to intercept `connect()` and validate sockaddr

**Warning:** SECCOMP_RET_USER_NOTIF has TOCTOU race conditions. Not suitable as sole security mechanism, but acceptable as defense-in-depth with domain filtering.

**Rust crates:**
- [libseccomp](https://crates.io/crates/libseccomp) - full libseccomp bindings
- [seccompiler](https://crates.io/crates/seccompiler) - simpler BPF filter generation

### macOS: Seatbelt

**Seatbelt** is Apple's sandbox framework (same as iOS).

**API options:**
1. `sandbox-exec -f profile.sb command` - external tool
2. `sandbox_init(profile, flags, &errorbuf)` - C API, can call via FFI

**Profile language:** Scheme-like DSL
```scheme
(version 1)
(deny default)
(allow file-read* (subpath "/allowed/path"))
(allow network-outbound (remote tcp "host:port"))
```

**Rust integration:**
- No existing crate with full support
- Need FFI bindings to `libsandbox.dylib`
- Or shell out to `sandbox-exec`

**Existing project:** [sandbox-shell (sx)](https://github.com/agentic-dev3o/sandbox-shell) - Rust macOS sandbox CLI. Similar goals but macOS-only, no runtime expansion.

**References:**
- [Apple Sandbox Design Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/)
- [HackTricks macOS Sandbox](https://book.hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sandbox/)

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                          nono binary                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────┐ │
│  │    CLI      │  │   Config     │  │   Capability Store      │ │
│  │   (clap)    │  │   (toml)     │  │   (in-memory)           │ │
│  └─────────────┘  └──────────────┘  └─────────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Platform Sandbox                         ││
│  │  ┌─────────────────────┐  ┌───────────────────────────────┐ ││
│  │  │   Linux Module      │  │      macOS Module             │ ││
│  │  │                     │  │                               │ ││
│  │  │  - Landlock (fs)    │  │  - Seatbelt profile gen       │ ││
│  │  │  - Landlock (net)   │  │  - sandbox_init() FFI         │ ││
│  │  │  - seccomp (compat) │  │                               │ ││
│  │  └─────────────────────┘  └───────────────────────────────┘ ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                   Supervisor System                         ││
│  │                                                             ││
│  │  - Fork into supervisor + sandboxed child                   ││
│  │  - Control socket for capability requests                   ││
│  │  - User prompt handling                                     ││
│  │  - Capability proxy for file operations                     ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      Shell / Launcher                       ││
│  │                                                             ││
│  │  - Command execution (simple launcher, not full shell)      ││
│  │  - PTY handling for interactive commands                    ││
│  │  - Signal forwarding                                        ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Process Model

```
User runs: nono --allow ./project -- claude

┌─────────────────────────────────────────────────────────────────┐
│  nono main() - Parse args, load config                          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│  fork()                                                         │
│                                                                 │
│  Parent (Supervisor)              Child (Sandbox Target)        │
│  ┌─────────────────────┐          ┌─────────────────────────┐   │
│  │ - Stays unsandboxed │          │ 1. Apply Landlock/      │   │
│  │ - Creates control   │          │    Seatbelt restrictions│   │
│  │   socket            │          │ 2. Drop privileges      │   │
│  │ - Listens for       │          │ 3. exec(claude) or REPL │   │
│  │   capability reqs   │          │                         │   │
│  │ - Prompts user      │          │ Claude runs here with   │   │
│  │ - Spawns expanded   │          │ inherited restrictions  │   │
│  │   children          │          │                         │   │
│  └─────────────────────┘          └─────────────────────────┘   │
│           │                                  ▲                  │
│           │         IPC (Unix socket)        │                  │
│           └──────────────────────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

### Runtime Capability Expansion Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  Sandboxed Process (Claude)                                     │
│                                                                 │
│  Claude: "I need to read ../other-project/lib.rs"              │
│                                                                 │
│  1. Attempts read → EACCES                                     │
│  2. Recognizes sandbox restriction                              │
│  3. Calls: nono-grant --path ../other-project --mode read       │
│                                                                 │
│  nono-grant:                                                    │
│    - Connects to supervisor socket                              │
│    - Sends CapabilityRequest { path, mode }                     │
│    - Waits for response                                         │
└─────────────────────────────┬───────────────────────────────────┘
                              │ IPC
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Supervisor                                                     │
│                                                                 │
│  Receives request, displays to user:                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  nono: Capability request                                  │ │
│  │                                                            │ │
│  │  Process: claude (PID 12345)                               │ │
│  │  Request: Read access to /home/user/other-project          │ │
│  │                                                            │ │
│  │  [A]pprove  [D]eny  [V]iew contents  [?] Help              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  User presses 'A':                                              │
│    - Supervisor records new capability                          │
│    - For file read: supervisor reads file, returns via IPC      │
│    - For new child: supervisor can spawn with expanded caps     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Why proxy for existing processes:**

Landlock restrictions cannot be expanded after `restrict_self()`. So:
- Current process: Supervisor proxies file operations
- New processes: Can spawn with expanded capabilities

---

## Crate Dependencies

```toml
[dependencies]
# CLI
clap = { version = "4", features = ["derive"] }

# Config
toml = "0.8"
serde = { version = "1", features = ["derive"] }

# Error handling
thiserror = "1"
anyhow = "1"

# Async (for supervisor event loop)
tokio = { version = "1", features = ["full"] }

# IPC
serde_json = "1"  # For capability request/response serialization

# Logging
tracing = "0.1"
tracing-subscriber = "0.3"

# Platform-specific
[target.'cfg(target_os = "linux")'.dependencies]
landlock = "0.4"
libseccomp = "0.3"  # For older kernel compat
nix = { version = "0.29", features = ["process", "signal", "pty"] }

[target.'cfg(target_os = "macos")'.dependencies]
nix = { version = "0.29", features = ["process", "signal", "pty"] }
# Note: Seatbelt via FFI, no crate needed
```

---

## Module Structure

```
src/
├── main.rs                 # Entry point
├── cli.rs                  # Clap argument definitions
├── config.rs               # TOML config parsing
├── capability.rs           # Capability types and CapabilitySet
├── error.rs                # Error types
│
├── sandbox/
│   ├── mod.rs              # Platform dispatch
│   ├── linux.rs            # Landlock + seccomp implementation
│   └── macos.rs            # Seatbelt implementation
│
├── supervisor/
│   ├── mod.rs              # Supervisor main loop
│   ├── socket.rs           # Unix socket IPC
│   ├── prompt.rs           # User interaction for capability requests
│   └── proxy.rs            # File operation proxy for sandboxed processes
│
├── shell/
│   ├── mod.rs              # Command execution
│   ├── pty.rs              # PTY handling for interactive commands
│   └── signal.rs           # Signal forwarding
│
└── grant/
    └── mod.rs              # nono-grant client (runs inside sandbox)
```

---

## Implementation Phases

### Phase 1: MVP (Filesystem Sandbox)

**Goal:** `nono --allow . -- claude` works, Claude cannot read `/etc/passwd`.

**Scope:**
- CLI parsing with clap
- Basic capability model (FsRead, FsWrite)
- Linux Landlock filesystem sandbox
- macOS Seatbelt filesystem sandbox
- Simple exec (no REPL, no supervisor)

**Tasks:**

1. **Project setup**
   ```bash
   cargo new nono
   cd nono
   # Add dependencies to Cargo.toml
   ```

2. **CLI definition** (`cli.rs`)
   ```rust
   #[derive(Parser)]
   pub struct Args {
       /// Paths to allow read+write access
       #[arg(long, short = 'a')]
       allow: Vec<PathBuf>,

       /// Paths to allow read-only access
       #[arg(long, short = 'r')]
       read: Vec<PathBuf>,

       /// Paths to allow write-only access
       #[arg(long, short = 'w')]
       write: Vec<PathBuf>,

       /// Command to run (after --)
       #[arg(last = true)]
       command: Vec<String>,
   }
   ```

3. **Capability types** (`capability.rs`)
   ```rust
   pub enum FsAccess {
       Read,
       Write,
       ReadWrite,
   }

   pub struct FsCapability {
       path: PathBuf,  // Canonicalized
       access: FsAccess,
   }

   pub struct CapabilitySet {
       fs: Vec<FsCapability>,
   }
   ```

4. **Linux sandbox** (`sandbox/linux.rs`)
   ```rust
   pub fn apply(caps: &CapabilitySet) -> Result<()> {
       use landlock::*;

       let abi = ABI::V4;  // Or detect
       let mut ruleset = Ruleset::default()
           .handle_access(AccessFs::from_all(abi))?
           .create()?;

       for cap in &caps.fs {
           let access = match cap.access {
               FsAccess::Read => AccessFs::ReadFile | AccessFs::ReadDir,
               FsAccess::Write => AccessFs::WriteFile | AccessFs::RemoveFile,
               FsAccess::ReadWrite => AccessFs::from_read(abi) | AccessFs::from_write(abi),
           };
           ruleset.add_rule(PathBeneath::new(&cap.path, access))?;
       }

       ruleset.restrict_self()?;
       Ok(())
   }
   ```

5. **macOS sandbox** (`sandbox/macos.rs`)
   ```rust
   pub fn apply(caps: &CapabilitySet) -> Result<()> {
       let profile = generate_profile(caps);

       // Option A: Shell out to sandbox-exec
       // Option B: FFI to sandbox_init

       // For MVP, use sandbox-exec:
       // Re-exec ourselves with sandbox-exec wrapper

       Ok(())
   }

   fn generate_profile(caps: &CapabilitySet) -> String {
       let mut profile = String::from("(version 1)\n(deny default)\n");
       profile.push_str("(allow process-fork)\n");
       profile.push_str("(allow process-exec)\n");

       for cap in &caps.fs {
           let ops = match cap.access {
               FsAccess::Read => "file-read*",
               FsAccess::Write => "file-write*",
               FsAccess::ReadWrite => "file-read* file-write*",
           };
           profile.push_str(&format!(
               "(allow {} (subpath \"{}\"))\n",
               ops,
               cap.path.display()
           ));
       }

       profile
   }
   ```

6. **Main** (`main.rs`)
   ```rust
   fn main() -> Result<()> {
       let args = Args::parse();
       let caps = build_capabilities(&args)?;

       // Apply sandbox
       #[cfg(target_os = "linux")]
       sandbox::linux::apply(&caps)?;

       #[cfg(target_os = "macos")]
       sandbox::macos::apply(&caps)?;

       // Execute command
       let status = Command::new(&args.command[0])
           .args(&args.command[1..])
           .status()?;

       std::process::exit(status.code().unwrap_or(1));
   }
   ```

**Success criteria:**
```bash
$ nono --allow . -- cat ./README.md
# Works, shows file

$ nono --allow . -- cat /etc/passwd
# EACCES error
```

---

### Phase 2: Network Isolation

**Goal:** `nono --allow . --net api.anthropic.com -- claude` blocks other network access.

**Scope:**
- Network capabilities (NetConnect, NetDomain)
- Linux: Landlock ABI v4 for TCP, seccomp fallback for older kernels
- macOS: Seatbelt network rules
- DNS handling

**Tasks:**

1. **Extend capabilities**
   ```rust
   pub enum NetAccess {
       /// Allow TCP connect to host:port
       TcpConnect { host: String, port: u16 },
       /// Allow TCP connect to any port on host
       TcpDomain(String),
       /// Allow TCP bind on port
       TcpBind(u16),
   }

   pub struct CapabilitySet {
       fs: Vec<FsCapability>,
       net: Vec<NetAccess>,
   }
   ```

2. **Linux Landlock network** (kernel 6.7+)
   ```rust
   // In sandbox/linux.rs
   pub fn apply(caps: &CapabilitySet) -> Result<()> {
       let abi = detect_abi();

       if abi >= ABI::V4 {
           apply_with_network(caps, abi)
       } else {
           apply_fs_only(caps, abi)?;
           apply_seccomp_network(caps)  // Fallback
       }
   }

   fn apply_with_network(caps: &CapabilitySet, abi: ABI) -> Result<()> {
       let mut ruleset = Ruleset::default()
           .handle_access(AccessFs::from_all(abi))?
           .handle_access(AccessNet::from_all(abi))?
           .create()?;

       // Add fs rules...

       // Add network rules
       for net in &caps.net {
           match net {
               NetAccess::TcpConnect { port, .. } => {
                   ruleset.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))?;
               }
               // ...
           }
       }

       ruleset.restrict_self()?;
       Ok(())
   }
   ```

3. **Linux seccomp fallback** (for older kernels)
   ```rust
   fn apply_seccomp_network(caps: &CapabilitySet) -> Result<()> {
       // Use SECCOMP_RET_ERRNO to block connect() to disallowed hosts
       // This is weaker than Landlock but provides some protection

       // Note: seccomp can only filter by syscall, not by argument content
       // For true host filtering, we'd need SECCOMP_RET_USER_NOTIF
       // which requires supervisor coordination

       // For MVP: just block all network if no --net flags provided
   }
   ```

4. **macOS Seatbelt network**
   ```rust
   fn generate_profile(caps: &CapabilitySet) -> String {
       let mut profile = /* ... fs rules ... */;

       if caps.net.is_empty() {
           profile.push_str("(deny network*)\n");
       } else {
           for net in &caps.net {
               match net {
                   NetAccess::TcpDomain(host) => {
                       profile.push_str(&format!(
                           "(allow network-outbound (remote tcp \"{}:*\"))\n",
                           host
                       ));
                   }
                   // ...
               }
           }
       }

       profile
   }
   ```

**Success criteria:**
```bash
$ nono --allow . --net api.anthropic.com -- curl https://api.anthropic.com/v1/...
# Works

$ nono --allow . --net api.anthropic.com -- curl https://evil.com
# Connection refused / blocked
```

---

### Phase 3: Supervisor + Runtime Expansion

**Goal:** User can grant `../other-project` access without restarting.

**Scope:**
- Fork into supervisor (unsandboxed) + child (sandboxed)
- Unix socket IPC
- Capability request/response protocol
- User prompt UI
- File operation proxy

**Tasks:**

1. **Supervisor architecture**
   ```rust
   fn main() -> Result<()> {
       let args = Args::parse();
       let caps = build_capabilities(&args)?;

       // Create control socket
       let socket_path = create_control_socket()?;

       match unsafe { fork()? } {
           ForkResult::Parent { child } => {
               // Supervisor: handle capability requests
               run_supervisor(socket_path, child, caps)
           }
           ForkResult::Child => {
               // Apply sandbox and run command
               apply_sandbox(&caps)?;
               exec_command(&args.command)
           }
       }
   }
   ```

2. **IPC protocol** (`supervisor/socket.rs`)
   ```rust
   #[derive(Serialize, Deserialize)]
   pub enum Request {
       /// Request file read (proxied through supervisor)
       ReadFile { path: PathBuf },

       /// Request file write (proxied through supervisor)
       WriteFile { path: PathBuf, content: Vec<u8> },

       /// Request new capability for future children
       ExpandCapability { cap: Capability },

       /// Request to spawn new process with expanded caps
       SpawnExpanded {
           command: Vec<String>,
           additional_caps: Vec<Capability>,
       },
   }

   #[derive(Serialize, Deserialize)]
   pub enum Response {
       FileContent(Vec<u8>),
       WriteOk,
       CapabilityGranted,
       CapabilityDenied { reason: String },
       SpawnedPid(u32),
       Error(String),
   }
   ```

3. **User prompt** (`supervisor/prompt.rs`)
   ```rust
   pub fn prompt_capability(req: &Request, pid: u32) -> Decision {
       // Clear line, show prompt
       eprintln!("\n┌─ nono: Capability Request ─────────────────────┐");
       eprintln!("│ Process: PID {}                              ", pid);
       eprintln!("│ Request: {:?}", req);
       eprintln!("│                                                │");
       eprintln!("│ [A]pprove  [D]eny  [V]iew  [?] Help            │");
       eprintln!("└────────────────────────────────────────────────┘");

       loop {
           let input = read_char()?;
           match input.to_ascii_lowercase() {
               'a' => return Decision::Approve,
               'd' => return Decision::Deny,
               'v' => { show_details(req); continue; }
               '?' => { show_help(); continue; }
               _ => continue,
           }
       }
   }
   ```

4. **nono-grant client** (`grant/mod.rs`)
   ```rust
   // Separate binary that runs inside sandbox
   // Connects to supervisor socket and requests capabilities

   fn main() -> Result<()> {
       let args = GrantArgs::parse();

       let socket_path = std::env::var("NONO_SOCKET")?;
       let mut stream = UnixStream::connect(socket_path)?;

       let request = Request::ExpandCapability {
           cap: Capability::FsRead(args.path.clone()),
       };

       serde_json::to_writer(&mut stream, &request)?;
       let response: Response = serde_json::from_reader(&stream)?;

       match response {
           Response::CapabilityGranted => {
               println!("Capability granted for future processes.");
               println!("Note: Current process still has original restrictions.");
           }
           Response::CapabilityDenied { reason } => {
               eprintln!("Denied: {}", reason);
               std::process::exit(1);
           }
           _ => unreachable!(),
       }

       Ok(())
   }
   ```

5. **File proxy** (`supervisor/proxy.rs`)
   ```rust
   // For existing sandboxed processes that can't expand capabilities,
   // the supervisor can read/write files on their behalf

   pub fn handle_read(path: &Path, caps: &CapabilitySet) -> Result<Vec<u8>> {
       // Verify path is within granted capability (user approved)
       if !caps.allows_read(path) {
           return Err(Error::NotGranted);
       }

       std::fs::read(path)
   }
   ```

**Success criteria:**
```bash
$ nono --allow ./project-a -- bash

# Inside sandbox:
nono-sandbox> claude
Claude> I need to read ../other-project/README.md
# Claude calls nono-grant

# User sees prompt, approves
# Claude can now read the file (via proxy or new child process)
```

---

### Phase 4: Polish

**Goal:** Production-ready release.

**Scope:**
- Comprehensive tests
- Security hardening
- Documentation
- Packaging

**Tasks:**

1. **Test suite**
   - Unit tests for capability parsing
   - Integration tests for sandbox enforcement
   - Platform-specific tests

2. **Security audit**
   - Symlink resolution edge cases
   - Race condition analysis
   - Fuzzing capability parsing

3. **Documentation**
   - README with examples
   - Man page
   - Security considerations doc

4. **Packaging**
   - Homebrew formula
   - cargo install
   - deb/rpm packages
   - AUR package

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Landlock ABI varies by kernel | Runtime detection, graceful degradation |
| macOS sandbox-exec deprecation | Apple hasn't deprecated sandbox_init() API |
| seccomp complexity | Use libseccomp crate, well-tested |
| Symlink TOCTOU races | Resolve at grant time, document limitation |
| User prompt fatigue | Clear prompts, remember decisions option |

---

## Timeline Estimate

| Phase | Scope | Status |
|-------|-------|--------|
| Phase 1 | MVP filesystem sandbox | Complete |
| Phase 2 | Network isolation | Complete (TCP blocking on Linux 6.7+, full on macOS) |
| Phase 3 | Runtime expansion | Not started |
| Phase 4 | Polish and release | Not started |

---

## Open Implementation Questions

1. **macOS FFI vs sandbox-exec:** Direct FFI to `sandbox_init()` is cleaner but requires more code. `sandbox-exec` wrapper is simpler but requires re-exec.

2. **Async vs sync supervisor:** Tokio for async would be cleaner for handling multiple socket connections, but adds complexity. Could start with blocking I/O.

3. **REPL mode:** Do we need an interactive shell mode (`nono>` prompt) or just `nono -- command`? Probably start with launcher-only.

4. **Executable allowlist enforcement:** Path-based is simple. Hash verification is more secure but adds complexity. Start with path-based.

5. **DNS resolution:** When blocking network, DNS still needs to resolve allowed domains. Options:
   - Allow all DNS (leak)
   - Supervisor proxy DNS
   - Pre-resolve at grant time

   For MVP: Allow DNS to system resolver, document limitation.
