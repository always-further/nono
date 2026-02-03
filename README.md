<div align="center">

# nono

**A secure, kernel-enforced capability sandbox for AI agents**

<a href="https://discord.gg/pPcjYzGvbS">
  <img src="https://img.shields.io/badge/Chat-Join%20Discord-7289da?style=for-the-badge&logo=discord&logoColor=white" alt="Join Discord"/>
</a>

<p>
  <a href="https://opensource.org/licenses/Apache-2.0">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"/>
  </a>
  <a href="https://github.com/lukehinds/nono/actions/workflows/ci.yml">
    <img src="https://github.com/lukehinds/nono/actions/workflows/ci.yml/badge.svg" alt="CI Status"/>
  </a>
  <a href="https://discord.gg/pPcjYzGvbS">
    <img src="https://img.shields.io/discord/1384081906773131274?color=7289da&label=Discord&logo=discord&logoColor=white" alt="Discord"/>
  </a>
</p>

</div>

> [!WARNING]
> This is an early alpha release that has not undergone comprehensive security auditing or peer review. Some of the core policy files are still undergoing changes. Although care and attention has been made and the author has a long background in security, there are no guarantees regarding maturity or stability. Not recommended for production environments. Please do raise bugs, if you see something wrong, you're probably right. 

**nono** is a secure, kernel-enforced capability shell for running untrusted AI agents and processes. Unlike policy-based sandboxes that intercept and filter operations, nono leverages OS security primitives (Landlock on Linux, Seatbelt on macOS) to create an environment where unauthorized operations are structurally impossible.

## Quick Start

### Homebrew (macOS)

```bash
brew tap lukehinds/nono 
brew install nono
```

### Prebuilt Binaries
Download the latest release from the [Releases](https://github.com/lukehinds/nono/releases) page.

### Build from Source

```bash
git clone https://github.com/lukehinds/nono.git
cd nono
cargo build --release
```

## Features

- **No escape hatch** - Once inside nono, there is no mechanism to bypass restrictions
- **Agent agnostic** - Works with any AI agent (Claude, GPT, opencode, openclaw) or any process
- **OS-level enforcement** - Kernel denies unauthorized operations
- **Destructive command blocking** - Blocks dangerous commands like `rm`, `dd`, `chmod` by default
- **Cross-platform** - Linux (Landlock) and macOS (Seatbelt)

## Usage

```bash
# Allow read+write to current directory
nono run --allow . -- command

# Separate read and write permissions
nono run --read ./src --write ./output -- cargo build

# Multiple paths
nono run --allow ./project-a --allow ./project-b -- command

# Block network access
nono run --allow . --net-block -- command

# Dry run (show what would be sandboxed)
nono run --allow . --dry-run -- command

# Check why a path would be blocked
nono why ~/.ssh/id_rsa
```

## Command Blocking

nono blocks dangerous commands by default to prevent AI agents from accidentally (or maliciously) causing harm. This provides defense-in-depth beyond filesystem restrictions.

### Blocked Commands

The following categories of commands are blocked by default:

| Category | Commands |
|----------|----------|
| File destruction | `rm`, `rmdir`, `shred`, `srm` |
| Disk operations | `dd`, `mkfs`, `fdisk`, `parted`, `wipefs` |
| Permission changes | `chmod`, `chown`, `chgrp`, `chattr` |
| System modification | `shutdown`, `reboot`, `halt`, `systemctl` |
| Package managers | `apt`, `brew`, `pip`, `yum`, `pacman` |
| File operations | `mv`, `cp`, `truncate` |
| Privilege escalation | `sudo`, `su`, `doas`, `pkexec` |
| Network exfiltration | `scp`, `rsync`, `sftp`, `ftp` |

### Overriding Command Blocks

```bash
# Allow a specific blocked command (use with caution)
nono run --allow . --allow-command rm -- rm ./temp-file.txt

# Block an additional command
nono run --allow . --block-command my-dangerous-tool -- my-script.sh
```

### Kernel-Level Protection

Even if a command is allowed via `--allow-command`, nono applies kernel-level protection that blocks:

- **File deletion** - `unlink`/`rmdir` syscalls are blocked
- **File truncation** - Cannot zero out files via truncation

This means even if `rm` is allowed, the actual deletion is blocked by the kernel:

```bash
$ nono run --allow /tmp/test --allow-command rm -- rm /tmp/test/file.txt
rm: /tmp/test/file.txt: Operation not permitted
```

## How It Works

```
┌─────────────────────────────────────────────────┐
│  Terminal                                       │
│                                                 │
│  $ nono run --allow ./project -- claude         │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │  nono (applies sandbox, then exec)        │  │
│  │                                           │  │
│  │  ┌─────────────────────────────────────┐  │  │
│  │  │  Claude Code (sandboxed)            │  │  │
│  │  │  - Can read/write ./project         │  │  │
│  │  │  - Cannot access ~/.ssh, ~/.aws...  │  │  │
│  │  │  - Network: allowed (or blocked)    │  │  │
│  │  └─────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Platform Support

| Platform | Mechanism | Kernel | Status |
|----------|-----------|--------|--------|
| macOS | Seatbelt | 10.5+ | Filesystem + Network |
| Linux | Landlock | 5.13+ | Filesystem |
| Linux | Landlock | 6.7+ | Filesystem + Network (TCP) |
| Windows | - | - | Not yet supported |

## Roadmap

- [x] **Phase 1**: Filesystem sandbox (MVP)
- [x] **Phase 2**: Network isolation (TCP blocking on Linux 6.7+, full on macOS)
- [ ] **Phase 3**: Runtime capability expansion
- [ ] **Phase 4**: Polish and release

See [SPEC.md](./SPEC.md) and [IMPLEMENTATION.md](./IMPLEMENTATION.md) for detailed design documents.

## Security Model

nono follows a capability-based security model with defense-in-depth:

1. **Command validation** - Dangerous commands (rm, dd, chmod, etc.) are blocked before execution
2. **Sandbox applied** - OS-level restrictions are applied (irreversible)
3. **Kernel enforcement** - Even allowed paths cannot have files deleted or truncated
4. **Command executed** - The command runs with only granted capabilities
5. **All children inherit** - Subprocesses also run under restrictions

### Defense Layers

| Layer | Protection | Bypass |
|-------|------------|--------|
| Command blocklist | Blocks known-dangerous binaries | `--allow-command` |
| Kernel (delete) | Blocks unlink/rmdir syscalls | None |
| Kernel (truncate) | Blocks file truncation | None |
| Filesystem sandbox | Restricts path access | Explicit `--allow` |
| Network sandbox | Blocks network access | Remove `--net-block` |

The key difference from policy-based sandboxes: there is no "escape hatch" API. The agent cannot request more permissions because the mechanism doesn't exist.

## License

Apache-2.0
