<div align="center" markdown>
  <img alt="nono mascot" src="assets/nono-mascot.png" style="width:50%;max-width:400px;height:auto;" />
  <h1>nono</h1>
  <p>A capability-based shell for running untrusted AI agents with OS-enforced isolation.</p>
</div>

AI coding agents are powerful but can also be dangerous. They can read your SSH keys, exfiltrate secrets to remote servers, or delete critical files. Current solutions rely on the agent to police itself - but bugs happen and security vulnerabilities are common.

## The Solution

nono uses kernel-level security primitives (Landlock on Linux, Seatbelt on macOS) to create sandboxes where unauthorized operations are **structurally impossible**. Once the sandbox is applied, there is no API to escape it - not even for nono itself.

## Quick Start

```bash
# Build nono
cargo build --release

# Run Claude Code with access only to current directory
nono run --allow . -- claude

# Run a build tool with read access to source, write access to output
nono run --read ./src --allow ./target -- cargo build

# Preview what permissions would be granted (dry run)
nono run --allow . --dry-run -- my-agent

# Check why a path would be blocked
nono why ~/.ssh/id_rsa
```

## Commands

| Command | Description |
|---------|-------------|
| `nono run` | Run a command inside the sandbox |
| `nono why` | Check why a path would be blocked or allowed |

## Key Features

- **No escape hatch** - Once sandbox is applied, it cannot be expanded or removed
- **OS-level enforcement** - Kernel enforces restrictions, not the application
- **Agent-agnostic** - Works with any CLI tool or AI agent
- **Process inheritance** - Child processes automatically inherit all restrictions
- **Sensitive path protection** - SSH keys, cloud credentials, and shell configs blocked by default
- **Agent awareness** - Environment variables help agents understand sandbox state

## Platform Support

| Platform | Mechanism | Status |
|----------|-----------|--------|
| Linux (kernel 5.13+) | Landlock LSM | Supported |
| macOS | Seatbelt (sandbox_init) | Supported |
| Windows | - | Not supported |

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                     nono process                        │
│  1. Parse capabilities from CLI                         │
│  2. Apply kernel sandbox (irreversible)                 │
│  3. exec() into target command                          │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                   Sandboxed Agent                       │
│  - Can only access explicitly granted paths             │
│  - Network allowed by default (use --net-block)         │
│  - All child processes inherit restrictions             │
│  - No way to escape or expand permissions               │
└─────────────────────────────────────────────────────────┘
```

## Next Steps

- [Installation](installation.md) - Get nono running on your system
- [CLI Reference](usage/flags.md) - Complete flag documentation
- [Security Model](security/index.md) - Understand the security guarantees
