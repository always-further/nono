<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/logo-light.png" />
    <img alt="nono logo" src="./assets/nono-mascot.png" style="width:80%;max-width:80%;height:auto;display:block;margin:0 auto;" />
  </picture>
  <h3>Don't YOLO! When you can nono!</h3>

  <!-- CTA Buttons -->
  <p>
    <a href="https://discord.gg/pPcjYzGvbS">
      <img src="https://img.shields.io/badge/Chat-Join%20Discord-7289da?style=for-the-badge&logo=discord&logoColor=white" alt="Join Discord"/>
    </a>
  </p>

  <!-- Badges -->
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

## A secure shell for AI agents.

**nono** is a secure, OS-enforced capability shell for running untrusted AI agents and processes. Unlike policy-based sandboxes that intercept and filter operations, nono leverages OS security primitives (Landlock on Linux, Seatbelt on macOS) to create an environment where unauthorized operations are structurally impossible.

## Quick Start

```bash
# Build
cargo build --release

# Run a command with filesystem access only to current directory
nono run --allow . -- your-command

# Example: Run Claude Code with restricted access
nono run --allow ./my-project -- claude

# Block network access (air-gapped mode)
nono run --allow . --net-block -- your-command
```

## Features

- **No escape hatch** - Once inside nono, there is no mechanism to bypass restrictions
- **Agent agnostic** - Works with any AI agent (Claude, GPT, opencode, openclaw) or any process
- **OS-level enforcement** - Kernel denies unauthorized operations
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

nono follows a capability-based security model:

1. **User enters sandbox** - You start nono with explicit capabilities
2. **Sandbox applied** - OS-level restrictions are applied (irreversible)
3. **Command executed** - The command runs with only granted capabilities
4. **All children inherit** - Subprocess also run under restrictions

The key difference from policy-based sandboxes: there is no "escape hatch" API. The agent cannot request more permissions because the mechanism doesn't exist.

## License

Apache-2.0
