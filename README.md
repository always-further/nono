<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="./assets/logo-light.png" />
    <img alt="NONO logo" src="./assets/nono-mascot.png" style="width:80%;max-width:80%;height:auto;display:block;margin:0 auto;" />
  </picture>
  <h3>Don't YOLO! When you can NONO!</h3>

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
    <a href="https://github.com/lukehinds/deepfabric/actions/workflows/test.yml">
      <img src="https://github.com/lukehinds/deepfabric/actions/workflows/test.yml/badge.svg" alt="CI Status"/>
    </a>
    <a href="https://discord.gg/pPcjYzGvbS">
      <img src="https://img.shields.io/discord/1384081906773131274?color=7289da&label=Discord&logo=discord&logoColor=white" alt="Discord"/>
    </a>
  </p>
</div>

## A secure shell for AI agents.

**NONO** is a secure, OS-enforced capability shell for running untrusted AI agents and processes. Unlike policy-based sandboxes that intercept and filter operations, NONO leverages OS security primitives (Landlock on Linux, Seatbelt on macOS) to create an environment where unauthorized operations are structurally impossible.

## Quick Start

```bash
# Build
cargo build --release

# Run a command with filesystem access only to current directory
nono --allow . -- your-command

# Example: Run Claude Code with restricted access
nono --allow ./my-project -- claude
```

## Features

- **No escape hatch** - Once inside nono, there is no mechanism to bypass restrictions
- **Agent agnostic** - Works with any AI agent (Claude, GPT, opencode, openclaw) or any process
- **OS-level enforcement** - Kernel denies unauthorized operations
- **Cross-platform** - Linux (Landlock) and macOS (Seatbelt)

## Usage

```bash
# Allow read+write to current directory
nono --allow . -- command

# Separate read and write permissions
nono --read ./src --write ./output -- cargo build

# Multiple paths
nono --allow ./project-a --allow ./project-b -- command

# Dry run (show what would be sandboxed)
nono --allow . --dry-run -- command
```

## How It Works

```
┌─────────────────────────────────────────────────┐
│  Terminal                                       │
│                                                 │
│  $ nono --allow ./project -- claude             │
│                                                 │
│  ┌───────────────────────────────────────────┐  │
│  │  nono (applies sandbox, then exec)        │  │
│  │                                           │  │
│  │  ┌─────────────────────────────────────┐  │  │
│  │  │  Claude Code (sandboxed)            │  │  │
│  │  │  - Can read/write ./project         │  │  │
│  │  │  - Cannot access other dirs         │  │  │
│  │  │  - Network blocked                  │  │  │
│  │  └─────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
```

## Platform Support

| Platform | Mechanism | Status |
|----------|-----------|--------|
| macOS | Seatbelt | Phase 1 complete |
| Linux | Landlock | Phase 1 complete (untested) |
| Windows | - | Not yet supported |

## Roadmap

- [x] **Phase 1**: Filesystem sandbox (MVP)
- [ ] **Phase 2**: Network isolation
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
