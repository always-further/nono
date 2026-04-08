<div align="center">

<img src="assets/nono-logo.png" alt="nono logo" width="600"/>

<p>
  From the creator of
  <a href="https://sigstore.dev"><strong>Sigstore</strong></a>
  <br/>
  <sub>The standard for secure software attestation, used by PyPI, npm, brew, and Maven Central</sub>
</p>
<p>
  <a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"/></a>
  <a href="https://github.com/always-further/nono/actions/workflows/ci.yml"><img src="https://github.com/always-further/nono/actions/workflows/ci.yml/badge.svg" alt="CI Status"/></a>
  <a href="https://docs.nono.sh"><img src="https://img.shields.io/badge/Docs-docs.nono.sh-green.svg" alt="Documentation"/></a>
</p>
<p>
  <a href="https://discord.gg/pPcjYzGvbS">
    <img src="https://img.shields.io/badge/Chat-Join%20Discord-7289da?style=for-the-badge&logo=discord&logoColor=white" alt="Join Discord"/>
  </a>
  <a href="https://github.com/marketplace/actions/agent-sign">
    <img src="https://img.shields.io/badge/Secure_Action-agent--sign-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="agent-sign GitHub Action"/>
  </a>
</p>

</div>

> [!WARNING]
> Early alpha -- not yet audited for production use. Active development may cause breakage. Please don't point a coding agent at the repo and raise large LLM-generated security issues, we likely already know about them; instead ask in [Discord](https://discord.gg/pPcjYzGvbS) first.

---

nono wraps any AI agent or process in a kernel-isolated sandbox in seconds. No hypervisor. No infrastructure required. A single binary, zero added latency, and flexible enough to fit a solo developer's workflow or a fleet of agents running at scale in production.

**Platform support:** macOS, Linux, and [WSL2](https://nono.sh/docs/cli/internals/wsl2). Native Windows coming soon.

**Install:**
```bash
brew install nono
```

Other options in the [Installation Guide](https://docs.nono.sh/cli/getting_started/installation).

---

## Latest News

**Detach and reattach to sandboxed agents** -- Run agents in the background with `nono run --detach`, reconnect with `nono attach`. Includes `nono ps`, `nono stop`, and `nono inspect`. ([#526](https://github.com/always-further/nono/pull/526))

**WSL2 support** -- Auto-detection with ~84% feature coverage out of the box. Run `nono setup --check-only` to see what's available. ([#522](https://github.com/always-further/nono/pull/522))

**Portable capability manifests** -- Export fully-resolved sandbox configs with `nono policy show <profile> --format manifest` for CI/Kubernetes deployment. ([#534](https://github.com/always-further/nono/pull/534))

**API endpoint filtering** -- Control which endpoints agents can reach with L7 filtering: `--allow-endpoint 'github:GET:/repos/*/issues/**'`. ([#513](https://github.com/always-further/nono/pull/513))

**Custom CAs and file-based credentials for k8s** -- `tls_ca` for self-signed endpoints ([#548](https://github.com/always-further/nono/pull/548)), `file://` URIs for mounted secrets ([#552](https://github.com/always-further/nono/pull/552)).

[All updates](https://github.com/always-further/nono/discussions/categories/announcements)

---

## Quick Start

```bash
# Any CLI agent -- just put your command after --
$ nono run --profile claude-code -- claude

# or with tmux style multiplexer and atomic snapshots
$ nono run --detached --profile claude-code --rollback -- claude
Started detached session 7a6a652f7273fe60.
Attach with: nono attach 7a6a652f7273fe60

# Any given command
nono run -- python3 my_agent.py
nono run --read /data -- npx @modelcontextprotocol/server-filesystem /data
nono run --profile codex -- codex
```

Built-in profiles for [Claude Code](https://docs.nono.sh/cli/clients/claude-code), [Codex](https://docs.nono.sh/cli/clients/codex), [OpenCode](https://docs.nono.sh/cli/clients/opencode), [OpenClaw](https://docs.nono.sh/cli/clients/openclaw), and [Swival](https://docs.nono.sh/cli/clients/swival) -- or [define your own](https://docs.nono.sh/cli/features/profiles-groups).

## Library

The core is a Rust library that can be embedded into any application. Policy-free -- it applies only what clients explicitly request.

```rust
use nono::{CapabilitySet, Sandbox};

let mut caps = CapabilitySet::new();
caps.allow_read("/data/models")?;
caps.allow_write("/tmp/workspace")?;

Sandbox::apply(&caps)?;  // Irreversible -- kernel-enforced from here on
```

Also available as [Python](https://github.com/always-further/nono-py) , [TypeScript](https://github.com/always-further/nono-ts), [Go](https://github.com/always-further/nono-go)  bindings.

## Key Features

| Feature | Description |
|---------|-------------|
| **Kernel sandbox** | Landlock (Linux) + Seatbelt (macOS). Irreversible, inherited by child processes. |
| **Credential injection** | Proxy mode keeps API keys outside the sandbox entirely. Supports keystore, 1Password, Apple Passwords. |
| **Attestation** | Sigstore-based signing and verification of instruction files (SKILLS.md, CLAUDE.md, etc.). |
| **Network filtering** | Allowlist-based host and endpoint filtering via local proxy. Cloud metadata endpoints hard-denied. |
| **Snapshots** | Content-addressable rollback with SHA-256 dedup and Merkle tree integrity. |
| **Policy profiles** | Pre-built profiles for popular agents and use cases. Custom profile builder for your own needs. |
| **Audit logs** | Verifiable logs of all agent actions, with optional remote upload and monitoring. |
| **Cross-platform** | Support for macOS, Linux, and WSL2. Native Windows support in planning. |
| **Multiplexing** | Run multiple agents in parallel with separate sandboxes. Attach/detach to long-running agents. |
| **Runs anywhere** | Local CLI, CI pipelines, Containers / Kubernetes, cloud VMs, microVMs. |

See the [full documentation](https://docs.nono.sh) for details and configuration.

## Contributing

We encourage using AI tools to contribute. However, you must understand and carefully review any AI-generated code before submitting. Security is paramount. If you don't understand how a change works, ask in [Discord](https://discord.gg/pPcjYzGvbS) first.

## Security

If you discover a security vulnerability, please **do not open a public issue**. Follow the process in our [Security Policy](https://github.com/always-further/nono/security).

## License

Apache-2.0
