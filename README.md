<div align="center">

<img src="assets/logo.gif" alt="nono logo" width="600"/>

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
   <a href="https://alwaysfurther.ai/careers">
      <img src="https://img.shields.io/badge/We're_Hiring-Join_the_team-ff4f00?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="We're hiring"/>
  </a>
  <a href="https://github.com/marketplace/actions/agent-sign">
    <img src="https://img.shields.io/badge/Secure_Action-agent--sign-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="agent-sign GitHub Action"/>
  </a>
</p>

---
</div>

> [!NOTE]
> In the lead-up to a 1.0 release, APIs are stabilizing. API changes may still occur where necessary, but will be kept to a minimum.

nono is a capability-based, policy-governed runtime for AI agents.

It gives a process narrowly scoped access to the host resources it actually needs: specific paths, network destinations, sockets, environment variables, credentials, and operations. Policies are explicit, composable, auditable, and enforced by kernel primitives.

nono fits the space between "run the agent directly on my machine with full access to keys and files" and "seal it inside a separate guest OS." Agents work inside real development environments, with host resources modeled as explicit capabilities.

A profile states what the agent may touch, and nono applies it. The core library is policy-free: it applies only the capabilities a caller provides. The CLI, profiles, and registry packages carry the policy - and all inbuilt policy can be extended or overridden, since policy is fully composable.

For organizations, that means policy can be reviewed, versioned, distributed, and reused. A team can ship a standard profile for a class of agents, collect supervised audit records, preserve rollback evidence, and keep sensitive credentials in a trusted proxy path instead of injecting them directly into the agent process.


---

## Installation

**Platform support:** macOS, Linux, and [WSL2](https://nono.sh/docs/cli/internals/wsl2).

**Install:**
```bash
brew install nono
```

Other options in the [Installation Guide](https://docs.nono.sh/cli/getting_started/installation).

---

## Quick Start

`nono pull` agent packages from the [registry](https://registry.nono.sh) for all popular agents — Claude Code, Codex, Pi, Hermes, OpenCode, OpenClaw, and more — or [build your own](https://nono.sh/docs/cli/features/package-publishing) and securely share plugins, SKILLS, and hooks with the community or your team.

```bash
nono run --profile always-further/claude -- claude
```

## Libraries and Bindings

The core is a Rust library that can be embedded into any application. Policy-free - it applies only what clients explicitly request.

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
| **Audit logs** | Default event audit for supervised runs, optional append-only integrity hashing, and optional rollback-backed filesystem evidence. |
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
