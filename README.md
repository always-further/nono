<div align="center">

<img src="assets/nono-logo.png" alt="nono logo" width="600"/>

**AI agent security that makes the dangerous bits structurally impossible.**

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
  <a href="https://github.com/marketplace/actions/nono-attest">
    <img src="https://img.shields.io/badge/Secure_Action-nono--attest-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="nono-attest GitHub Action"/>
  </a>
</p>

</div>

> [!WARNING]
> This is an early alpha release that has not undergone comprehensive security audits. While we have taken care to implement robust security measures, there may still be undiscovered issues. We do not recommend using this in production until we release a stable version of 1.0.

> [!NOTE]
> See our [latest release](https://github.com/always-further/nono/releases/latest) or [CHANGELOG.md](./CHANGELOG.md) for release notes.

AI agents get filesystem access, run shell commands, and are inherently open to prompt injection. The standard response is guardrails and policies. The problem is that policies can be bypassed and guardrails linguistically overcome.

Kernel-enforced sandboxing (Landlock/Seatbelt) blocks unauthorized access at the syscall level. Every filesystem change gets a rollback snapshot with integrity protection. Destructive commands are denied before they run. Secrets are injected without touching disk. When the agent needs access outside its permissions, a kernel-mediated supervisor intercepts the syscall via seccomp BPF, opens the file after user approval, and injects only the file descriptor — the agent never executes its own `open()`. No root or `CAP_SYS_ADMIN` required. Runs on any Linux kernel 5.13+ — bare metal, containers(Docker,Podman,K8s), Firecracker, Kata.

## CLI

The CLI is the quickest way to get going! zero startup latency, no need to install hypervisors, runtimes, mount volumes...sandboxed and protected in a single command

```bash
# Any CLI agent — just put your command after --
nono run --profile claude-code -- claude
nono run --profile opencode -- opencode
nono run --profile openclaw -- openclaw

nono run --allow-cwd -- python3 my_agent.py
nono run --allow-cwd -- npx @anthropic/agent-framework

# MCP servers, agents, anything!
nono run --read /data -- npx @modelcontextprotocol/server-filesystem /data
nono run --profile pydantic-ai-agent --allow logs/ -- uv run my_agent.py
nono run --profile custom-profile -- node agent.js

# Rollback snapshots — undo everything the agent did
nono run --rollback --profile claude-code --allow-cwd -- claude

# Combine rollback, network filtering, and port binding
nono run --rollback --allow-proxy api.anthropic.ai --allow-port 8000 -- uv run uvicorn myagent.main:app --port 8000

# Network proxy — allowlist hosts, inject credentials without exposing keys
nono run --allow-proxy api.openai.com --proxy-credential openai -- python3 agent.py

# Audit trail on every session — opt out with --no-audit
nono run --no-audit --allow-cwd -- npm test

# Direct exec for scripts and piping (no parent process)
nono wrap --read ./src --write ./output -- cargo build

# Need a profile automatically applied for a specific client?
nono learn -- new-cool-coding-agent

# Why did you block that command? 
nono why --path ~/.ssh/id_rsa
DENIED
  Reason: sensitive_path
  Details: Path matches sensitive pattern 'Block access to cryptographic keys, tokens, and cloud credentials'. Access blocked by security policy.
```

Built-in profiles for [Claude Code](https://docs.nono.sh/clients/claude-code), [OpenCode](https://docs.nono.sh/clients/opencode), and [OpenClaw](https://docs.nono.sh/clients/openclaw) — or define your own with custom permissions.

## Library

The core is a Rust library that can be embedded into any application via native bindings. The library is a policy-free sandbox primitive -- it applies only what clients explicitly request.

#### <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/rust/rust-original.svg" width="18" height="18" alt="Rust"/> Rust — [crates.io](https://crates.io/crates/nono)

```rust
use nono::{CapabilitySet, Sandbox};

let mut caps = CapabilitySet::new();
caps.allow_read("/data/models")?;
caps.allow_write("/tmp/workspace")?;

Sandbox::apply(&caps)?;  // Irreversible — kernel-enforced from here on
```

#### <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/python/python-original.svg" width="18" height="18" alt="Python"/> Python — [nono-py](https://github.com/always-further/nono-py)

```python
from nono_py import CapabilitySet, AccessMode, apply

caps = CapabilitySet()
caps.allow_path("/data/models", AccessMode.READ)
caps.allow_path("/tmp/workspace", AccessMode.READ_WRITE)

apply(caps)  # Apply CapabilitySet
```

#### <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/typescript/typescript-original.svg" width="18" height="18" alt="TypeScript"/> TypeScript — [nono-ts](https://github.com/always-further/nono-ts)

```typescript
import { CapabilitySet, AccessMode, apply } from "nono-ts";

const caps = new CapabilitySet();
caps.allowPath("/data/models", AccessMode.Read);
caps.allowPath("/tmp/workspace", AccessMode.ReadWrite);

apply(caps);  // Irreversible — kernel-enforced from here on
```

## Features

### Kernel-Enforced Sandbox

nono applies OS-level restrictions that cannot be bypassed or escalated from within the sandboxed process. Permissions are defined as capabilities granted before execution -- once the sandbox is applied, it is irreversible. All child processes inherit the same restrictions.

| Platform | Mechanism | Minimum Kernel |
|----------|-----------|----------------|
| macOS | Seatbelt | 10.5+ |
| Linux | Landlock | 5.13+ |

```bash
# Grant read to src, write to output — everything else is denied by the kernel
nono run --read ./src --write ./output -- cargo build
```

### Credential Injection

Two modes: **proxy injection** keeps credentials entirely outside the sandbox — the agent connects to `localhost` and the proxy injects real API keys into upstream requests. **Env injection** loads secrets from the OS keystore or 1Password and injects them as environment variables before the sandbox locks.

```bash
# Proxy mode — agent never sees the API key, even in its own memory
nono run --network-profile claude-code --proxy-credential openai -- my-agent

# Env mode — simpler, but secret is in the process environment
nono run --env-credential openai_api_key --allow-cwd -- my-agent

# 1Password — use op:// URIs with an explicit env var name
nono run --env-credential 'op://Development/OpenAI/credential=OPENAI_API_KEY' --allow-cwd -- my-agent
```

### Agent SKILL Provenance and Supply Chain Security

Instruction files (SKILLS.md, CLAUDE.md, AGENT.MD) and associated artifacts such as scripts are a supply chain attack vector. nono cryptographically signs and verifies them using Sigstore attestation with DSSE envelopes and in-toto / SLSA style statements. It supports keyed signing (system keystore) and keyless signing (OIDC via GitHub Actions + Fulcio + Rekor). Upon execution, nono verifies the signature, checks the signing certificate against trusted roots, and validates the statement predicates (e.g. signed within the last 30 days, signed by a trusted maintainer).

<p align="center">
  <a href="https://github.com/marketplace/actions/nono-attest">
    <img src="https://img.shields.io/badge/GitHub_Action-nono--attest-2088FF?style=for-the-badge&logo=github-actions&logoColor=white" alt="nono-attest GitHub Action"/>
  </a>
</p>

Sign instruction files directly within GitHub Actions workflows. Users can then verify that files originate from the expected repository and branch, signed by a trusted maintainer.

### Network Filtering

Allowlist-based host filtering via a local proxy. The sandbox blocks all direct outbound connections — the agent can only reach explicitly allowed hosts. Cloud metadata endpoints are hardcoded as denied.

```bash
nono run --allow-proxy api.openai.com --allow-proxy api.anthropic.com -- my-agent

# Keep the claude-code profile, but allow unrestricted network for this session
nono run --profile claude-code --allow-net -- claude
```

### Supervisor and Capability Expansion

On Linux, seccomp user notification intercepts syscalls when the agent needs access outside its sandbox. The supervisor prompts the user, then injects the file descriptor directly — the agent never executes its own `open()`. Sensitive paths are never-grantable regardless of approval.

```bash
nono run --rollback --allow-cwd -- claude
```

### Undo and Snapshots

Content-addressable snapshots of your working directory taken before and during sandboxed execution. SHA-256 deduplication and Merkle tree commitments for integrity verification. Interactively review and restore individual files or the entire directory. Known regenerable directories (`.git`, `target`, `node_modules`, etc.) and directories with more than 10,000 files are auto-excluded from snapshots to prevent hangs on large projects.

```bash
# Zero-flag usage — auto-excludes large/regenerable directories
nono run --rollback --allow-cwd -- npm test

# Force-include an auto-excluded directory
nono run --rollback --rollback-include target -- cargo build

# Exclude a custom directory from rollback
nono run --rollback --rollback-exclude vendor -- go test ./...

# Disable rollback entirely
nono run --no-rollback --allow-cwd -- npm test

nono rollback list
nono rollback restore
```

### Composable Policy Groups

Security policy defined as named groups in a single JSON file. Profiles reference groups by name — compose fine-grained policies from reusable building blocks.

```json
{
  "deny_credentials": {
    "deny": { "access": ["~/.ssh", "~/.gnupg", "~/.aws", "~/.kube"] }
  },
  "node_runtime": {
    "allow": { "read": ["~/.nvm", "~/.fnm", "~/.npm"] }
  }
}
```

### Destructive Command Blocking

Dangerous commands (`rm`, `dd`, `chmod`, `sudo`, `scp`) are blocked before execution. Override per invocation with `--allow-command` or permanently via `allowed_commands` in a profile.

```bash
$ nono run --allow-cwd -- rm -rf /
nono: blocked command: rm

# Override per invocation
nono run --allow-cwd --allow-command rm -- rm ./temp-file.txt

# Override via profile
# { "security": { "allowed_commands": ["rm"] } }
nono run --profile my-profile -- rm /tmp/old-file.txt
```

> [!WARNING]
> Command blocking is defense-in-depth layered on top of the kernel sandbox. Commands can bypass this via `sh -c '...'` or wrapper scripts — the sandbox filesystem restrictions are the real security boundary.

### Audit Trail

Every supervised session automatically records command, timing, exit code, network events, and cryptographic snapshot commitments as structured JSON. Opt out with `--no-audit`.

```bash
nono audit list
nono audit show 20260216-193311-20751 --json
```

## Quick Start

### macOS

```bash
brew tap always-further/nono
brew install nono
```

> [!NOTE]
> The package is not in homebrew official yet, [give us a star](https://github.com/always-further/nono) to help raise our profile for when we request approval.

### Linux

See the [Installation Guide](https://docs.nono.sh/installation) for prebuilt binaries and package manager instructions.

### From Source

See the [Development Guide](https://docs.nono.sh/development) for building from source.

## Supported Clients

nono ships with built-in profiles for popular AI coding agents. Each profile defines audited, minimal permissions.

| Client | Profile | Docs |
|--------|---------|------|
| **Claude Code** | `claude-code` | [Guide](https://docs.nono.sh/clients/claude-code) |
| **OpenCode** | `opencode` | [Guide](https://docs.nono.sh/clients/opencode) |
| **OpenClaw** | `openclaw` | [Guide](https://docs.nono.sh/clients/openclaw) |

Custom profiles can [extend built-in ones](https://docs.nono.sh/profiles) with `"extends": "claude-code"` to inherit all settings and add overrides. nono is agent-agnostic and works with any CLI command. See the [full documentation](https://docs.nono.sh) for usage details, configuration, and integration guides.

## Projects using nono

| Project | Repository |
|---------|------------|
| **claw-wrap** | [GitHub](https://github.com/dedene/claw-wrap) |

## Architecture

nono is structured as a Cargo workspace:

- **nono** (`crates/nono/`) -- Core library. A policy-free sandbox primitive that applies only what clients explicitly request.
- **nono-cli** (`crates/nono-cli/`) -- CLI binary. Owns all security policy, profiles, hooks, and UX.
- **nono-ffi** (`bindings/c/`) -- C FFI bindings with auto-generated header.

Language-specific bindings are maintained separately:

| Language | Repository | Package |
|----------|------------|---------|
| Python | [nono-py](https://github.com/always-further/nono-py) | PyPI |
| TypeScript | [nono-ts](https://github.com/always-further/nono-ts) | npm |

## Contributing

We encourage using AI tools to contribute to nono. However, you must understand and carefully review any AI-generated code before submitting. The security of nono is paramount -- always review and test your code thoroughly, especially around core sandboxing functionality. If you don't understand how a change works, please ask for help in the [Discord](https://discord.gg/pPcjYzGvbS) before submitting a PR.

## Security

If you discover a security vulnerability, please **do not open a public issue**. Instead, follow the responsible disclosure process outlined in our [Security Policy](https://github.com/always-further/nono/blob/main/SECURITY.md).

## License

Apache-2.0
