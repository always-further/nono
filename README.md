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
</p>

</div>

> [!WARNING]
> This is an early alpha release that has not undergone comprehensive security audits. While we have taken care to implement robust security measures, there may still be undiscovered issues. We do not recommend using this in production until we release a stable version of 1.0.

> [!NOTE]
> We are just wrapping up the separation of the CLI and core library. The last stable CLI release is still available on homebrew tap (version v0.5.0) and is fine to use. We will update this README with installation instructions when all library clients are ready. We plan to submit to homebrew-core, but the repo is not yet 30 days old.

AI agents get filesystem access, run shell commands, and are inherently open to prompt injection. The standard response is guardrails and policies. The problem is that policies can be bypassed and guardrails linguistically overcome.

Kernel-enforced sandboxing (Landlock on Linux, Seatbelt on macOS) blocks unauthorized access at the syscall level. Destructive commands are denied before they run. Secrets are injected securely without touching disk. Every filesystem change gets a rollback snapshot. Every command leaves a tamper resistant trail. When the agent needs to do something outside its permissions, a supervisor handles approval.

## CLI

The CLI builds on the library to provide a ready-to-use sandboxing tool, popular with coding-agents, with built-in profiles, policy groups, and interactive UX.

```bash
# Claude Code with inbuilt profile
nono run --profile claude-code -- claude
# OpenCode with custom permissions
nono run --profile opencode --allow-cwd/src --allow-cwd/output -- opencode
# OpenClaw with custom permissions
nono run --profile openclaw --allow-cwd -- openclaw gateway
# Any command with custom permissions
nono run --read ./src --write ./output -- cargo build
```

## Library (Coming very Soon!)

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

### Secrets and Key Isolation

Credentials (API keys, tokens, passwords) are loaded from the system keystore and injected into the sandboxed process as environment variables at runtime. The keystore files themselves are never exposed to the sandboxed process, preventing exfiltration of raw secrets even if the agent is compromised.

```bash
# Store a secret in the system keystore, then inject it at runtime
security add-generic-password \
  -T /usr/local/bin/nono \
  -s "nono" \
  -a "openai_api_key" \
  -w "my_super_secret_api_key"

nono run --secrets  openai_api_key --allow-cwd -- agent-command
```

### Composable Policy Groups (Coming Soon!)

Security policy is defined as named groups in a single JSON file. Each group specifies allow/deny rules for filesystem paths, command execution, and platform-specific behavior. Profiles reference groups by name, making it straightforward to compose fine-grained policies from reusable building blocks. Profile-level filesystem entries and CLI overrides are applied additively on top.

Groups define reusable rules:

```json
{
  "deny_credentials": {
    "description": "Block access to cryptographic keys, tokens, and cloud credentials",
    "deny": {
      "access": ["~/.ssh", "~/.gnupg", "~/.aws", "~/.kube", "~/.docker"]
    }
  },
  "node_runtime": {
    "description": "Node.js runtime and package manager paths",
    "allow": {
      "read": ["~/.nvm", "~/.fnm", "~/.npm", "/usr/local/lib/node_modules"]
    }
  }
}
```

Profiles compose groups by name and add their own filesystem entries on top:

```json
{
  "claude-code": {
    "security": {
      "groups": ["user_caches_macos", "node_runtime", "rust_runtime", "unlink_protection"]
    },
    "filesystem": {
      "allow": ["$HOME/.claude"],
      "read_file": ["$HOME/.gitconfig"]
    }
  }
}
```

### Destructive Command Blocking

Dangerous commands (`rm`, `dd`, `chmod`, `sudo`, `scp`, and others) are blocked before execution. This is layered on top of the kernel sandbox as defense-in-depth -- even if a command were allowed, the sandbox would still enforce filesystem restrictions. Commands can be selectively allowed or additional commands blocked per invocation.

```bash
# rm is blocked by default
$ nono run --allow-cwd -- rm -rf /
nono: blocked command: rm

# Selectively allow a blocked command
nono run --allow-cwd --allow-command rm -- rm ./temp-file.txt
```

### Undo and Snapshots (Coming Soon!)

nono takes content-addressable snapshots of your working directory before the sandboxed process runs. If the agent makes unwanted changes, you can interactively review and restore individual files or the entire directory to its previous state. Snapshots use SHA-256 deduplication and Merkle tree commitments for integrity verification.

```bash
# List snapshots taken during sandboxed sessions
nono rollback list

# Interactively review and restore changes
nono rollback restore
```

### Supervisor and Capability Expansion (Coming Soon!)

On Linux, nono can run in supervised mode where the sandboxed process starts with minimal permissions. When the agent needs access to a file outside its sandbox, the request is intercepted via seccomp user notification and routed to the supervisor, which prompts the user for approval. Approved access is granted transparently by injecting file descriptors -- the agent never needs to know about nono. Sensitive paths (system config, SSH keys, etc.) are configured as never-grantable regardless of user approval.

```bash
# Run with rollback snapshots and capability expansion
nono run --rollback --supervised --allow-cwd -- claude
```
 
### Audit Trail (Coming Soon!)

Every sandboxed session records what command was run, when it started and ended, its exit code, tracked paths, and cryptographic snapshot commitments. Session logs can be inspected as structured JSON for compliance and forensics.

```bash
# Show audit record for a session
nono audit show 20260216-193311-20751 --json
❯ nono audit show 20260216-193311-20751 --json
{
  "command": [
    "sh",
    "-c",
    "echo done"
  ],
  "ended": "2026-02-16T19:33:11.519810+00:00",
  "exit_code": 0,
  "merkle_roots": [
    "2ee13961d5b9ec78cca0c2bd1bad29ea39c3b2256df00dec97978e131961b753",
    "2ee13961d5b9ec78cca0c2bd1bad29ea39c3b2256df00dec97978e131961b753"
  ],
  "session_id": "20260216-193311-20751",
  "snapshots": [
    {
      "changes": [],
      "file_count": 1,
      "merkle_root": "2ee13961d5b9ec78cca0c2bd1bad29ea39c3b2256df00dec97978e131961b753",
      "number": 0,
      "timestamp": "1771270391"
    },
    {
      "changes": [],
      "file_count": 1,
      "merkle_root": "2ee13961d5b9ec78cca0c2bd1bad29ea39c3b2256df00dec97978e131961b753",
      "number": 1,
      "timestamp": "1771270391"
    }
  ],
  "started": "2026-02-16T19:33:11.496516+00:00",
  "tracked_paths": [
    "/Users/jsmith/project"
  ]
}
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

nono is agent-agnostic and works with any CLI command. See the [full documentation](https://docs.nono.sh) for usage details, configuration, and integration guides.

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
