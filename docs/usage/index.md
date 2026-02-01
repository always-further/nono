# Usage Overview

nono wraps any command with an OS-level sandbox. You specify what the command is allowed to access, and nono enforces those restrictions at the kernel level.

## Commands

nono provides two main commands:

| Command | Description |
|---------|-------------|
| `nono run` | Run a command inside the sandbox |
| `nono why` | Check why a path would be blocked or allowed |

## Running Commands (`nono run`)

### Basic Syntax

```bash
nono run [OPTIONS] -- <COMMAND> [ARGS...]
```

The `--` separator is recommended. Everything after it is the command to run.

### Minimal Example

```bash
# Grant read+write access to current directory, run claude
nono run --allow . -- claude
```

## Checking Path Access (`nono why`)

### Basic Syntax

```bash
nono why [OPTIONS] <PATH>
```

### Examples

```bash
# Check if a sensitive path would be blocked
nono why ~/.ssh/id_rsa
# Output: BLOCKED: ~/.ssh/id_rsa is a sensitive path

# Check with suggestions for granting access
nono why -s ./my-project
# Output includes: nono run --allow ./my-project -- <command>
```

### Options

| Flag | Description |
|------|-------------|
| `-s`, `--suggest` | Show flags needed to grant access |

## Understanding Permissions

nono provides three levels of filesystem access:

| Flag | Access Level | Use Case |
|------|--------------|----------|
| `--allow` / `-a` | Read + Write | Working directories, project folders |
| `--read` / `-r` | Read Only | Source code, configuration |
| `--write` / `-w` | Write Only | Output directories, logs |

### Directory vs File Permissions

- **Directory flags** (`--allow`, `--read`, `--write`) grant recursive access
- **File flags** (`--allow-file`, `--read-file`, `--write-file`) grant access to a single file

```bash
# Recursive access to entire directory
nono run --allow ./project -- command

# Access to single config file only
nono run --read-file ./config.toml -- command
```

## Network Access

Network is **allowed by default**. Use `--net-block` to disable outbound connections:

```bash
# Block network access for offline build
nono run --allow . --net-block -- cargo build
```

!!! note "Binary Control"
    Network access is currently all-or-nothing. You can either allow all network access (default) or block it entirely with `--net-block`.

    Granular filtering (allowing only specific domains) is not yet supported due to technical limitations in Apple Seatbelt and requires experimentation. This feature may be added in a future release.

## What Happens at Runtime

1. **Parse** - nono parses your capability flags
2. **Canonicalize** - All paths are resolved to absolute paths (prevents symlink escapes)
3. **Apply Sandbox** - Kernel sandbox is initialized (irreversible)
4. **Execute** - nono exec()s into your command, inheriting the sandbox
5. **Enforce** - Kernel blocks any unauthorized access attempts

## Environment Variables

When running inside nono, these environment variables are set:

| Variable | Description |
|----------|-------------|
| `NONO_ACTIVE` | Set to `1` when running under nono |
| `NONO_ALLOWED` | Colon-separated list of allowed paths |
| `NONO_NET` | `allowed` or `blocked` |
| `NONO_BLOCKED` | Colon-separated list of blocked sensitive paths |
| `NONO_HELP` | Help text for requesting additional access |
| `NONO_CONTEXT` | Full explanation of sandbox state for AI agents |

These help sandboxed applications (especially AI agents) provide better error messages when access is denied.

## Secrets Management

nono can securely load API keys from the system keystore (macOS Keychain / Linux Secret Service) and inject them as environment variables:

```bash
# Store a secret in the keystore
security add-generic-password -s "nono" -a "openai_api_key" -w "sk-..."

# Use the secret in a sandboxed command
nono run --allow . --secrets openai_api_key -- my-agent
```

Secrets are loaded **before** the sandbox is applied, so the sandboxed process cannot access the keystore directly - only the specific secrets you authorize.

See [Secrets Management](secrets.md) for full documentation.

## Sensitive Paths

The following paths are always blocked by default to protect credentials:

- `~/.ssh` - SSH keys
- `~/.aws`, `~/.gcloud`, `~/.azure` - Cloud credentials
- `~/.gnupg` - GPG keys
- `~/.kube`, `~/.docker` - Container credentials
- `~/.zshrc`, `~/.bashrc`, `~/.profile` - Shell configs (often contain secrets)
- `~/.npmrc`, `~/.git-credentials` - Package manager tokens

Use `nono why <path>` to check if a specific path is blocked and why.

## Next Steps

- [CLI Reference](flags.md) - Complete flag documentation
- [Secrets Management](secrets.md) - Secure API key loading from system keystore
- [Examples](examples.md) - Common usage patterns
