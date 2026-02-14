<div align="center">

<img src="assets/nono-logo.png" alt="nono logo" width="600"/>

**The Swiss Army knife of agent security**

<a href="https://discord.gg/pPcjYzGvbS">
  <img src="https://img.shields.io/badge/Chat-Join%20Discord-7289da?style=for-the-badge&logo=discord&logoColor=white" alt="Join Discord"/>
</a>

<p>
  <a href="https://opensource.org/licenses/Apache-2.0">
    <img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"/>
  </a>
  <a href="https://github.com/always-further/nono/actions/workflows/ci.yml">
    <img src="https://github.com/always-further/nono/actions/workflows/ci.yml/badge.svg" alt="CI Status"/>
  </a>
  <a href="https://discord.gg/pPcjYzGvbS">
    <img src="https://img.shields.io/discord/1384081906773131274?color=7289da&label=Discord&logo=discord&logoColor=white" alt="Discord"/>
  </a>
  <a href="https://docs.nono.sh">
    <img src="https://img.shields.io/badge/Docs-docs.nono.sh-green.svg" alt="Documentation"/>
  </a>
</p>

</div>

> [!WARNING]
> This is an early alpha release that has not undergone comprehensive security audit
> We are also in the process of porting the core to its own library. We still welcome PR's, but note a bit of cat herding maybe involved if the change touches a lot of files.

**nono** is a secure, kernel-enforced capability shell for running AI agents and any POSIX style process. Unlike policy-based sandboxes that intercept and filter operations, nono leverages OS security primitives (Landlock on Linux, Seatbelt on macOS) to create an environment where unauthorized operations are structurally impossible.

**nono** also provides protections against destructive commands (rm -rf ..) and provides a way to securely store API keys, tokens, secrets that are injected securely into the process at run time.

> [!NOTE]
> NEWS! Work is underway to seperate the core functionality into a library with C bindings, which will allow other projects to integrate nono's security primitives directly without shelling out to the CLI. This will also allow us to expand support to other platforms like Windows. Initial languages will be Python, Typescript, and of course Rust. Following up with Go, Java, and C# bindings.

Many more features are planned, see the Roadmap below. 

## Quick Start

### MacOS

```bash
brew tap always-further/nono 
brew install nono
```
> [!NOTE]
> The package is not in homebrew official yet, [give us a star](https://github.com/always-further/nono) to help raise our profile for when request approval

### Linux Package Managers

We are in the process of packaging nono for popular Linux distributions. In the meantime, you can use the prebuilt binaries or build from source.

### Building from Source

See the [Development Guide](https://docs.nono.sh/development) for instructions on building nono from source.

### Use of AI for Development

We encourage using AI tools to contribute to nono! However, you must understand and carefully review any AI-generated code before submitting. AI is a part of the life of software development now, but its use can unwittingly introduce security vulnerabilities — and the security of nono is paramount. Always review and test your code thoroughly, especially around core sandboxing functionality. Being able to explain your changes in your own words also helps reviewers. If you don't understand how a change works, please ask for help in the Discord before submitting a PR.

## Supported Clients

nono ships with built-in profiles for popular AI coding agents. Each profile defines audited, minimal permissions so you can get started with a single command.

<table>
  <tr>
    <th>Client</th>
    <th>Command</th>
    <th>Network</th>
    <th>Docs</th>
  </tr>
  <tr>
    <td><strong>Claude Code</strong><br/>Anthropic's CLI coding agent</td>
    <td><code>nono run --profile claude-code -- claude</code></td>
    <td>Allowed</td>
    <td><a href="https://docs.nono.sh/clients/claude-code">Guide</a></td>
  </tr>
  <tr>
    <td><strong>OpenCode</strong><br/>Open-source AI coding assistant</td>
    <td><code>nono run --profile opencode -- opencode</code></td>
    <td>Allowed</td>
    <td><a href="https://docs.nono.sh/clients/opencode">Guide</a></td>
  </tr>
  <tr>
    <td><strong>OpenClaw</strong><br/>Multi-channel AI agent platform</td>
    <td><code>nono run --profile openclaw -- openclaw gateway</code></td>
    <td>Allowed</td>
    <td><a href="https://docs.nono.sh/clients/openclaw">Guide</a></td>
  </tr>
</table>

Don't see your tool? nono is agent-agnostic and works with any CLI command:

```bash
nono run --allow . -- my-agent
```

## Projects using nono

<table>
  <tr>
    <th>Project</th>
    <th>Repository</th>
  </tr>
  <tr>
    <td><strong>claw-wrap</strong></td>
    <td><a href="https://github.com/dedene/claw-wrap">GitHub</a></td>
  </tr>
</table>


### Shell Alias (Claude Code example)

For quick access, add a shell function:

```bash
sclaude() {
    nono run --profile claude-code --allow . "$@" -- claude
}
```

Usage:
```bash
sclaude                           # Current directory only
sclaude --allow /tmp              # Current directory + /tmp
sclaude --read ~/Documents        # Current directory + read-only ~/Documents
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

# Start an interactive shell inside the sandbox
nono shell --allow .

# Check why a path would be blocked
nono why --path ~/.ssh/id_rsa --op read
```

## Command Blocking

nono blocks what might be considered dangerous commands by default to prevent AI agents from accidentally (or maliciously) causing harm. This provides defense-in-depth beyond filesystem restrictions.

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

nono applies kernel-level protections that limit destructive operations:

- **File and directory deletion blocked outside granted paths** - `unlink`/`rmdir` syscalls are blocked for system paths like `/tmp`, `/dev`, and any path not explicitly granted with `--allow` or `--write`

Within paths you explicitly grant write access to (`--allow` or `--write`), file creation, modification, and deletion (including directory deletion) are permitted - this is necessary for normal file operations like atomic writes and directory renames.

```bash
# File deletion blocked in system paths (even with --allow-command rm)
$ nono run --allow ./project --allow-command rm -- rm /etc/hosts
rm: /etc/hosts: Operation not permitted
```


## Platform Support

| Platform | Mechanism | Kernel | Status |
|----------|-----------|--------|--------|
| macOS | Seatbelt | 10.5+ | Filesystem + Network |
| Linux | Landlock | 5.13+ | Filesystem |
| Windows | - | - | Not yet supported |

## Roadmap

### Planned Features

| Feature | Description |
|---------|-------------|
| ~~**Advisory API**~~ | ~~Allow agents to preemptively check permissions before attempting operations, avoiding trial-and-error failures~~ |
| **Signed Policy Files** | Policy files signed and attestable via [Sigstore Rekor](https://rekor.sigstore.dev/), with embedded DSSE signed payloads. Users can craft and sign their own default policies |
| **Interactive Permission Mode** | `nono run --interactive` spawns a supervisor that prompts when blocked operations are attempted |
| **Network Filtering** | Fine-grained network controls (e.g. allowlist/denylist hosts, ports, protocols) |
| **Time-Limited Permissions** | `nono run --allow /tmp:5m -- agent` grants temporary access that expires automatically |
| ~~**Learning Mode**~~ | ~~`nono learn -- command` traces syscalls and generates a minimal capability profile~~ |
| **Ephemeral Mode** | `nono run --ephemeral` creates a copy-on-write overlay filesystem where writes are isolated, enabling full undo |
| **Audit Logging** | `nono run --audit-log ./session.jsonl -- command` logs all sandbox-relevant operations for post-hoc analysis and replay |
| **Extend Secrets Manager Support** | Support for popular secrets managers: Bitwarden/1Password/KeePass  |
| **nono as a library** | Expose nono's sandboxing functionality as a library via Rust bindings |
| **Windows Support** | Implement a Windows version using Job Objects and Windows Sandbox |


## Security Model

nono follows a capability-based security model with defense-in-depth:

1. **Command validation** - Dangerous commands (rm, dd, chmod, etc.) are blocked before execution
2. **Sandbox applied** - OS-level restrictions are applied (irreversible)
3. **Kernel enforcement** - File and directory deletion blocked outside granted write paths
4. **Command executed** - The command runs with only granted capabilities
5. **All children inherit** - Subprocesses also run under restrictions
6. **Key isolation** - Secrets are injected securely and cannot be accessed outside the sandbox


## Documentation

Full documentation is available at [docs.nono.sh](https://docs.nono.sh), including guides for supported clients, configuration, and building from source.

## Security

If you discover a security vulnerability, please **do not open a public issue**. Public disclosure of vulnerabilities can put all users at risk. Instead, please follow the responsible disclosure process outlined in our [Security Policy](https://github.com/always-further/nono/blob/main/SECURITY.md).

## License

Apache-2.0
