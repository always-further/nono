# CLI Reference

Complete reference for all nono command-line flags.

## Global Options

These options work with all commands.

### `--silent`, `-s`

Suppress all nono output (banner, summary, status messages). Only the executed command's output will be shown.

```bash
nono -s run --allow . -- my-agent
nono --silent why ~/.ssh/id_rsa
```

## Commands

### `nono run`

Run a command inside the sandbox.

```bash
nono run [OPTIONS] -- <COMMAND> [ARGS...]
```

### `nono why`

Check why a path would be blocked or allowed.

```bash
nono why [OPTIONS] <PATH>
```

### `nono setup`

Set up nono on this system. Verifies installation, tests sandbox support, and optionally generates example profiles.

```bash
nono setup [OPTIONS]
```

## `nono run` Options

### Directory Permissions

These flags grant recursive access to directories and all their contents.

#### `--allow`, `-a`

Grant read and write access to a directory.

```bash
nono run --allow ./project -- command
nono run -a ./src -a ./tests -- command
```

Can be specified multiple times to allow multiple directories.

#### `--read`, `-r`

Grant read-only access to a directory.

```bash
nono run --read ./config -- command
nono run -r /etc/myapp -- command
```

Useful for source code directories that shouldn't be modified.

#### `--write`, `-w`

Grant write-only access to a directory.

```bash
nono run --write ./output -- command
nono run -w ./logs -- command
```

Useful for output directories where reading existing content isn't needed.

### File Permissions

These flags grant access to individual files only (non-recursive).

#### `--allow-file`

Grant read and write access to a single file.

```bash
nono run --allow-file ./database.sqlite -- command
```

#### `--read-file`

Grant read-only access to a single file.

```bash
nono run --read-file ./config.toml -- command
nono run --read-file ~/.gitconfig -- command
```

#### `--write-file`

Grant write-only access to a single file.

```bash
nono run --write-file ./output.log -- command
```

### Network Control

#### `--net-block`

Block all network access. Network is **allowed by default**.

```bash
# Block network for a build process that should be offline
nono run --allow . --net-block -- cargo build
```

!!! note "Binary Control"
    Network access is currently binary - either all outbound connections are allowed, or all are blocked. There is no per-host or per-domain filtering.

    Granular network filtering (e.g., allowing only specific domains like `api.anthropic.com`) is a desired feature but not yet supported. Apple Seatbelt has technical limitations that make per-host filtering challenging and would require significant experimentation to implement correctly. This feature may be added in a future release.

### Secrets Options

#### `--secrets`

Load secrets from the system keystore (macOS Keychain / Linux Secret Service) and inject them as environment variables.

```bash
# Load specific secrets by account name
nono run --allow . --secrets openai_api_key,anthropic_api_key -- my-agent

# Use with profile (loads secrets defined in profile's [secrets] section)
nono run --profile claude-code --secrets -- claude
```

Secrets are:

- Loaded **before** the sandbox is applied (keystore access blocked after)
- Auto-named by uppercasing: `openai_api_key` becomes `$OPENAI_API_KEY`
- Zeroized from memory after `exec()`

See [Secrets Management](secrets.md) for full documentation on storing and using secrets.

### Profile Options

#### `--profile`, `-p`

Use a named profile (built-in or from `~/.config/nono/profiles/`).

```bash
nono run --profile claude-code -- claude
nono run -p openclaw -- openclaw gateway
```

#### `--workdir`

Working directory for `$WORKDIR` expansion in profiles (defaults to current directory).

```bash
nono run --profile claude-code --workdir ./my-project -- claude
```

#### `--trust-unsigned`

Trust unsigned user profiles. Required for profiles without signatures.

```bash
nono run --profile my-custom-profile --trust-unsigned -- command
```

### Operational Flags

#### `--dry-run`

Show what capabilities would be granted without actually executing the command or applying the sandbox.

```bash
nono run --allow . --read /etc --dry-run -- my-agent
```

Output:
```
Capabilities that would be granted:
  [rw] /Users/luke/project
  [r-] /etc
  [net] allowed

Would execute: my-agent
```

#### `--verbose`, `-v`

Increase logging verbosity. Can be specified multiple times.

| Flag | Level | Output |
|------|-------|--------|
| (none) | Error | Only errors |
| `-v` | Info | Informational messages |
| `-vv` | Debug | Detailed debug output |
| `-vvv` | Trace | Full trace output |

```bash
nono run -vvv --allow . -- command
```

#### `--config`, `-c`

Specify a configuration file path.

```bash
nono run --config ./nono.toml -- command
```

!!! note "Coming Soon"
    Configuration file support is planned for a future release.

## `nono why` Options

### `<PATH>` (required)

The path to check.

```bash
nono why ~/.ssh/id_rsa
nono why ./my-project
```

### `--suggest`

Show what flags would grant access to this path.

```bash
nono why --suggest ~/.aws
# Output includes suggested nono run flags
```

## `nono setup` Options

### `--check-only`

Only verify installation and sandbox support, don't create any files.

```bash
nono setup --check-only
```

### `--profiles`

Generate example user profiles in `~/.config/nono/profiles/`.

```bash
nono setup --profiles
```

### `--shell-integration`

Show shell integration instructions (aliases, etc.).

```bash
nono setup --shell-integration
```

### `--verbose`, `-v`

Show detailed information during setup. Can be specified multiple times.

```bash
nono setup -v --profiles
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command executed successfully |
| 1 | nono error (invalid arguments, sandbox failure) |
| * | Exit code from the executed command |

## Path Resolution

All paths are canonicalized before the sandbox is applied:

- Relative paths are resolved to absolute paths
- Symlinks are followed and resolved
- Parent directory references (`..`) are resolved

This prevents symlink escape attacks where a malicious agent creates a symlink pointing outside the allowed directory.

```bash
# These are equivalent if ./project resolves to /home/user/project
nono run --allow ./project -- command
nono run --allow /home/user/project -- command
```

## Combining Flags

Flags can be combined freely:

```bash
nono run \
  --allow ./project \
  --read ~/.config/myapp \
  --write ./logs \
  --read-file ~/.gitconfig \
  -vv \
  -- my-agent --arg1 --arg2
```

## Examples

See the [Examples](examples.md) page for common usage patterns.
