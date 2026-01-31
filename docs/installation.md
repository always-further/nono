# Installation

## From Source (Recommended)

nono is written in Rust. You'll need the Rust toolchain installed.

### Prerequisites

=== "Linux"

    - Rust 1.70 or later
    - Linux kernel 5.13+ (for Landlock support)
    - Kernel 6.7+ recommended (for network filtering)

    Check your kernel version:
    ```bash
    uname -r
    ```

=== "macOS"

    - Rust 1.70 or later
    - macOS 10.15 (Catalina) or later
    - Xcode Command Line Tools

### Build Steps

```bash
# Clone the repository
git clone https://github.com/lukehinds/nono.git
cd nono

# Build release binary
cargo build --release

# Binary is at ./target/release/nono
```

### Install to PATH

```bash
# Option 1: Copy to /usr/local/bin
sudo cp target/release/nono /usr/local/bin/

# Option 2: Add to your shell config
echo 'export PATH="$PATH:/path/to/nono/target/release"' >> ~/.zshrc
```

## Cargo Install

```bash
cargo install nono
```

!!! note "Coming Soon"
    The crate is not yet published to crates.io. Use the source installation method for now.

## Homebrew (macOS)

```bash
brew install nono
```

!!! note "Coming Soon"
    The Homebrew formula is not yet available. Use the source installation method for now.

## Verify Installation

```bash
# Check version
nono --version

# Test with dry run
nono --allow . --dry-run -- echo "Hello from sandbox"
```

## Kernel Requirements (Linux)

nono uses Landlock, which requires kernel support:

| Kernel Version | Landlock ABI | Capabilities |
|----------------|--------------|--------------|
| 5.13+ | ABI v1 | Basic filesystem access control |
| 5.19+ | ABI v2 | File rename across directories |
| 6.2+ | ABI v3 | File truncation |
| 6.7+ | ABI v4 | TCP network filtering |
| 6.10+ | ABI v5 | Advanced socket/signal scoping |

nono automatically detects the available ABI and uses the highest supported version. On older kernels, some features may be unavailable but filesystem sandboxing will still work.

### Check Landlock Support

```bash
# Check if Landlock is available
cat /sys/kernel/security/lsm
# Should include "landlock" in the output
```

If Landlock is not listed, you may need to enable it in your kernel configuration or boot parameters.
