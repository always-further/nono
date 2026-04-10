# External Integrations

**Analysis Date:** 2026-04-04

## APIs & External Services

**Update Service:**
- `https://update.nono.sh/v1/check` - Checks for CLI updates.
  - SDK/Client: `ureq` (HTTP client used for update checks in `crates/nono-cli/src/update_check.rs`).
  - Opt-out: `NONO_NO_UPDATE_CHECK=1` or configuration.

**Sigstore (Fulcio/Rekor):**
- Used for attestation and verification of instruction files.
  - SDK/Client: `sigstore-verify`, `sigstore-sign` (crates).
  - Used in: `crates/nono/src/trust/` and `crates/nono-cli/src/trust_cmd.rs`.

## Data Storage

**Keyrings:**
- **Linux:** Secret Service (D-Bus) or `gnome-keyring`.
- **macOS:** Apple Keychain.
- **Windows:** Windows Credential Manager.
  - Client: `keyring` (v3) crate.
  - Used in: `crates/nono/src/keystore.rs`.

**Password Managers:**
- **1Password:** Integration via `op` CLI.
  - Implementation: `crates/nono/src/keystore.rs` (`load_from_op` calls `op read`).
- **Apple Passwords:** Integration via `security` CLI.
  - Implementation: `crates/nono/src/keystore.rs` (`load_from_apple_password` calls `security find-internet-password`).

**File Storage:**
- **Local Filesystem:**
  - Config: `~/.config/nono/` (Unix) or `%USERPROFILE%\.nono\` (Windows).
  - State: `~/.local/state/nono/` (Unix).
  - Policy: `~/.config/nono/profiles/`.

## System Hooks

**Linux:**
- **Landlock LSM:** Used for filesystem and network sandboxing.
  - Implementation: `crates/nono/src/sandbox/landlock.rs` (assumed based on dependencies and project goals).

**macOS:**
- **Seatbelt (Sandbox.kext):** Used for kernel-level sandboxing via `sandbox_init`.

**Windows:**
- **Windows Filtering Platform (WFP):** Used for network egress filtering.
  - Implementation: `crates/nono-cli/src/windows_wfp_contract.rs`.
- **Job Objects:** Used for process grouping and basic restriction.
- **RPC:** Used for interaction with sandboxed processes.

## Authentication & Identity

**Instruction Attestation:**
- **Sigstore:** Keyless signing via Fulcio (OpenID Connect) and Rekor (Transparency Log).
  - Implementation: `crates/nono/src/trust/signing.rs`.

## Monitoring & Observability

**Logs:**
- **Structured Logging:** Uses `tracing` crate.
- **Output:** Stderr, controlled by `NONO_LOG` environment variable.

## CI/CD & Deployment

**Hosting:**
- GitHub Releases for binaries.
- Docker Hub for development and CI images (`Dockerfile`).

**CI Pipeline:**
- **GitHub Actions:** `.github/workflows/ci.yml`, `release.yml`, etc.

## Environment Configuration

**Required env vars:**
- `NONO_LOG` - Logging verbosity and filters.
- `NONO_NO_UPDATE_CHECK` - Opt-out of version checks.
- `OP_SERVICE_ACCOUNT_TOKEN` - Optional for 1Password CLI automation.

**Secrets location:**
- System Keyring (Service name: `nono`).
- Environment variables via `env://` scheme.

---

*Integration audit: 2026-04-04*
