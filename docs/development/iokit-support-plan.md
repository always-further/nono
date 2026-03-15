# Add IOKit Support for Chrome/Playwright Compatibility

## Context

Chrome's rendering pipeline requires IOKit access (`iokit-open`, `iokit-get-properties`) for hardware queries — even in headless mode. nono's Seatbelt profile starts with `(deny default)` which blocks all IOKit operations, and there's currently no way to allow them. This causes Chrome to SIGSEGV when initializing the renderer, breaking `@playwright/mcp` and any other Chromium-based tooling.

**Goal**: Add `--allow-iokit` CLI flag so users can opt into IOKit access when running browser-based tools. IOKit is never auto-enabled — always explicit.

## Design Decision: Blanket vs Granular IOKit Access

Seatbelt supports fine-grained IOKit filtering — Apple's own WebKit sandbox profile ([WebProcess.sb.in][webkit-sb]) uses per-class and per-property rules like:

```scheme
(allow iokit-open-user-client (iokit-user-client-class "IOSurfaceRootUserClient"))
(allow iokit-get-properties (iokit-property "chip-id" "display-rotation"))
```

The full set of IOKit operation classes (as of macOS Sequoia) is: `iokit-open` (wildcard), `iokit-open-user-client`, `iokit-open-service`, `iokit-get-properties`, `iokit-set-properties`, and `iokit-issue-extension`. Filtering is available via `iokit-user-client-class`, `iokit-property`, and `iokit-registry-entry-class` predicates ([SandboxMirror docs][sandbox-mirror], [Apple Sandbox Guide v1.0][apple-guide]).

**nono uses blanket `(allow iokit-open)` + `(allow iokit-get-properties)` instead.** Rationale:

1. **The IOKit classes Chrome needs are a moving target.** They vary by hardware (Intel vs Apple Silicon, discrete vs integrated GPU), macOS version, and Chromium version. A static allowlist would break unpredictably and require constant maintenance.

2. **WebKit can afford granularity because Apple controls both sides.** They know exactly which IOKit classes their own renderer talks to. nono can't make that guarantee for third-party Chromium builds shipped by Playwright, Puppeteer, or Electron.

3. **The opt-in flag is the meaningful security boundary.** Default is fully locked down — `(deny default)` blocks all IOKit. `--allow-iokit` is an explicit user decision to open this surface for a specific invocation. That's the gate, not which IOKit subclass gets through.

4. **nono's threat model is AI agents, not browser exploit chains.** The adversary is a misbehaving LLM trying to read `~/.ssh`, not a sophisticated attacker pivoting through an IOKit driver vulnerability.

5. **No write access to hardware registries.** `iokit-set-properties` is deliberately excluded — there's no legitimate reason for a sandboxed coding agent to write to IOKit device registries.

6. **Granular control is still available** via the existing `platform_rules` mechanism in `CapabilitySet`. Users who need surgical IOKit filtering can inject specific rules through custom policy groups.

[webkit-sb]: https://github.com/WebKit/WebKit/blob/main/Source/WebKit/WebProcess/com.apple.WebProcess.sb.in
[sandbox-mirror]: https://github.com/steven-michaud/SandboxMirror/blob/master/app-sandbox.md
[apple-guide]: https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf

## Additional Requirement: `mach-register`

Step 0 testing (`scripts/test-iokit-step0.sh`) revealed that Chrome also requires `(allow mach-register)` to function under `(deny default)`. Chrome's multi-process architecture uses `bootstrap_check_in` to register a Mach port rendezvous server (`org.chromium.Chromium.MachPortRendezvousServer.<pid>`) that child processes connect to. Without `mach-register`, this fails with:

```
FATAL:base/apple/mach_port_rendezvous_mac.cc:155
Check failed: kr == KERN_SUCCESS. bootstrap_check_in ... Permission denied (1100)
```

nono's current Seatbelt profile (`macos.rs`) allows `mach-lookup` but not `mach-register`. This is a **separate issue from IOKit** — `mach-register` is needed for any Chromium process to start, regardless of IOKit access. It should be added to the base profile (not gated behind `--allow-iokit`) since other multi-process tools may also need Mach port registration.

**Decision**: Add `(allow mach-register)` to the base Seatbelt profile in `macos.rs`, alongside the existing `(allow mach-lookup)`. This is low-risk — it allows processes to register named Mach services (normal IPC), and the existing `(deny mach-priv*)` still blocks privileged Mach operations.

## Platform Scope

**macOS only.** IOKit is Apple's kernel framework for hardware driver communication — it doesn't exist on Linux. On Linux, Chrome queries hardware info through `/sys` and `/proc` filesystem paths, which are already covered by Landlock's existing read rules. The `iokit_allowed` bool lives on `CapabilitySet` (cross-platform struct) but only `macos.rs` consumes it when generating the Seatbelt profile. `linux.rs` (Landlock) ignores it.

## Files to Modify

| File | Change |
|------|--------|
| `crates/nono/src/capability.rs` | Add `iokit_allowed: bool` field to `CapabilitySet` + builder/accessor/setter |
| `crates/nono/src/sandbox/macos.rs` | Add `(allow mach-register)` to base profile; emit `(allow iokit-open)` + `(allow iokit-get-properties)` when IOKit enabled |
| `crates/nono-cli/src/cli.rs` | Add `--allow-iokit` flag to `SandboxArgs` and `WhyArgs` |
| `crates/nono-cli/src/capability_ext.rs` | Wire `args.allow_iokit` → `caps.set_iokit_allowed(true)` |
| `crates/nono-cli/src/main.rs` | Pass `allow_iokit` in `WhyArgs` → `SandboxArgs` conversions |
| `crates/nono-cli/src/sandbox_state.rs` | Add `iokit_allowed` for `nono why --self` roundtrip |
| **nono-py** | |
| `nono-py/src/lib.rs` | Add `allow_iokit()` method + `is_iokit_allowed` property to `JsCapabilitySet` |
| `nono-py/python/nono_py/_nono_py.pyi` | Add type stubs for new method + property |
| **nono-ts** | |
| `nono-ts/src/lib.rs` | Add `allowIokit()` method + `isIokitAllowed` getter via `#[napi]` |
| `nono-ts/index.d.ts` | Add type definitions for new method + getter |

No changes to `policy.json` or built-in profiles — IOKit is always opt-in via CLI flag.

## Implementation

### 1. `CapabilitySet` — add `iokit_allowed` field

**File**: `crates/nono/src/capability.rs`

Add field to struct (after `extensions_enabled`):
```rust
iokit_allowed: bool,  // macOS IOKit access (iokit-open, iokit-get-properties)
```

Add builder method (follows `block_network()` pattern):
```rust
#[must_use]
pub fn allow_iokit(mut self) -> Self {
    self.iokit_allowed = true;
    self
}
```

Add mutable setter (follows `set_network_blocked()`):
```rust
pub fn set_iokit_allowed(&mut self, allowed: bool) {
    self.iokit_allowed = allowed;
}
```

Add accessor (follows `is_network_blocked()`):
```rust
#[must_use]
pub fn is_iokit_allowed(&self) -> bool {
    self.iokit_allowed
}
```

Update `summary()` — add IOKit section after Network (macOS only):
```rust
if cfg!(target_os = "macos") && self.iokit_allowed {
    lines.push("IOKit:".to_string());
    lines.push("  access: allowed".to_string());
}
```

### 2. Seatbelt profile — add `mach-register` and emit IOKit rules

**File**: `crates/nono/src/sandbox/macos.rs`

Add `mach-register` to the base profile, after the existing `mach-lookup` block (~line 333):
```rust
profile.push_str("(allow mach-register)\n");
```

In `generate_profile()`, after the `system-info` line (~350) and before root filesystem access:
```rust
// IOKit: allow hardware property queries when opted in.
// Required for Chromium-based browsers (Playwright, Puppeteer) which query
// GPU info and display properties via IOKit even in headless mode.
if caps.is_iokit_allowed() {
    profile.push_str("(allow iokit-open)\n");
    profile.push_str("(allow iokit-get-properties)\n");
}
```

Add tests:
- `test_generate_profile_has_mach_register` — verify `mach-register` in base profile
- `test_generate_profile_iokit_allowed` — verify both IOKit rules present when enabled
- `test_generate_profile_iokit_denied_by_default` — verify no `iokit-` in default profile

### 3. CLI — add `--allow-iokit` flag

**File**: `crates/nono-cli/src/cli.rs`

Add to `SandboxArgs` (after `net_block` on line 207):
```rust
/// Allow IOKit access (macOS only). Required for Chromium-based browsers
/// (Playwright, Puppeteer) which need hardware queries even in headless mode.
#[arg(long)]
pub allow_iokit: bool,
```

Add to `WhyArgs` (after `net_block` on line 369):
```rust
/// Allow IOKit access (for query context, macOS only)
#[arg(long)]
pub allow_iokit: bool,
```

### 4. Wire CLI flag to CapabilitySet

**File**: `crates/nono-cli/src/capability_ext.rs`

In `from_args()`, after the `net_block` block (line ~114):
```rust
if args.allow_iokit {
    caps.set_iokit_allowed(true);
}
```

In `add_cli_overrides()`, after the `net_block` block (line ~301):
```rust
if args.allow_iokit {
    caps.set_iokit_allowed(true);
}
```

Update all `SandboxArgs` struct literals in tests to include `allow_iokit: false`.

### 5. WhyArgs → SandboxArgs conversion

**File**: `crates/nono-cli/src/main.rs`

Add `allow_iokit: args.allow_iokit` to both `SandboxArgs` constructions in `run_why()` (lines ~165 and ~191).

### 6. Sandbox state roundtrip

**File**: `crates/nono-cli/src/sandbox_state.rs`

Add to `SandboxState`:
```rust
#[serde(default)]  // backward compat with old state files
pub iokit_allowed: bool,
```

Update `from_caps()`: `iokit_allowed: caps.is_iokit_allowed()`

Update `to_caps()`: `caps.set_iokit_allowed(self.iokit_allowed)`

### 7. Python SDK — expose `allow_iokit`

**Repo**: `nono-py`

Both SDKs wrap the Rust `CapabilitySet` from `crates/nono/` directly (not the CLI). Once the core library adds `set_iokit_allowed()` / `is_iokit_allowed()`, the SDK changes are mechanical — follow the `block_network()` pattern.

**File**: `nono-py/src/lib.rs`

Add method to `PyCapabilitySet` (after `block_network`):
```rust
#[pyo3(text_signature = "($self)")]
pub fn allow_iokit(&mut self) {
    self.inner.set_iokit_allowed(true);
}

#[getter]
pub fn is_iokit_allowed(&self) -> bool {
    self.inner.is_iokit_allowed()
}
```

**File**: `nono-py/python/nono_py/_nono_py.pyi`

Add to `CapabilitySet` class:
```python
def allow_iokit(self) -> None: ...
@property
def is_iokit_allowed(self) -> bool: ...
```

`SandboxState` roundtrip needs no SDK changes — it delegates to the Rust `SandboxState` which uses serde with `#[serde(default)]`.

### 8. TypeScript SDK — expose `allowIokit`

**Repo**: `nono-ts`

**File**: `nono-ts/src/lib.rs`

Add method to `JsCapabilitySet` (after `blockNetwork`):
```rust
#[napi]
pub fn allow_iokit(&mut self) {
    self.inner.set_iokit_allowed(true);
}

#[napi(getter)]
pub fn is_iokit_allowed(&self) -> bool {
    self.inner.is_iokit_allowed()
}
```

**File**: `nono-ts/index.d.ts`

Add to `CapabilitySet` class:
```typescript
allowIokit(): void
get isIokitAllowed(): boolean
```

`SandboxState` roundtrip needs no SDK changes — same serde delegation as Python.

## Verification

### Step 0: Reproduce the failure (before any code changes)

**Status: DONE** — confirmed via `scripts/test-iokit-step0.sh`.

Use `sandbox-exec` with a raw Seatbelt profile that mirrors nono's `(deny default)` baseline. This confirms IOKit is the actual blocker — no nono build required. An automated test script is provided:

```bash
cd nono && ./scripts/test-iokit-step0.sh
```

The script runs Playwright's Chromium under two Seatbelt profiles — one without IOKit rules (expect SIGSEGV) and one with (expect success). It requires `@playwright/test` installed locally in `scripts/`:

```bash
cd scripts && npm install @playwright/test && npx playwright install chromium
```

**Results** (Apple Silicon, macOS Sequoia):
- Without IOKit: `SEGV_ACCERR` signal 11 — Chrome crashes during renderer init
- With IOKit: exit 0 — Chrome launches headless and loads `about:blank`

**Additional finding**: Chrome also requires `(allow mach-register)` for its Mach port rendezvous server (`bootstrap_check_in`). Without it, Chrome fails with `FATAL:base/apple/mach_port_rendezvous_mac.cc:155 ... Permission denied (1100)`. This is separate from IOKit and should be added to the base Seatbelt profile (see "Additional Requirement: `mach-register`" section above).

Monitor sandbox violations in a separate terminal to see exactly what gets denied:

```bash
# Watch for IOKit denials in real time
log stream --predicate 'subsystem == "com.apple.sandbox" AND message CONTAINS "iokit"' --style compact
```

### Step 1: Unit tests (after code changes)

```bash
cd nono && cargo test
```

Key tests to verify:
- `test_generate_profile_has_mach_register` — `mach-register` present in base profile
- `test_generate_profile_iokit_allowed` — both `iokit-open` and `iokit-get-properties` rules present
- `test_generate_profile_iokit_denied_by_default` — no `iokit-` rules in default profile
- Existing tests pass with new `allow_iokit: false` field in `SandboxArgs` struct literals

### Step 2: End-to-end with nono

```bash
cd nono && cargo build

# Confirm flag exists
./target/debug/nono run --help | grep iokit

# FAIL: run without --allow-iokit (same crash as Step 0)
./target/debug/nono run --allow . -- node scripts/launch-chromium.mjs

# PASS: run with --allow-iokit
./target/debug/nono run --allow . --allow-iokit -- node scripts/launch-chromium.mjs

# Verify dry-run output shows IOKit status
./target/debug/nono run --allow /tmp --allow-iokit --dry-run -- echo test
# Should include "IOKit: access: allowed" in summary

# Verify default dry-run does NOT show IOKit
./target/debug/nono run --allow /tmp --dry-run -- echo test
# Should NOT mention IOKit
```

### Step 3: CI checks

```bash
cargo clippy -- -D warnings
cargo fmt --check
```
