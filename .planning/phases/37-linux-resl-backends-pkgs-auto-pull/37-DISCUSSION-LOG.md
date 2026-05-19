# Phase 37: Linux RESL backends + PKGS auto-pull - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-05-19
**Phase:** 37-linux-resl-backends-pkgs-auto-pull
**Areas discussed:** CI workflow shape, UnsupportedKernelFeature error, --no-auto-pull flag semantics, Auto-pull e2e fixture strategy

---

## CI workflow shape

### Q1: How should the Linux runner verification job be wired into CI?

| Option | Description | Selected |
|--------|-------------|----------|
| Extend existing Linux test job | Add `cargo test -p nono-cli --test resl_nix_linux --test resl_nix_async_signal_safety` + an auto-pull e2e test to the existing ubuntu test job in ci.yml. Single new job-step, inherits caching. Risk: bloats the existing job's wallclock if cgroup tests are slow. | |
| New dedicated job in ci.yml | Add a 'linux-resl' job that pins runs-on: ubuntu-24.04 (success criteria #6 mandates 24.04, current jobs use ubuntu-latest). Parallel to other jobs, can be re-run independently when only resl-touching code changes. Slight cost: more CI minutes. | |
| Separate phase-37-linux-resl.yml workflow | Dedicated workflow file. Cleanest blast-radius isolation; can have its own triggers / cron. But: more files to maintain, doesn't run by default on every PR unless we duplicate the trigger config. | ✓ |

**User's choice:** Separate phase-37-linux-resl.yml workflow

### Q2: cgroup v2 user-delegation: does the test job need a systemd-user-session, root, or neither?

| Option | Description | Selected |
|--------|-------------|----------|
| loginctl enable-linger + machinectl shell | Most realistic — runs the tests as the runner user under a real systemd-user-session, which is how production hosts behave. Requires 1-2 lines of pre-job setup; documented Ubuntu 24.04 path. The require_cgroup_v2! macro will pass. | ✓ |
| Run tests as root | Easiest: sudo gives unrestricted cgroup access. But masks bugs where production users hit delegation failures. Also: the v2.3 Plan 25-01 code path assumed unprivileged user-delegated cgroup; running as root bypasses that codepath entirely. | |
| You decide | Let me investigate during research-phase. The right answer is whichever ubuntu-24.04 runners actually offer out-of-the-box — if it's already a systemd-user-session, no setup needed. | |

**User's choice:** loginctl enable-linger + machinectl shell

### Q3: What's the gating posture for the new workflow vs main CI?

| Option | Description | Selected |
|--------|-------------|----------|
| Required check on PRs to main | Treat it the same as ci.yml — a red Phase 37 job blocks merge. Lines up with REQ-RESL-NIX-01 acceptance #4. This is the v2.5 baseline-aware gate posture inherited from Phase 41. | ✓ |
| Required only for Linux-touching PRs | Skip the job (success-by-skip) when no resl-NIX paths touched — mirrors the existing ci.yml `changes` job pattern. Saves CI minutes; risk of false-greens if the path-filter glob misses something. | |
| Non-blocking advisory only | Job runs but doesn't block merge. Useful during Phase 37 itself while we shake out bugs, but contradicts success criteria #6 ('executes … as part of the Phase 37 close gate'). | |

**User's choice:** Required check on PRs to main

### Q4: Test granularity: one combined integration job, or split by backend?

| Option | Description | Selected |
|--------|-------------|----------|
| Single integration step | Run `cargo test -p nono-cli --test resl_nix_linux --test resl_nix_async_signal_safety` plus a new auto-pull e2e test in one step. Sequential, fastest wallclock when green. Harder to triage when one assertion flakes — you get a single red dot. | |
| Matrix per backend | Matrix over [memory, cpu, pids, auto-pull] — each gets its own job. Best signal-to-noise on red. Cost: ~4x CI minutes per run; longer turnaround. | |
| Two jobs: RESL-NIX + PKGS-04 | Compromise. resl-nix integration tests (memory/cpu/pids) run as one job; auto-pull e2e runs as a second job. Reflects the two distinct REQ families and keeps the signed-artifact fixture path isolated. | ✓ |

**User's choice:** Two jobs: RESL-NIX + PKGS-04

---

## UnsupportedKernelFeature error

### Q1: Net-new variant vs reuse existing?

| Option | Description | Selected |
|--------|-------------|----------|
| Net-new UnsupportedKernelFeature { feature, hint } | Adds a typed variant with a structured hint field. Matches success criteria #4 wording verbatim. FFI consumers can introspect the hint field; matches the precedent that Phase 25-01 set with NotSupportedOnPlatform. Re-opens crates/nono/src/error.rs — fine in v2.5 since we're not in an UPST window. | ✓ |
| Reuse UnsupportedPlatform(String) | Keep what Phase 25-01 wrote. Format the hint into the string. Cons: stringly-typed, can't introspect from FFI; partially violates success criteria literal-text reading. | |
| Extend NotSupportedOnPlatform with hint field | Mutates the existing struct variant by adding `hint: Option<String>`. Avoids a new variant. Cons: changes the existing variant's shape, which is a mildly breaking change for any external caller pattern-matching exhaustively. | |

**User's choice:** Net-new UnsupportedKernelFeature { feature, hint }

### Q2: FFI mapping: which error code does UnsupportedKernelFeature map to in nono-ffi?

| Option | Description | Selected |
|--------|-------------|----------|
| Map to existing ErrUnsupportedPlatform | Reuse the same code Phase 25-01 used for NotSupportedOnPlatform. Consumers distinguish via nono_last_error() string. Zero FFI ABI churn. FFI consumers can't programmatically detect 'wrong kernel config' vs 'wrong OS'. | ✓ |
| Add new NonoErrorCode::ErrUnsupportedKernel | Net-new FFI error code. Better signal for FFI consumers (Python/TS bindings can throw a more specific exception). Requires updating bindings/c/src/types.rs + the generated nono.h header. | |
| You decide | Pick whichever the researcher recommends after looking at how the C FFI consumers actually surface these errors today. | |

**User's choice:** Map to existing ErrUnsupportedPlatform

### Q3: What hint text should the CLI show on a cgroup-v1 host?

| Option | Description | Selected |
|--------|-------------|----------|
| Minimal: 'cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all' | Single line, names both common boot-flag spellings. Actionable. Matches REQ acceptance #3 'hint pointing to the cgroup_no_v1 boot flag' verbatim. | ✓ |
| Verbose: minimal + distro hint + 'check /sys/fs/cgroup/cgroup.controllers' diagnostic | Adds a one-liner the user can paste to confirm their own kernel state, plus 'Fedora 31+ / Ubuntu 21.10+ / Debian 11+ default to v2'. Self-diagnosable; mirrors how Landlock errors guide users. Longer error string. | |
| Minimal text + link to docs/troubleshooting/cgroup-v2.md | Short message + URL to a docs page we create. Cleanest CLI output. Requires the docs page to actually exist + be discoverable; another thing to keep in sync. | |

**User's choice:** Minimal hint text

### Q4: Detection point: when does the cgroup-v1 fail-closed fire?

| Option | Description | Selected |
|--------|-------------|----------|
| At sandbox setup (pre-fork) per resource flag | Only fire UnsupportedKernelFeature when the user actually passes --memory / --cpu-percent / --max-processes on a v1 host. Other invocations of nono on v1 still work. Matches v2.3 Plan 25-01 fail-fast precedent. | ✓ |
| At binary startup (eager) | Refuse to run nono at all on a cgroup-v1 host. Breaks scenarios where the user doesn't need resource limits. Way too aggressive. | |
| Lazy at child fork | Try to write to cgroup.max files and surface the kernel's ENOTSUP/ENOENT. The error happens in the post-fork child where diagnostic surface is limited; harder to attach a clean hint. | |

**User's choice:** At sandbox setup (pre-fork) per resource flag

---

## --no-auto-pull flag semantics

### Q1: Scope: which subcommands carry --no-auto-pull?

| Option | Description | Selected |
|--------|-------------|----------|
| Only nono run + nono wrap | The acceptance criteria #5 example is `nono run --profile ... --no-auto-pull`. Limit to the user-facing run paths where profile resolution happens implicitly. Keeps the surface small. | ✓ |
| All subcommands that resolve --profile | Add to every subcommand that takes --profile (run, wrap, exec_strategy callers). Consistent ergonomics; can be propagated via a shared ProfileResolverArgs struct in cli.rs. | |
| Global top-level flag | `nono --no-auto-pull run ...` — top-level clap flag, applies everywhere. Cleanest mental model. Clap top-level flags are less discoverable in `--help` than per-subcommand flags. | |

**User's choice:** Only nono run + nono wrap

### Q2: Environment variable counterpart?

| Option | Description | Selected |
|--------|-------------|----------|
| NONO_NO_AUTO_PULL=1 honored | CLI flag takes precedence; env var sets the default. Matches the convention of NONO_LOG / NONO_NO_UPDATE_CHECK / NONO_UPDATE_URL already in the codebase. Useful in CI where you don't want to thread the flag through every invocation. | ✓ |
| Flag only, no env var | Keep the surface minimal. Users in CI/script contexts have to add the flag everywhere; doesn't match the NONO_* env convention. | |
| You decide | Let me see what other NONO_* env vars exist and pick consistently. | |

**User's choice:** NONO_NO_AUTO_PULL=1 honored

### Q3: Fallback behavior when --no-auto-pull is set + the profile isn't installed locally?

| Option | Description | Selected |
|--------|-------------|----------|
| Existing 'profile not found' error verbatim | REQ-PKGS-04 acceptance #4 says exactly this: 'falls back to the legacy profile not found error'. Match the existing error message used when load_profile() fails for any non-registry name. | |
| New diagnostic: 'profile not installed; auto-pull disabled by --no-auto-pull' | Distinct message to help users debug their own --no-auto-pull config. More discoverable, but deviates from acceptance criteria literal text. | |
| Existing error + diagnostic footer | Existing error string, plus the standard nono diagnostic-footer mechanism (DiagnosticFormatter) appends an `--no-auto-pull is set; remove to enable auto-pull` line. Combines both. | ✓ |

**User's choice:** Existing error + diagnostic footer

### Q4: Where does the flag value thread structurally?

| Option | Description | Selected |
|--------|-------------|----------|
| RunArgs field + read at profile-resolve site | Add `no_auto_pull: bool` to RunArgs / WrapArgs in cli.rs. Profile resolver reads it via a ResolveContext parameter. Cleanest: explicit data flow, easy to test. | |
| Mutate a thread-local in main() | Set a once_cell at startup, read inside load_registry_profile. Zero plumbing through call sites. Hidden global state, bad for unit tests, conflicts with CLAUDE.md 'Explicit Over Implicit' rule. | |
| Add ProfileResolverArgs struct shared by run + wrap | New `pub struct ProfileResolverArgs { no_auto_pull: bool, ... }` flattened into RunArgs + WrapArgs via #[clap(flatten)]. Sets up future profile-resolver options to slot in cleanly. | ✓ |

**User's choice:** Add ProfileResolverArgs struct shared by run + wrap

---

## Auto-pull e2e fixture strategy

### Q1: Source of the signed fixture pack the CI test pulls?

| Option | Description | Selected |
|--------|-------------|----------|
| Generate + sign at CI time (ephemeral) | CI step creates a minimal profile pack, signs it with sigstore-sign using OIDC keyless (GitHub Actions OIDC token — same flow Phase 32 sigstore-integration shipped). Hermetic; tests verify the same crypto path real users hit. | ✓ |
| Commit pre-signed pack in tests/fixtures/ | Pre-sign a pack once, check it into the repo. Faster CI. Bundle TTL / Rekor inclusion proof staleness will break verification within weeks. | |
| Point at real registry.nono.sh | NONO_REGISTRY=https://registry.nono.sh; pull `claude-code-edge` from production. Most realistic, but: depends on prod registry availability and on the pack continuing to verify against current trust roots. | |

**User's choice:** Generate + sign at CI time (ephemeral)

### Q2: How does the test serve the pack to nono (the HTTP surface)?

| Option | Description | Selected |
|--------|-------------|----------|
| Reuse Phase 26-02 std-only TCP server in registry_client::tests | Phase 26-02 already built a 50-LOC single-shot in-process TCP server. Extend it to serve the bundle + artifact + manifest as a multi-endpoint mock registry. Zero new dev-deps. | ✓ |
| Add mockito = '1' dev-dep | The Plan 26-02 original plan called for this; Phase 26-02 skipped it under the portable-subset constraint. Revives the dep that 26-02 deliberately avoided. | |
| Local Python http.server in CI step | Bash step starts `python -m http.server 8080`; Rust test points NONO_REGISTRY at 127.0.0.1:8080. Serves static files; can't mock multi-endpoint registry protocol without scripting. | |

**User's choice:** Reuse Phase 26-02 std-only TCP server in registry_client::tests

### Q3: Trust root + verification posture for the ephemeral fixture?

| Option | Description | Selected |
|--------|-------------|----------|
| Production trust root + GitHub OIDC issuer pin | Test uses the production Sigstore trust root and verifies the OIDC issuer matches https://token.actions.githubusercontent.com. Most realistic. Will surface real verifier bugs. TUF trust-root refresh failures (2 pre-existing flakes) hit this path. | ✓ |
| Test-only trust root injected via NONO_TEST_HOME seam | Reuse Phase 27.1's NONO_TEST_HOME seam to install a test trust root keyed to an ephemeral keypair the CI generates. Hermetic; sidesteps the prod TUF flakes. Doesn't exercise the production trust verification code path. | |
| You decide | Pick based on what's faster to land green. | |

**User's choice:** Production trust root + GitHub OIDC issuer pin

### Q4: Test location: where does the e2e auto-pull test live?

| Option | Description | Selected |
|--------|-------------|----------|
| New crates/nono-cli/tests/auto_pull_e2e_linux.rs (integration test) | Mirrors the resl_nix_linux.rs pattern. Linux-gated (#[cfg(target_os = "linux")]) since CI fixture-signing relies on GitHub OIDC. Invokes the `nono` binary via the existing test harness; covers acceptance #1-#4. | ✓ |
| Inline in registry_client::tests as a unit test | Phase 26-02 kept its tests inside the module. A true e2e auto-pull test needs to run the CLI end-to-end — that's not really a unit test. | |
| Bash script + cargo run in CI step | Drive nono entirely from a bash test runner in the workflow. Simplest plumbing. No in-Rust assertions; harder to maintain. | |

**User's choice:** New crates/nono-cli/tests/auto_pull_e2e_linux.rs (integration test)

---

## Claude's Discretion

- Whether the 2 pre-existing TUF-trust-root test flakes need their own sub-plan or can be absorbed as a Phase 37 fix-pass commit (D-15 prerequisite).
- Whether `nono inspect` Limits-block string drift gets a Phase 37 plan or a follow-up — depends on what the existing code emits today.
- Whether Ubuntu 24.04's default systemd-user-session provides cgroup-v2 delegation out-of-the-box such that `loginctl enable-linger` alone is sufficient.
- Whether `phase-37-linux-resl.yml` gets a path-filter so it only fires on Linux-touching PRs, or always runs.

## Deferred Ideas

- macOS `setrlimit` portion of Plan 25-01 (already pre-deferred at v2.5 scoping).
- Phase 38 REQ-AAHX-HOST-01 native re-validation (pre-deferred to v2.6).
- Mockito dev-dep (held under portable-subset rule).
- Net-new FFI error code `ErrUnsupportedKernel` (deferred — can be added without ABI break later).
- Real `registry.nono.sh` as e2e source (D-13 chose ephemeral CI-signed pack instead).
