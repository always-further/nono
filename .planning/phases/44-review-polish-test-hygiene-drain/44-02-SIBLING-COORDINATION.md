# Phase 44 Plan 44-02 — Sibling Repo Coordination Log

Per D-44-D1 + D-44-D2: sibling-repo URLs derived from this repo's
`git remote -v` upstream entry **at execute-time**.

## Derivation (D-44-D2)

Raw values captured at execute-time (verifier-greppable form):

```
UPSTREAM_URL=https://github.com/always-further/nono.git
DERIVED_ORG=always-further
```

- Upstream URL (from `git remote get-url upstream || origin`): `https://github.com/always-further/nono.git`
- Derived org (`$DERIVED_ORG`): `always-further`
- Derivation matches historically observed `always-further`: yes
- Derived-org deviation checkpoint fired: no (DERIVED_ORG matches historically observed value; auto-proceed to Option A path)
- Derived sibling URLs:
  - nono-py: `https://github.com/always-further/nono-py.git`
  - nono-ts: `https://github.com/always-further/nono-ts.git`

## Existence check (gh repo view)

| Repo                       | Status                                              | Local clone               |
| -------------------------- | --------------------------------------------------- | ------------------------- |
| `always-further/nono-py`   | exists (`https://github.com/always-further/nono-py`) | `C:\Users\OMack\nono-py` (newly cloned) |
| `always-further/nono-ts`   | exists (`https://github.com/always-further/nono-ts`) | `C:\Users\OMack\nono-ts` (newly cloned) |

## Clone provenance

- nono-py clone: `git clone https://github.com/always-further/nono-py.git` at `C:\Users\OMack\nono-py`; HEAD `e4a56f894f3b9cf108b71dc243687218bccc2b47`
- nono-ts clone: `git clone https://github.com/always-further/nono-ts.git` at `C:\Users\OMack\nono-ts`; HEAD `3f0390e1b18cf2b21389722a925441c0d777524e`

Note: this repo is being executed from a Claude Code worktree at
`C:\Users\OMack\Nono\.claude\worktrees\agent-a1997e4c572ec30bd`. The plan's
`../nono-py/` and `../nono-ts/` references are relative to the **main** repo
at `C:\Users\OMack\Nono`, so absolute paths are used here to avoid
ambiguity. The siblings are positioned adjacent to the main repo.

## Decision

Option A auto-selected (per plan-44-02 Task 1 action step "If `$DERIVED_ORG ==
always-further` and both siblings exist and clone succeeds, auto-proceed to
Task 2"). No user input required.

## nono-py test convention discovery

- Layout: `tests/` (pytest collected via `pyproject.toml::[tool.pytest.ini_options].testpaths = ["tests"]`)
- Runner: **pytest** (`pyproject.toml` dev deps include `pytest>=8`; markers `smoke` + `integration` registered)
- Existing FFI-error-mapping test (closest analog): `tests/test_policy.py:280-288` — `pytest.raises(RuntimeError)` on `validate_deny_overlaps([deny_path], caps)` for Linux (macOS skipped because Seatbelt enforces deny-within-allow natively)
- Exception class names found: **no custom `SandboxInitError`** class. PyO3 mapping in `src/lib.rs::to_py_err`:
  - `NonoError::SandboxInit(_) | NonoError::UnsupportedPlatform(_)` → `PyRuntimeError`
  - `NonoError::BrokerNotFound` → falls into wildcard `_` arm → `PyRuntimeError`
  - `NonoError::PathNotFound(_)` → `PyFileNotFoundError`
- The Rust C-FFI maps `BrokerNotFound` → `NonoErrorCode::ErrSandboxInit` (integer -6) at `bindings/c/src/lib.rs:285-291`; nono-py's PyO3 wildcard arm produces `PyRuntimeError`, which IS the SandboxInit-equivalent Python class for this binding (no separate class yet)
- CONTRIBUTING.md requires a feature branch + PR + DCO sign-off + squash-on-merge

## nono-ts test convention discovery

- Layout: `tests/test_*.js` (loose Node-script style)
- Runner: **plain `node <file>.js`** — `package.json` declares `"test": "node test.js"` but `test.js` does NOT exist in the repo at clone-time (the existing `tests/test_*.js` files are invoked individually). No vitest, jest, mocha, or other framework is wired up.
- Existing FFI-error-mapping test (closest analog): `tests/test_errors.js` (try/catch + console.log, no assertions) and `tests/test_sandbox_policy.js` lines 35-40 (custom `assert()` helper that calls `process.exit(1)` on fail — the canonical assertion idiom)
- Exception class names found: **no custom `SandboxInitError`** class. napi-rs mapping in `src/lib.rs::to_napi_err`:
  - `NonoError::PathNotFound(_) | ExpectedDirectory(_) | ExpectedFile(_)` → `Error::new(Status::InvalidArg, ...)`
  - all other variants (including `SandboxInit`, `BrokerNotFound`) → `Error::new(Status::GenericFailure, ...)` via wildcard `_` arm
  - The napi Status appears as the JS `Error.code` property
- napi.targets: `darwin` + `linux` only — no Windows binary published, so `BrokerNotFound` (Windows-only) cannot be triggered from JS in 0.4.0
- No CONTRIBUTING.md or explicit DCO requirement — sign-off applied anyway per CLAUDE.md fork-level rule

## Sibling commit SHAs (populated after Tasks 4 + 5)

| Sibling | Branch                     | Commit SHA                                 | Subject |
|---------|----------------------------|--------------------------------------------|---------|
| nono-py | `44-broker-ffi-lockstep`   | `61ee6aa16449fcbdeccb819aec051dd7492c8b0b` | test: broker FFI mapping lockstep with fork (Phase 44) |
| nono-ts | `44-broker-ffi-lockstep`   | `1df3e16e6ac8ccb676eb6ae7eb7553e715d46303` | test: broker FFI mapping lockstep with fork (Phase 44) |

## PR coordination (plan-discretion per D-44-D1)

### nono-py

- CONTRIBUTING.md flow: feature branch (`44-broker-ffi-lockstep` created locally) → PR against `always-further/nono-py:main` → DCO sign-off (present on commit `61ee6aa`) → squash-on-merge.
- **PR disposition:** local branch committed; remote push + `gh pr create` deferred to the user. The DCO trailer is present so a future push is one command (`git push -u origin 44-broker-ffi-lockstep && gh pr create --base main`). Recorded here per D-44-D1 plan-discretion option: "PR coordination deferred; sibling commit lives on a local branch pending upstream review".
- Rationale: the executor has commit access locally but the PR submission requires the user to coordinate review with the always-further maintainer (Luke Hinds per `pyproject.toml::authors`). Submitting the PR directly without the user's review handoff would violate the "Every pull request requires a review from a maintainer" rule in CONTRIBUTING.md step 9.
- **Follow-up:** the Phase 44 close summary in the fork should reference the local branch SHA `61ee6aa` so the user can run the push when ready.

### nono-ts

- No CONTRIBUTING.md found; `README.md` + `DEVELOPMENT.md` give no explicit PR/DCO guidance. The fork-level CLAUDE.md DCO rule applies — sign-off included on commit `1df3e16`.
- Branch `44-broker-ffi-lockstep` created locally at `C:\Users\OMack\nono-ts`.
- **PR disposition:** local branch committed; remote push + PR coordination deferred to the user (same rationale as nono-py: the maintainer/reviewer handoff is the user's call). Future push command: `git push -u origin 44-broker-ffi-lockstep && gh pr create --base main` from `C:\Users\OMack\nono-ts`.
- Rationale: the `package.json::scripts.test` declares `node test.js` but `test.js` does not exist in the repo at clone-time. Adding/wiring the test entry point is a separate maintenance concern; the new `tests/test_broker_ffi_mapping.js` can be invoked directly via `node tests/test_broker_ffi_mapping.js`. PR submission should let the maintainer decide whether to wire the test into a runner first.

## REQ-TEST-HYG-02 Determinism Check

50-consecutive-runs result: **PARTIAL — deferred to live CI lane**.

Per Roadmap SC#3: "both flakes pass deterministically across 50
consecutive runs on a Windows host (or CI lane equivalent)".

Disposition rationale:
- Executor is running inside a Claude Code worktree on a Windows
  host (`win32` platform per env), but `cargo-nextest` is NOT
  installed on this host (`cargo nextest --version` returns
  "no such command: nextest").
- The plan's Part C explicitly authorises a PARTIAL deferral via
  cross-target-verify-checklist when nextest is unavailable from
  the dev host.
- The `.config/nextest.toml` file is correctly written, doc-comments
  cross-link source to config, and the filter syntax matches the
  Option A shape from D-44-D3 / 44-PATTERNS.md § ".config/nextest.toml"
  Option A. The first CI run that wires `cargo nextest run -p
  nono-cli --test env_vars --config-file .config/nextest.toml` into
  the Windows CI lane (per 44-PATTERNS.md "CI wire-up" snippet) will
  execute the determinism check.

Follow-up: the Phase 44 verifier (or a Phase 46/47 CI hardening
plan) should wire the nextest invocation into the Windows CI
workflow and capture the 50-runs result. Until then this disposition
stays PARTIAL.
