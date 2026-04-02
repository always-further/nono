# Changelog

## [0.27.0] - 2026-04-02

### Bug Fixes

- *(test)* Use real temp directories for env_nono_allow_comma_separated

- *(proxy)* Strip port suffix from allow_domain entries in proxy host filter

- Tighten manifest round-trip fidelity and wire proxy from --config

- *(test)* Use portable paths in manifest round-trip test

- Harden --config flag conflicts and error handling

- *(macos)* Align Seatbelt signal isolation with Linux Landlock behaviour

- Gate deny-overlap test to Linux only

- Harden deny-overlap validation, reject unknown profile fields, narrow user_tools scope


### Dependencies

- *(deps)* Bump tracing-subscriber from 0.3.22 to 0.3.23

- *(deps)* Bump ureq from 3.2.0 to 3.3.0


### Documentation

- Replace mention of --supervised with --capability-elevation in README

- Address review feedback on wsl2 cross-references

- Add WSL2 cross-references to feature docs and fix discoverability

- Move endpoint filtering from credential injection to networking page

- *(keystore)* Update module docs for file:// scheme and add redaction


### Features

- *(policy)* Check credentials Option with is_some_and instead of field access

- *(proxy)* Block CONNECT to credential upstreams and smart NO_PROXY

- *(sandbox)* Add allow_domain ports to Landlock ConnectTcp rules

- *(profile)* Allow child to override inherited credentials to empty

- *(schema)* Allow additionalProperties for forward-compatible evolution

- *(cli)* Add `nono policy show --format manifest` for profile-to-manifest compilation

- *(cli)* Wire up --config manifest path in prepare_sandbox

- *(cli)* Add conflicts_with to --config flag

- *(manifest)* Add typify codegen, manifest module, and CapabilitySet conversion

- *(schema)* Add capability manifest JSON Schema

- *(proxy)* Auto-detect credential format from inject_header

- *(keystore)* Preserve significant whitespace in secret files

- *(profile)* Accept file:// credential keys in custom_credentials

- *(keystore)* Wire file:// into credential dispatch and CLI mappings

- *(keystore)* Add load_from_file() for file:// credential source

- *(keystore)* Add file:// URI validation for local file credentials

- *(policy)* Split linux system groups for granular host compatibility

- Add $XDG_RUNTIME_DIR to variable expansion


### Refactoring

- Deduplicate path expansion and fs grant construction

- *(keystore)* Extract file-backed secret helpers


### Testing

- *(env_vars)* Use as_str() for contains() calls

- *(env_vars)* Replace to_str() with display().to_string()

- *(profile,trust_scan)* Add env lock guards to fix test isolation

- *(cli)* Add global env lock for parallel test isolation

- *(cli)* Add integration tests for --config manifest flag

- *(profile)* Add endpoint_rules field to credential test fixtures


### Revert

- Keep ~/.local/state in user_tools, defer to #546

## [0.26.1] - 2026-03-31

### Bug Fixes

- *(learn)* Make Enter actually skip profile save prompt (closes #431)

- *(proxy)* Use lossy UTF-8 decoding for percent-encoded paths

- *(proxy)* Percent-decode paths before endpoint rule matching


### CI/CD

- *(workflows)* Decouple image build from release workflow


### Dependencies

- *(deps)* Bump docker/setup-buildx-action from 3.12.0 to 4.0.0

- *(deps)* Bump toml from 1.0.6+spec-1.1.0 to 1.0.7+spec-1.1.0

- *(deps)* Bump docker/setup-qemu-action from 3.7.0 to 4.0.0

- *(deps)* Bump docker/build-push-action from 6.19.2 to 7.0.0

- *(deps)* Bump docker/login-action from 3.7.0 to 4.0.0

- *(deps)* Bump sigstore/cosign-installer from 3.10.1 to 4.1.1


### Miscellaneous

- Add DCO sign-off requirement to CLAUDE.md

## [0.26.0] - 2026-03-30

### Bug Fixes

- *(wsl2)* Security hardening from code review

- *(learn)* Resolve fs_usage pipe buffering and process name mismatch on macOS


### CI/CD

- *(workflows)* Extract push condition to environment variable

- *(workflows)* Extract Docker image build into reusable workflow

- *(release)* Fix workflow inputs reference syntax

- *(release)* Use inputs.tag fallback in Docker publish condition

- *(release)* Support manual tag input in workflow conditions


### Documentation

- *(wsl2)* Add WSL2 documentation and feature matrix (Track 1.5)


### Features

- *(wsl2)* Add WSL2 feature matrix to setup --check-only (Track 1.4)

- *(wsl2)* Clarify proxy network enforcement on WSL2 (Track 1.3)

- *(wsl2)* Guard seccomp notify paths for WSL2 (Track 1.2)

- *(wsl2)* Add WSL2 detection, feature matrix, and integration tests (Track 1.1)

- *(proxy)* Add L7 method+path endpoint filtering for reverse proxy routes (#465)

- *(ci)* Add Docker image build and push to release workflow (#511) ([#511](https://github.com/always-further/nono/pull/511))

- *(cli)* Add --log-file flag to redirect logs to a file (#490) ([#490](https://github.com/always-further/nono/pull/490))


### Miscellaneous

- Add .gitattributes to enforce LF line endings

## [0.25.0] - 2026-03-26

### Features

- *(undo)* Support per-root exclusion filters in snapshot manager (#506) ([#506](https://github.com/always-further/nono/pull/506))

- *(sandbox/linux)* Add seccomp proxy-only network fallback (#503) ([#503](https://github.com/always-further/nono/pull/503))

- *(trust)* Add skip_dirs support to trust scanning and rollback preflight (#498) ([#498](https://github.com/always-further/nono/pull/498))

## [0.24.0] - 2026-03-25

### Documentation

- Add documentation for add_deny_commands (#495) ([#495](https://github.com/always-further/nono/pull/495))

- Update GitHub Action badge to agent-sign (#494) ([#494](https://github.com/always-further/nono/pull/494))


### Features

- *(sandbox/linux)* Add seccomp fallback for network  (#496) ([#496](https://github.com/always-further/nono/pull/496))

## [0.23.1] - 2026-03-25

### Bug Fixes

- Block Unix socket connections via add_deny_access; add add_deny_commands (#488) ([#488](https://github.com/always-further/nono/pull/488))

- Handle relative paths in --rollback-dest pre-check (#486) ([#486](https://github.com/always-further/nono/pull/486))

## [0.23.0] - 2026-03-24

### Dependencies

- *(deps)* Bump toml from 1.0.3+spec-1.1.0 to 1.0.6+spec-1.1.0 (#479) ([#479](https://github.com/always-further/nono/pull/479))

- *(deps)* Bump which from 8.0.0 to 8.0.2 (#478) ([#478](https://github.com/always-further/nono/pull/478))

- *(deps)* Bump aws-lc-rs from 1.16.1 to 1.16.2 (#477) ([#477](https://github.com/always-further/nono/pull/477))

- *(deps)* Bump mislav/bump-homebrew-formula-action from 3.6 to 4.1 (#476) ([#476](https://github.com/always-further/nono/pull/476))

- *(deps)* Bump actions/cache from 5.0.3 to 5.0.4 (#474) ([#474](https://github.com/always-further/nono/pull/474))

- *(deps)* Bump always-further/agent-sign from 0.0.4 to 0.0.8 (#475) ([#475](https://github.com/always-further/nono/pull/475))


### Documentation

- Remove compiled PDF, keep Typst source


### Features

- *(query)* Add diagnostic details to path query results (#472) ([#472](https://github.com/always-further/nono/pull/472))

- *(cli)* Add --rollback-dest flag to override snapshot storage path

## [0.22.1] - 2026-03-23

### Build

- *(audit)* Add cargo-audit ignores for AWS-LC X.509 advisories (#449) ([#449](https://github.com/always-further/nono/pull/449))


### CI/CD

- Add change classification to skip unnecessary jobs (#456) ([#456](https://github.com/always-further/nono/pull/456))


### Documentation

- Detect system architecture in deb installation command (#455) ([#455](https://github.com/always-further/nono/pull/455))

- Fix arrow direction in OS-level enforcement diagram (#453) ([#453](https://github.com/always-further/nono/pull/453))

- *(clients)* Recommend disabling agent sandboxes when running under nono (#451) ([#451](https://github.com/always-further/nono/pull/451))

## [0.22.0] - 2026-03-21

### Dependencies

- *(deps)* Bump rustls-webpki from 0.103.9 to 0.103.10 (#443) ([#443](https://github.com/always-further/nono/pull/443))


### Features

- *(trust)* Lazy verification of scan policies (#448) ([#448](https://github.com/always-further/nono/pull/448))

## [0.21.0] - 2026-03-21

### Bug Fixes

- *(setup)* Detect Landlock via syscall probe instead of LSM file (#417) ([#417](https://github.com/always-further/nono/pull/417))

- *(cli)* Add ~/.opencode to opencode profile paths (#421) ([#421](https://github.com/always-further/nono/pull/421))


### Features

- *(policy)* Add standard I/O and fd paths to base_posix group (#441) ([#441](https://github.com/always-further/nono/pull/441))

- *(trust)* Add --user flag to sign-policy for user-level trust policy (#440) ([#440](https://github.com/always-further/nono/pull/440))

- *(trust)* Scaffold policies, enforce missing includes at startup, and simplify write protection (#435) ([#435](https://github.com/always-further/nono/pull/435))


### Doc

- Fix installation command for nono-cli package (#426) ([#426](https://github.com/always-further/nono/pull/426))

## [0.20.0] - 2026-03-18

### Features

- Support multiple base profiles in extends field (#399) ([#399](https://github.com/always-further/nono/pull/399))

- *(cli)* Standardize network flag naming and add listen_port support (#415) ([#415](https://github.com/always-further/nono/pull/415))

## [0.19.0] - 2026-03-18

### Bug Fixes

- *(deny)* Canonicalize parent directories in deny access rules (#393) ([#393](https://github.com/always-further/nono/pull/393))


### Dependencies

- *(deps)* Bump tempfile from 3.26.0 to 3.27.0 (#398) ([#398](https://github.com/always-further/nono/pull/398))

- *(deps)* Bump sigstore-sign from 0.6.3 to 0.6.4 (#397) ([#397](https://github.com/always-further/nono/pull/397))

- *(deps)* Bump clap from 4.5.60 to 4.6.0 (#396) ([#396](https://github.com/always-further/nono/pull/396))

- *(deps)* Bump actions/download-artifact from 8.0.0 to 8.0.1 (#395) ([#395](https://github.com/always-further/nono/pull/395))

- *(deps)* Bump softprops/action-gh-release from 2.5.0 to 2.6.1 (#394) ([#394](https://github.com/always-further/nono/pull/394))


### Features

- *(sandbox)* Add IpcMode capability for POSIX semaphores (macOS Seatbelt) (#412) ([#412](https://github.com/always-further/nono/pull/412))

- *(learn)* Add macOS network tracing via nettop (#403) ([#403](https://github.com/always-further/nono/pull/403))

- Add linux-arm64 (#402) ([#402](https://github.com/always-further/nono/pull/402))

## [0.18.0] - 2026-03-16

### Bug Fixes

- *(hooks)* Use resolved path in capability display (#387) ([#387](https://github.com/always-further/nono/pull/387))

- *(main)* Move cwd resolution before pre-fork sandbox setup (#370) ([#370](https://github.com/always-further/nono/pull/370))

- *(policy)* Honor excluded dangerous command groups for direct exec (#368) ([#368](https://github.com/always-further/nono/pull/368))

- *(config)* Remove hardcoded dangerous commands list (#366) ([#366](https://github.com/always-further/nono/pull/366))

- *(exec)* Prevent implicit cwd access under restrictive profiles (#363) ([#363](https://github.com/always-further/nono/pull/363))


### Documentation

- *(profiles)* Simplify group-based profile creation guide (#390) ([#390](https://github.com/always-further/nono/pull/390))

- *(profiles-groups)* Expand built-in profiles and add policy override examples (#376) ([#376](https://github.com/always-further/nono/pull/376))


### Features

- Restyle --help output with grouped sections and bold headings (#345) ([#345](https://github.com/always-further/nono/pull/345))

- *(trust)* Skip well-known heavy directories in instruction file walk (#388) ([#388](https://github.com/always-further/nono/pull/388))

- *(cli)* Add `nono profile` scaffolding and authoring tooling (#385) ([#385](https://github.com/always-further/nono/pull/385))

- *(policy)* Extract git config paths into reusable group (#383) ([#383](https://github.com/always-further/nono/pull/383))

- *(cli)* Add `nono policy` introspection subcommand (#382) ([#382](https://github.com/always-further/nono/pull/382))

- *(profile)* Add profile-level override_deny for deny group exceptions (#380) ([#380](https://github.com/always-further/nono/pull/380))

- *(macos)* Gate open shim installation behind launch services flag (#374) ([#374](https://github.com/always-further/nono/pull/374))

- *(capability)* Remove exact file caps when deny patch overrides grant (#367) ([#367](https://github.com/always-further/nono/pull/367))

- *(policy)* Deprecate security.trust_groups in favor of policy.exclude_groups (#357) ([#357](https://github.com/always-further/nono/pull/357))

- *(policy)* Use default profile groups for runtime policy resolution (#356) ([#356](https://github.com/always-further/nono/pull/356))

- *(policy)* Add extends field to embedded profiles (#355) ([#355](https://github.com/always-further/nono/pull/355))

- Add default profile with base group configuration (#352) ([#352](https://github.com/always-further/nono/pull/352))

- *(profile)* Add composable policy patch configuration (#351) ([#351](https://github.com/always-further/nono/pull/351))


### Refactoring

- *(setup)* Move banner printing to main.rs (#386) ([#386](https://github.com/always-further/nono/pull/386))

- *(supervisor)* Remove never_grant in favor of protected roots (#360) ([#360](https://github.com/always-further/nono/pull/360))

- *(policy)* Remove deprecated base_groups and trust_groups fields (#359) ([#359](https://github.com/always-further/nono/pull/359))

- *(policy)* Deprecate base_groups in favor of default profile (#358) ([#358](https://github.com/always-further/nono/pull/358))

## [0.17.1] - 2026-03-13

### Bug Fixes

- Narrow broad linux /etc and /proc reads in system_read policy (#350) ([#350](https://github.com/always-further/nono/pull/350))


### Features

- *(sandbox/linux)* Add Landlock V6 signal scoping support (#344) ([#344](https://github.com/always-further/nono/pull/344))


### Miscellaneous

- Release v0.17.0

- Release v0.17.0

## [0.17.0] - 2026-03-13

### Bug Fixes

- Narrow broad linux /etc and /proc reads in system_read policy (#350) ([#350](https://github.com/always-further/nono/pull/350))


### Features

- *(sandbox/linux)* Add Landlock V6 signal scoping support (#344) ([#344](https://github.com/always-further/nono/pull/344))


### Miscellaneous

- Release v0.17.0

## [0.17.0] - 2026-03-12

### Bug Fixes

- Add OAuth2 URL opening support via supervisor IPC (#340) ([#340](https://github.com/always-further/nono/pull/340))

- Check access mode when determining if CWD is already covered (#334) ([#334](https://github.com/always-further/nono/pull/334))


### Documentation

- Updating docs to reflect pnpm support. (#332) ([#332](https://github.com/always-further/nono/pull/332))

- Update Homebrew install references (#326) ([#326](https://github.com/always-further/nono/pull/326))


### Features

- *(cli)* Add pluggable theme system with 6 built-in palettes (#341) ([#341](https://github.com/always-further/nono/pull/341))


### Refactoring

- *(cli)* Standardize flags to verb-noun ordering (#302) ([#302](https://github.com/always-further/nono/pull/302))

## [0.16.0] - 2026-03-10

### Bug Fixes

- Add pnpm paths to policy.json (#320) ([#320](https://github.com/always-further/nono/pull/320))

- Add uv paths to python_runtime group (#313) ([#313](https://github.com/always-further/nono/pull/313))

- Allow tty ioctls on Linux v5+ (#310) ([#310](https://github.com/always-further/nono/pull/310))


### Documentation

- Fix broken links and stale examples (#283) ([#283](https://github.com/always-further/nono/pull/283))


### Features

- Inject nono sandbox instructions via Claude Code system prompt (#322) ([#322](https://github.com/always-further/nono/pull/322))

- Add `--external-proxy-bypass` for routing domains direct (#309) ([#309](https://github.com/always-further/nono/pull/309))

- Abi-aware Landlock capability system (#256, #306) (#311) ([#311](https://github.com/always-further/nono/pull/311))

- Add built-in swival profile (#312) ([#312](https://github.com/always-further/nono/pull/312))

- Add same-sandbox process mode for signal and process-info (#299) ([#299](https://github.com/always-further/nono/pull/299))


### Miscellaneous

- Migrate Homebrew distribution from tap to homebrew-core (#321) ([#321](https://github.com/always-further/nono/pull/321))

- Simplify instruction file signing with nono-attest Action (#317) ([#317](https://github.com/always-further/nono/pull/317))

## [0.15.0] - 2026-03-09

### Bug Fixes

- Allow opentui data dir in opencode profile (#296) ([#296](https://github.com/always-further/nono/pull/296))

- `nono run` default to direct exec when supervision is not needed (#295) ([#295](https://github.com/always-further/nono/pull/295))

- Add tilde expansion to profile paths and opencode binary access (#294) ([#294](https://github.com/always-further/nono/pull/294))

- Honor silent tracing output (#290) ([#290](https://github.com/always-further/nono/pull/290))

- Preserve supervised Linux open semantics (#289) ([#289](https://github.com/always-further/nono/pull/289))


### Dependencies

- *(deps)* Bump sigstore-verify from 0.6.3 to 0.6.4 (#305) ([#305](https://github.com/always-further/nono/pull/305))

- *(deps)* Bump libc from 0.2.182 to 0.2.183 (#304) ([#304](https://github.com/always-further/nono/pull/304))

- *(deps)* Bump tempfile from 3.25.0 to 3.26.0 (#303) ([#303](https://github.com/always-further/nono/pull/303))


### Documentation

- Document that gemini baseurl is ignored in opencode (#307) ([#307](https://github.com/always-further/nono/pull/307))


### Features

- Add Apple Passwords URI credential support (#229) ([#229](https://github.com/always-further/nono/pull/229))

- Add built-in Codex profile (#300) ([#300](https://github.com/always-further/nono/pull/300))

- Add Debian package support (#298) ([#298](https://github.com/always-further/nono/pull/298))

- Add capability_elevation profile field and OS-aware groups (#293) ([#293](https://github.com/always-further/nono/pull/293))

- Make claude-code profile platform-aware (#291) ([#291](https://github.com/always-further/nono/pull/291))

## [0.14.0] - 2026-03-08

### Bug Fixes

- Resolve symlinked paths in deny rule checks (#272) (#279) ([#279](https://github.com/always-further/nono/pull/279))


### Features

- Add environment variable equivalents for CLI flags (#270) (#278) ([#278](https://github.com/always-further/nono/pull/278))

## [0.12.0] - 2026-03-07

### Bug Fixes

- Resolve dirfd-relative paths in seccomp-notify handler (#262) (#277) ([#277](https://github.com/always-further/nono/pull/277))

- Show platform-correct path in user-level policy warning (#263) ([#263](https://github.com/always-further/nono/pull/263))

- Enforce macOS signal isolation via Seatbelt (#264) ([#264](https://github.com/always-further/nono/pull/264))

- *(profile)* Allow clearing inherited network profiles (#252) ([#252](https://github.com/always-further/nono/pull/252))


### Documentation

- *(readme)* Update latest release note (#253) ([#253](https://github.com/always-further/nono/pull/253))


### Features

- Add port_allow to profile JSON NetworkConfig (#254) (#276) ([#276](https://github.com/always-further/nono/pull/276))

- Context-aware diagnostic banner for sandbox failures (#275) ([#275](https://github.com/always-further/nono/pull/275))

- *(cli)* Add --net-allow override (#251) ([#251](https://github.com/always-further/nono/pull/251))

- Add macOS learn mode using fs_usage and profile save prompt (#244) ([#244](https://github.com/always-further/nono/pull/244))


### Miscellaneous

- Implement Cargo audit and update AWS-LC (#273) ([#273](https://github.com/always-further/nono/pull/273))

- Remove Monitor strategy, make Supervised the default (#267) ([#267](https://github.com/always-further/nono/pull/267))

## [0.11.0] - 2026-03-05

### Features

- Add --allow-port for bidirectional localhost IPC between sandboxes (#248) ([#248](https://github.com/always-further/nono/pull/248))

- Unify proxy network audit with session audit trail (#231) ([#231](https://github.com/always-further/nono/pull/231))


### Miscellaneous

- Add GitHub issue templates for bugs, features, and onboarding (#247) ([#247](https://github.com/always-further/nono/pull/247))

- Add GitHub issue templates for bugs, features, and onboarding

## [0.10.0] - 2026-03-04

### Bug Fixes

- Don't inject phantom token for unavailable credentials (#234) (#236) ([#236](https://github.com/always-further/nono/pull/236))

- Allow CLI flags to upgrade access mode of profile-covered paths (#232) ([#232](https://github.com/always-further/nono/pull/232))

- Landlock network false-negative and runtime ABI probe in setup (#230) ([#230](https://github.com/always-further/nono/pull/230))

- Proxy host filtering and credential resolution for sandboxed (#215) ([#215](https://github.com/always-further/nono/pull/215))

- Include character device files in policy group resolution (#218) ([#218](https://github.com/always-further/nono/pull/218))

- Pre-create claude-code config lock file on Linux (#221) ([#221](https://github.com/always-further/nono/pull/221))


### Features

- Add --override-deny CLI flag for targeted deny group exemptions (#242) ([#242](https://github.com/always-further/nono/pull/242))

- Add env:// credential scheme and GitHub token proxy support (#227) ([#227](https://github.com/always-further/nono/pull/227))

- Remove RFC1918 private network CIDR deny list from host filter (#226) ([#226](https://github.com/always-further/nono/pull/226))

- Add allowed_commands support to profile security config (#204) ([#204](https://github.com/always-further/nono/pull/204))

- Profile inheritance via `extends` field (#203) ([#203](https://github.com/always-further/nono/pull/203))

## [0.9.0] - 2026-03-03

### Bug Fixes

- Prevent --net-block bypass via proxy credential activation (#202) ([#202](https://github.com/always-further/nono/pull/202))


### Features

- Rollback preflight with auto-exclude and walk budget (#200) ([#200](https://github.com/always-further/nono/pull/200))

## [0.8.1] - 2026-03-03

### Miscellaneous

- Release v0.8.0

## [0.8.0] - 2026-03-02

### Bug Fixes

- Reject parent directory traversal in snapshot manifest validation (#201) ([#201](https://github.com/always-further/nono/pull/201))

- Writes setup profiles to the correct directory on macOS (#184) ([#184](https://github.com/always-further/nono/pull/184))

- Add AccessFs::RemoveDir to Landlock write permissions (#199) ([#199](https://github.com/always-further/nono/pull/199))

- *(network)* Add claude.ai to llm_apis allow list (#206) ([#206](https://github.com/always-further/nono/pull/206))


### CI/CD

- Add conventional commits enforcement and auto-labeling (#194) ([#194](https://github.com/always-further/nono/pull/194))


### Features

- Add 7 new integration test suites and parallelize test runner (#214) ([#214](https://github.com/always-further/nono/pull/214))


### Miscellaneous

- *(docs)* Add 1Password credential injection documentation (#198) ([#198](https://github.com/always-further/nono/pull/198))

## [0.7.0] - 2026-03-01

### 🚀 Features

- Add 1Password secret injection via op:// URI support (#183)
## [0.6.1] - 2026-02-27

### 🚀 Features

- First release of seperarate nono and nono-cli packages

