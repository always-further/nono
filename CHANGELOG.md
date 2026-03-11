# Changelog

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

