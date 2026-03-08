# Changelog

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

