#!/usr/bin/env bash
set -euo pipefail

NONO="${NONO:-${BIN:-./target/debug/nono}}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ETI witness requires Linux Landlock enforcement. Current platform: $(uname -s)" >&2
  exit 2
fi

if [[ ! -x "$NONO" ]]; then
  echo "nono binary not found or not executable: $NONO" >&2
  echo "Run: make build-cli" >&2
  exit 2
fi

SH_BIN="$(command -p -v sh || command -v sh || true)"
GIT_BIN="$(command -p -v git || command -v git || true)"
SSH_BIN="$(command -p -v ssh || command -v ssh || true)"

if [[ -z "$SH_BIN" || -z "$GIT_BIN" ]]; then
  echo "This witness needs sh and git on PATH." >&2
  exit 2
fi

TMPDIR_ETI="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_ETI"' EXIT

BASE_PROFILE="$TMPDIR_ETI/eti-agent-git.json"
SSH_PROFILE="$TMPDIR_ETI/eti-agent-git-ssh.json"
OUT="$TMPDIR_ETI/out.txt"

write_base_profile() {
  # Python is used only to emit JSON safely outside the ETI sandbox. It is not
  # part of the witnessed command chain.
  python3 - "$BASE_PROFILE" "$SH_BIN" "$GIT_BIN" <<'PY'
import json
import sys

profile_path, sh_bin, git_bin = sys.argv[1:4]
profile = {
    "extends": "default",
    "meta": {
        "name": "eti-agent-git-witness",
        "version": "1.0.0",
        "description": "Witness profile: a shell-shaped agent command may call git; direct git is denied."
    },
    "workdir": {"access": "none"},
    "network": {"block": False},
    "command_policies": {
        "entrypoint": "sh",
        "commands": {
            "sh": {
                "executable": sh_bin,
                "can_use": ["git"],
                "sandbox": {
                    "fs_read": ["."],
                    "fs_write": ["."],
                    "environment": {
                        "allow_vars": [
                            "PATH", "HOME", "USER", "LOGNAME", "TERM",
                            "LANG", "LC_*", "GIT_*"
                        ]
                    }
                }
            },
            "git": {
                "executable": git_bin,
                "from": {
                    "sh": {
                        "fs_read": ["."],
                        "fs_write": ["."],
                        "environment": {
                            "allow_vars": [
                                "PATH", "HOME", "USER", "LOGNAME",
                                "TERM", "LANG", "LC_*"
                            ],
                            "set_vars": {
                                "GIT_PAGER": "",
                                "GIT_CONFIG_COUNT": "1",
                                "GIT_CONFIG_KEY_0": "core.pager",
                                "GIT_CONFIG_VALUE_0": ""
                            }
                        }
                    },
                    "session": "deny"
                }
            }
        }
    }
}
with open(profile_path, "w", encoding="utf-8") as f:
    json.dump(profile, f, indent=2)
    f.write("\n")
PY
}

write_ssh_profile() {
  # Python is used only to emit JSON safely outside the ETI sandbox. It is not
  # part of the witnessed command chain.
  python3 - "$SSH_PROFILE" "$SH_BIN" "$GIT_BIN" "$SSH_BIN" <<'PY'
import json
import os
import pathlib
import sys

profile_path, sh_bin, git_bin, ssh_bin = sys.argv[1:5]
known_hosts = []
for candidate in [
    pathlib.Path.home() / ".ssh" / "known_hosts",
    pathlib.Path.home() / ".ssh" / "known_hosts2",
    pathlib.Path("/etc/ssh/ssh_known_hosts"),
    pathlib.Path("/etc/ssh/ssh_known_hosts2"),
]:
    if candidate.exists():
        known_hosts.append(str(candidate))

profile = {
    "extends": "default",
    "meta": {
        "name": "eti-agent-git-ssh-witness",
        "version": "1.0.0",
        "description": "Witness profile: sh may call git, git may call ssh with ssh-agent, direct git/ssh are denied."
    },
    "workdir": {"access": "none"},
    "network": {"block": False},
    "command_policies": {
        "entrypoint": "sh",
        "credentials": {
            "ssh-agent": {
                "type": "local-socket",
                "path": "$SSH_AUTH_SOCK",
                "mode": "connect",
                "env_var": "SSH_AUTH_SOCK"
            }
        },
        "commands": {
            "sh": {
                "executable": sh_bin,
                "can_use": ["git"],
                "sandbox": {
                    "fs_read": ["."],
                    "fs_write": ["."],
                    "environment": {
                        "allow_vars": [
                            "PATH", "HOME", "USER", "LOGNAME", "TERM",
                            "LANG", "LC_*", "GIT_*"
                        ]
                    }
                }
            },
            "git": {
                "executable": git_bin,
                "can_use": ["ssh"],
                "from": {
                    "sh": {
                        "fs_read": ["."],
                        "fs_write": ["."],
                        "environment": {
                            "allow_vars": [
                                "PATH", "HOME", "USER", "LOGNAME", "TERM",
                                "LANG", "LC_*", "GIT_*"
                            ],
                            "set_vars": {
                                "GIT_CONFIG_COUNT": "3",
                                "GIT_CONFIG_KEY_0": "core.sshCommand",
                                "GIT_CONFIG_VALUE_0": "ssh",
                                "GIT_CONFIG_KEY_1": "core.pager",
                                "GIT_CONFIG_VALUE_1": "",
                                "GIT_CONFIG_KEY_2": "advice.detachedHead",
                                "GIT_CONFIG_VALUE_2": "false",
                                "GIT_PAGER": "",
                                "GIT_SSH": "ssh",
                                "GIT_SSH_VARIANT": "ssh",
                                "GIT_TERMINAL_PROMPT": "0"
                            }
                        }
                    },
                    "session": "deny"
                }
            },
            "ssh": {
                "executable": ssh_bin,
                "from": {
                    "git": {
                        "use_credentials": ["ssh-agent"],
                        "argv_prepend": ["-o", "IdentityFile=none"],
                        "fs_read_file": known_hosts,
                        "network": {
                            "tcp_connect_ports": [22]
                        },
                        "environment": {
                            "allow_vars": [
                                "PATH", "HOME", "USER", "LOGNAME", "TERM",
                                "LANG", "LC_*", "GIT_PROTOCOL"
                            ]
                        }
                    },
                    "session": "deny"
                }
            }
        }
    }
}
with open(profile_path, "w", encoding="utf-8") as f:
    json.dump(profile, f, indent=2)
    f.write("\n")
PY
}

show_output() {
  sed -n '1,120p' "$OUT"
}

run_success() {
  local label="$1"
  shift
  echo
  echo "== $label"
  if "$@" >"$OUT" 2>&1; then
    show_output
  else
    show_output
    echo "FAIL: expected success" >&2
    exit 1
  fi
}

run_denied() {
  local label="$1"
  shift
  echo
  echo "== $label"
  if "$@" >"$OUT" 2>&1; then
    show_output
    echo "FAIL: expected ETI denial" >&2
    exit 1
  fi
  show_output
  if ! grep -Eq "ETI denied|direct exec|entrypoint|explicit_deny|blocked" "$OUT"; then
    echo "FAIL: command failed, but output did not look like an ETI denial" >&2
    exit 1
  fi
}

write_base_profile

echo "Using nono: $NONO"
echo "Generated base profile: $BASE_PROFILE"

run_success "validate base profile" \
  "$NONO" profile validate "$BASE_PROFILE"

run_success "agent-shaped command can call git through an approved chain: sh -> git" \
  "$NONO" run --profile "$BASE_PROFILE" -- \
  sh -c 'git --version'

run_denied "direct git from the session is denied" \
  "$NONO" run --profile "$BASE_PROFILE" -- git --version

run_denied "direct canonical git path is denied, so PATH shims are not bypassed" \
  "$NONO" run --profile "$BASE_PROFILE" -- "$GIT_BIN" --version

if [[ "${ETI_SSH_PROBE:-0}" != "1" ]]; then
  echo
  echo "SSH probe skipped. To witness sh -> git -> ssh, run:"
  echo "  ETI_SSH_PROBE=1 ETI_SSH_REMOTE=git@github.com:OWNER/REPO.git NONO=$NONO $0"
  exit 0
fi

if [[ -z "$SSH_BIN" ]]; then
  echo "SSH probe requested, but ssh was not found." >&2
  exit 2
fi

if [[ -z "${SSH_AUTH_SOCK:-}" ]]; then
  echo "SSH probe requested, but SSH_AUTH_SOCK is unset." >&2
  echo "Start an ssh-agent and add a key first." >&2
  exit 2
fi

REMOTE="${ETI_SSH_REMOTE:-git@github.com:github/gitignore.git}"

if [[ "$REMOTE" == git@github.com:* ]] && ! ssh-keygen -F github.com >/dev/null 2>&1; then
  echo "SSH probe requested, but github.com is not in known_hosts." >&2
  echo "Prime it outside nono first, for example:" >&2
  echo "  ssh -o IdentityFile=none -T git@github.com" >&2
  exit 2
fi

write_ssh_profile

echo
echo "Generated SSH profile: $SSH_PROFILE"

run_success "validate SSH chain profile" \
  "$NONO" profile validate "$SSH_PROFILE"

run_denied "direct ssh from the session is denied" \
  "$NONO" run --profile "$SSH_PROFILE" -- ssh -V

run_denied "direct canonical ssh path is denied" \
  "$NONO" run --profile "$SSH_PROFILE" -- "$SSH_BIN" -V

run_success "agent-shaped command can perform private-dependency-shaped chain: sh -> git -> ssh" \
  "$NONO" run --profile "$SSH_PROFILE" -- \
  sh -c 'git ls-remote "$1" HEAD' sh "$REMOTE"

echo
echo "ETI composable chaining witness passed."
