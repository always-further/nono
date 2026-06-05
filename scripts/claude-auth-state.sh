#!/usr/bin/env bash
# Inspect and mutate Claude auth state using the same path rules Claude uses.
#
# This script mirrors Claude's auth storage resolution closely enough to test:
# - access-token expiry (forces refresh)
# - refresh-token failure
# - missing access token
# - local logout state
#
# The `--claude-config-dir` flag models `CLAUDE_CONFIG_DIR` being explicitly
# set. That matters even when the value is "$HOME/.claude", because Claude
# hashes the explicit config dir into the macOS keychain service name and also
# changes the fallback global config path.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  ./scripts/claude-auth-state.sh --mode MODE [--claude-config-dir DIR]

Modes:
  show
      Print the resolved Claude auth paths and keychain service names.

  expire-access
      Set claudeAiOauth.expiresAt=0 to force Claude into its refresh path.

  break-refresh
      Set expiresAt=0 and replace refreshToken with an invalid value.

  drop-access-token
      Remove claudeAiOauth.accessToken so Claude treats stored OAuth as absent.

  logout-local
      Delete local OAuth storage, remove the legacy API key, and clear
      oauthAccount/primaryApiKey in global config.

Notes:
  - If --claude-config-dir is omitted, this script uses the default Claude
    config layout rooted at "$HOME/.claude".
  - If --claude-config-dir is provided, this script models
    CLAUDE_CONFIG_DIR=DIR being set for Claude itself, even if DIR is
    "$HOME/.claude".
  - On macOS, the keychain entry is primary and plaintext credentials are the
    fallback. Mutation modes update both when both exist.

Examples:
  ./scripts/claude-auth-state.sh --mode show
  ./scripts/claude-auth-state.sh --mode expire-access
  ./scripts/claude-auth-state.sh --mode break-refresh --claude-config-dir /tmp/claude-auth
  ./scripts/claude-auth-state.sh --mode logout-local
EOF
}

fail() {
    echo "Error: $*" >&2
    exit 1
}

note() {
    printf '%s\n' "$*"
}

is_truthy() {
    local value
    value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        1|true|yes|on)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

hash_prefix() {
    local input="$1"

    if command -v shasum >/dev/null 2>&1; then
        printf '%s' "$input" | shasum -a 256 | awk '{print substr($1, 1, 8)}'
        return
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$input" | sha256sum | awk '{print substr($1, 1, 8)}'
        return
    fi

    perl -MDigest::SHA=sha256_hex -e '
        use strict;
        use warnings;
        local $/;
        my $value = <STDIN>;
        print substr(sha256_hex($value // q{}), 0, 8);
    '
}

oauth_file_suffix() {
    if [[ -n "${CLAUDE_CODE_CUSTOM_OAUTH_URL:-}" ]]; then
        printf '%s' '-custom-oauth'
        return
    fi

    if [[ "${USER_TYPE:-}" == "ant" ]]; then
        if is_truthy "${USE_LOCAL_OAUTH:-}"; then
            printf '%s' '-local-oauth'
            return
        fi
        if is_truthy "${USE_STAGING_OAUTH:-}"; then
            printf '%s' '-staging-oauth'
            return
        fi
    fi

    printf '%s' ''
}

get_username() {
    if [[ -n "${USER:-}" ]]; then
        printf '%s' "$USER"
        return
    fi

    if id -un >/dev/null 2>&1; then
        id -un
        return
    fi

    printf '%s' 'claude-code-user'
}

is_macos() {
    [[ "$(uname -s)" == "Darwin" ]]
}

config_dir="$HOME/.claude"
config_dir_explicit=0
mode=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            [[ $# -ge 2 ]] || fail "--mode requires a value"
            mode="$2"
            shift 2
            ;;
        --claude-config-dir)
            [[ $# -ge 2 ]] || fail "--claude-config-dir requires a value"
            config_dir="$2"
            config_dir_explicit=1
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            fail "unknown argument: $1"
            ;;
    esac
done

[[ -n "$mode" ]] || fail "--mode is required"

oauth_suffix="$(oauth_file_suffix)"
credentials_path="$config_dir/.credentials.json"
legacy_config_path="$config_dir/.config.json"

global_config_path() {
    if [[ -f "$legacy_config_path" ]]; then
        printf '%s' "$legacy_config_path"
        return
    fi

    if [[ "$config_dir_explicit" -eq 1 ]]; then
        printf '%s/.claude%s.json' "$config_dir" "$oauth_suffix"
        return
    fi

    printf '%s/.claude%s.json' "$HOME" "$oauth_suffix"
}

keychain_service_name() {
    local service_suffix="$1"
    local dir_hash=""

    if [[ "$config_dir_explicit" -eq 1 ]]; then
        dir_hash="-$(hash_prefix "$config_dir")"
    fi

    printf 'Claude Code%s%s%s' "$oauth_suffix" "$service_suffix" "$dir_hash"
}

oauth_keychain_service="$(keychain_service_name '-credentials')"
api_key_keychain_service="$(keychain_service_name '')"
username="$(get_username)"
global_config="$(global_config_path)"

backup_dir=""

ensure_backup_dir() {
    if [[ -n "$backup_dir" ]]; then
        return
    fi

    local old_umask
    old_umask="$(umask)"
    umask 077
    backup_dir="$(mktemp -d "${TMPDIR:-/tmp}/claude-auth-state.XXXXXX")"
    umask "$old_umask"
}

backup_contents() {
    local name="$1"
    local contents="$2"
    ensure_backup_dir
    printf '%s' "$contents" > "$backup_dir/$name"
    chmod 600 "$backup_dir/$name" 2>/dev/null || true
}

backup_file() {
    local path="$1"
    local name="$2"
    [[ -f "$path" ]] || return 0

    ensure_backup_dir
    cp "$path" "$backup_dir/$name"
    chmod 600 "$backup_dir/$name" 2>/dev/null || true
}

keychain_item_exists() {
    local service_name="$1"

    is_macos || return 1
    security find-generic-password -a "$username" -w -s "$service_name" >/dev/null 2>&1
}

read_keychain_item() {
    local service_name="$1"
    security find-generic-password -a "$username" -w -s "$service_name"
}

write_keychain_item() {
    local service_name="$1"
    local value="$2"
    local hex_value

    hex_value="$(
        printf '%s' "$value" | perl -e '
            use strict;
            use warnings;
            local $/;
            my $input = <STDIN>;
            print unpack("H*", $input // q{});
        '
    )"

    security add-generic-password -U -a "$username" -s "$service_name" -X "$hex_value" >/dev/null
}

delete_keychain_item() {
    local service_name="$1"
    security delete-generic-password -a "$username" -s "$service_name" >/dev/null 2>&1
}

mutate_oauth_storage_json() {
    local requested_mode="$1"

    perl -MJSON::PP -e '
        use strict;
        use warnings;

        my $mode = shift @ARGV;
        local $/;
        my $input = <STDIN>;
        die "missing JSON input\n" if !defined($input) || $input eq q{};

        my $json = JSON::PP->new->ascii->canonical->pretty;
        my $data = $json->decode($input);
        die "expected JSON object\n" if ref($data) ne q{HASH};

        my $oauth = $data->{claudeAiOauth};
        die "claudeAiOauth is missing\n" if ref($oauth) ne q{HASH};

        if ($mode eq q{expire-access}) {
            $oauth->{expiresAt} = 0;
        } elsif ($mode eq q{break-refresh}) {
            $oauth->{expiresAt} = 0;
            $oauth->{refreshToken} = q{invalid-refresh-token};
        } elsif ($mode eq q{drop-access-token}) {
            delete $oauth->{accessToken};
        } else {
            die "unsupported mode: $mode\n";
        }

        print $json->encode($data);
    ' "$requested_mode"
}

clear_global_auth_json() {
    perl -MJSON::PP -e '
        use strict;
        use warnings;

        local $/;
        my $input = <STDIN>;
        die "missing JSON input\n" if !defined($input) || $input eq q{};

        my $json = JSON::PP->new->ascii->canonical->pretty;
        my $data = $json->decode($input);
        die "expected JSON object\n" if ref($data) ne q{HASH};

        delete $data->{oauthAccount};
        delete $data->{primaryApiKey};

        print $json->encode($data);
    '
}

write_credentials_file() {
    local contents="$1"
    mkdir -p "$config_dir"
    printf '%s' "$contents" > "$credentials_path"
    chmod 600 "$credentials_path" 2>/dev/null || true
}

show_state() {
    note "Mode: show"
    note "Config dir: $config_dir"
    if [[ "$config_dir_explicit" -eq 1 ]]; then
        note "CLAUDE_CONFIG_DIR semantics: explicit"
    else
        note "CLAUDE_CONFIG_DIR semantics: default"
    fi
    note "OAuth suffix: ${oauth_suffix:-<prod>}"
    note "Credentials file: $credentials_path"
    if [[ -f "$credentials_path" ]]; then
        note "Credentials file exists: yes"
    else
        note "Credentials file exists: no"
    fi
    note "Global config file: $global_config"
    if [[ -f "$global_config" ]]; then
        note "Global config exists: yes"
    else
        note "Global config exists: no"
    fi

    if is_macos; then
        note "OAuth keychain service: $oauth_keychain_service"
        if keychain_item_exists "$oauth_keychain_service"; then
            note "OAuth keychain entry exists: yes"
        else
            note "OAuth keychain entry exists: no"
        fi

        note "Legacy API key keychain service: $api_key_keychain_service"
        if keychain_item_exists "$api_key_keychain_service"; then
            note "Legacy API key keychain entry exists: yes"
        else
            note "Legacy API key keychain entry exists: no"
        fi
    else
        note "Keychain inspection: skipped (non-macOS)"
    fi

    if [[ "$config_dir_explicit" -eq 1 ]]; then
        printf 'Run Claude with: CLAUDE_CONFIG_DIR=%q claude\n' "$config_dir"
    else
        note "Run Claude with its default config dir."
    fi
}

mutate_oauth_state() {
    local requested_mode="$1"
    local keychain_present=0
    local keychain_original=""
    local keychain_updated=""
    local file_present=0
    local file_original=""
    local file_updated=""

    if keychain_item_exists "$oauth_keychain_service"; then
        keychain_present=1
        keychain_original="$(read_keychain_item "$oauth_keychain_service")"
        keychain_updated="$(printf '%s' "$keychain_original" | mutate_oauth_storage_json "$requested_mode")"
    fi

    if [[ -f "$credentials_path" ]]; then
        file_present=1
        file_original="$(cat "$credentials_path")"
        file_updated="$(printf '%s' "$file_original" | mutate_oauth_storage_json "$requested_mode")"
    fi

    if [[ "$keychain_present" -eq 0 && "$file_present" -eq 0 ]]; then
        fail "no stored OAuth credentials were found in keychain or $credentials_path"
    fi

    if [[ "$keychain_present" -eq 1 ]]; then
        backup_contents "oauth-keychain.json" "$keychain_original"
        write_keychain_item "$oauth_keychain_service" "$keychain_updated"
        note "Updated OAuth keychain entry: $oauth_keychain_service"
    fi

    if [[ "$file_present" -eq 1 ]]; then
        backup_file "$credentials_path" "credentials.json"
        write_credentials_file "$file_updated"
        note "Updated plaintext credentials: $credentials_path"
    fi

    note "Backup dir: $backup_dir (contains secrets)"
}

logout_local() {
    local changed=0

    if keychain_item_exists "$oauth_keychain_service"; then
        backup_contents "oauth-keychain.json" "$(read_keychain_item "$oauth_keychain_service")"
        delete_keychain_item "$oauth_keychain_service"
        note "Deleted OAuth keychain entry: $oauth_keychain_service"
        changed=1
    fi

    if keychain_item_exists "$api_key_keychain_service"; then
        backup_contents "api-key-keychain.txt" "$(read_keychain_item "$api_key_keychain_service")"
        delete_keychain_item "$api_key_keychain_service"
        note "Deleted legacy API key keychain entry: $api_key_keychain_service"
        changed=1
    fi

    if [[ -f "$credentials_path" ]]; then
        backup_file "$credentials_path" "credentials.json"
        rm -f "$credentials_path"
        note "Deleted plaintext credentials: $credentials_path"
        changed=1
    fi

    if [[ -f "$global_config" ]]; then
        local global_original
        local global_updated
        global_original="$(cat "$global_config")"
        global_updated="$(printf '%s' "$global_original" | clear_global_auth_json)"
        backup_file "$global_config" "$(basename "$global_config")"
        mkdir -p "$(dirname "$global_config")"
        printf '%s' "$global_updated" > "$global_config"
        chmod 600 "$global_config" 2>/dev/null || true
        note "Cleared oauthAccount and primaryApiKey in: $global_config"
        changed=1
    fi

    if [[ "$changed" -eq 0 ]]; then
        note "No local Claude auth state was found to clear."
        return
    fi

    note "Backup dir: $backup_dir (contains secrets)"
}

case "$mode" in
    show)
        show_state
        ;;
    expire-access|break-refresh|drop-access-token)
        mutate_oauth_state "$mode"
        ;;
    logout-local)
        logout_local
        ;;
    *)
        fail "unsupported mode: $mode"
        ;;
esac
