#!/usr/bin/env bash
# Monitor Claude Code auth state to diagnose token expiration
# Run: ./scripts/monitor-auth.sh [--once]
# Logs to: /tmp/nono-auth-monitor.log

set -euo pipefail

LOG="/tmp/nono-auth-monitor.log"
INTERVAL=3600  # 1 hour
CRED_FILE="$HOME/.claude/.credentials.json"
SETTINGS_FILE="$HOME/.claude/settings.json"
CLAUDE_JSON="$HOME/.claude.json"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"
}

check_file() {
    local path="$1"
    local label="$2"
    if [ -f "$path" ]; then
        local mod_time size
        mod_time=$(stat -f '%Sm' -t '%Y-%m-%d %H:%M:%S' "$path" 2>/dev/null || echo "unknown")
        size=$(stat -f '%z' "$path" 2>/dev/null || echo "unknown")
        log "  $label: exists, modified=$mod_time, size=${size}B"

        # Check for key indicators without exposing secrets
        if command -v jq &>/dev/null; then
            local key_source key_prefix expires_at has_refresh
            key_source=$(jq -r '.apiKeySource // empty' "$path" 2>/dev/null || true)
            key_prefix=$(jq -r '.apiKey // .api_key // empty' "$path" 2>/dev/null | head -c 20 || true)
            expires_at=$(jq -r '.expiresAt // .expires_at // empty' "$path" 2>/dev/null || true)
            has_refresh=$(jq -r 'if .refreshToken // .refresh_token then "yes" else "no" end' "$path" 2>/dev/null || true)

            [ -n "$key_source" ] && log "    apiKeySource=$key_source"
            [ -n "$key_prefix" ] && log "    key_prefix=${key_prefix}..."
            [ -n "$expires_at" ] && log "    expires_at=$expires_at"
            [ "$has_refresh" = "yes" ] && log "    has_refresh_token=yes"
        fi
    else
        log "  $label: NOT FOUND"
    fi
}

check_api() {
    # Lightweight check: hit the roles endpoint to see if auth works
    # This doesn't consume tokens, just validates the key
    local api_key
    api_key=$(jq -r '.apiKey // .api_key // empty' "$SETTINGS_FILE" 2>/dev/null || true)
    if [ -z "$api_key" ]; then
        api_key=$(jq -r '.apiKey // .api_key // empty' "$CRED_FILE" 2>/dev/null || true)
    fi

    if [ -n "$api_key" ]; then
        local status
        status=$(curl -s -o /dev/null -w '%{http_code}' \
            -H "x-api-key: $api_key" \
            -H "anthropic-version: 2023-06-01" \
            "https://api.anthropic.com/v1/models" 2>/dev/null || echo "failed")
        log "  API check: HTTP $status"
    else
        log "  API check: no key found to test"
    fi
}

run_check() {
    log "=== Auth State Check ==="
    check_file "$CRED_FILE" "credentials.json"
    check_file "$SETTINGS_FILE" "settings.json"
    check_file "$CLAUDE_JSON" ".claude.json"
    check_api
    log "=== End Check ==="
    log ""
}

log "Auth monitor started (interval=${INTERVAL}s, log=$LOG)"

if [ "${1:-}" = "--once" ]; then
    run_check
    exit 0
fi

while true; do
    run_check
    sleep "$INTERVAL"
done
