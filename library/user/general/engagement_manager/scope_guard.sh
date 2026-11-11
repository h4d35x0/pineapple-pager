#!/bin/bash
# scope_guard.sh: optional scope check for payloads, part of Engagement Manager (h4d35x0).
#
# Use from any payload:
#   SG=/root/payloads/user/general/engagement_manager/scope_guard.sh
#   [ -f "$SG" ] && . "$SG"
#   if type scope_check >/dev/null 2>&1 && ! scope_check "$TARGET_BSSID"; then
#       ERROR_DIALOG "$TARGET_BSSID is out of scope for the active engagement"; exit 1
#   fi
#
# scope_check VALUE   VALUE is an AP BSSID, a client MAC or an SSID.
#   returns 0  no engagement is active (the Pager works as normal), or VALUE is in scope
#   returns 1  an engagement is active and VALUE is not in its scope
#   returns 1  an engagement is active but its scope cannot be read (fails closed)

SCOPE_GUARD_ACTIVE="${ENGAGEMENT_BASE:-/root/engagements}/active.env"

scope_check() {
    local value="$1" dir scope mac
    [ -f "$SCOPE_GUARD_ACTIVE" ] || return 0
    dir="$(sed -n 's/^DIR=//p' "$SCOPE_GUARD_ACTIVE" | head -n 1)"
    scope="$dir/scope.tsv"
    [ -n "$dir" ] && [ -r "$scope" ] || return 1
    [ -n "$value" ] || return 1
    mac="$(printf '%s' "$value" | tr 'A-F' 'a-f')"
    awk -F'\t' -v v="$value" -v m="$mac" '
        ($1 == "ssid" && $2 == v) || (($1 == "bssid" || $1 == "client") && $2 == m) { found = 1; exit }
        END { exit(found ? 0 : 1) }' "$scope"
}
