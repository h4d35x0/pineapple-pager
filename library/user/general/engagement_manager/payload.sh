#!/bin/bash
# Title: Engagement Manager
# Author: h4d35x0
# Description: Optional engagement mode. Records scope and authorization, can restrict PineAP to in-scope targets, and builds a timestamped activity report. Does nothing until you start an engagement here.
# Version: 1.0
# Category: general
#
# Nothing changes on the Pager until "Start engagement" is chosen here. With no active engagement the scope
# helper (scope_guard.sh) answers "in scope" for everything, so other payloads behave exactly as before.
#
# What it does while an engagement is active:
#   - Scope: SSIDs, AP BSSIDs and client MACs, from /root/engagements/scope.txt or picked from recon.
#     scope.txt lines:  ssid <name> | bssid <mac> | client <mac>   (# comments allowed)
#   - Optional enforcement with PineAP's own filters: the SSID filter is set to allow only in-scope SSIDs and,
#     if client MACs are in scope, the client filter to allow only those. The previous filter config is saved
#     and restored exactly when the engagement ends. These filters govern which networks PineAP serves and
#     which clients may connect to it; they do NOT stop deauth or other payloads. Payloads that want that call
#     scope_check from scope_guard.sh.
#   - Report: everything the system log recorded between the START and END markers (payload launches,
#     alerts, errors), the scope, the authorization statement, and loot created during the engagement.
#     Needs the persistent log (/mmc/root/logs/system.log). This is an activity/audit report; for the recon
#     findings (APs, clients, handshakes, encryption, WiGLE) run recondb_reporting (Engagement Report Generator).
#
# Sources: activity-log fields (what ran, when, against which target) per A. Champion, Practical Purple
# Teaming, p.276 (VECTR test-case logging) and pp.403-412 on stating scope in reports; scoping per
# Red Team Engineering, p.24.

BASE="${ENGAGEMENT_BASE:-/root/engagements}"
ACTIVE="$BASE/active.env"
SCOPE_TXT="$BASE/scope.txt"
API_SOCK="${API_SOCK:-/tmp/api.sock}"
LOG_FILE="${ENGAGEMENT_SYSLOG:-/mmc/root/logs/system.log}"

mkdir -p "$BASE"
chmod 700 "$BASE" 2>/dev/null

confirmed() { [ "$1" = "${DUCKYSCRIPT_USER_CONFIRMED:-1}" ]; }

active_get() { sed -n "s/^$1=//p" "$ACTIVE" 2>/dev/null | head -n 1; }

api() {   # api GET|PUT path [json]
    if [ "$1" = "PUT" ]; then
        curl -s --max-time 15 --unix-socket "$API_SOCK" -X PUT -H "Content-Type: application/json" \
            -d "$3" "http://localhost/api/$2"
    else
        curl -s --max-time 15 --unix-socket "$API_SOCK" "http://localhost/api/$2"
    fi
}

valid_mac() { printf '%s' "$1" | grep -qiE '^([0-9a-f]{2}:){5}[0-9a-f]{2}$'; }

# Scope from scope.txt -> TSV "type<TAB>value" on stdout. Bad lines are reported and skipped.
scope_from_file() {
    local type value
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in ''|'#'*) continue ;; esac
        type="${line%% *}"
        value="${line#* }"
        [ "$value" = "$line" ] && { LOG "scope.txt: skipped (no value): $line" >&2; continue; }
        case "$type" in
            ssid) printf 'ssid\t%s\n' "$value" ;;
            bssid|client)
                value="$(printf '%s' "$value" | tr 'A-F' 'a-f' | tr -d ' ')"
                if valid_mac "$value"; then printf '%s\t%s\n' "$type" "$value"; else LOG "scope.txt: bad MAC: $line" >&2; fi
                ;;
            *) LOG "scope.txt: unknown type: $line" >&2 ;;
        esac
    done < "$SCOPE_TXT"
}

# Scope picked from APs PineAP recon sees -> TSV on stdout (bssid + ssid per pick).
scope_from_recon() {
    local page=0 pages=1 doc aps="/tmp/eng_aps.$$" pick
    : > "$aps"
    while [ "$page" -lt "$pages" ] && [ "$page" -lt 200 ]; do
        doc="$(api GET "recon/wifi/devices?page=$page")" || break
        pages="$(printf '%s' "$doc" | jq -r '.pages // 0' 2>/dev/null)"
        case "$pages" in ''|*[!0-9]*) break ;; esac
        printf '%s' "$doc" | jq -r '.devices[]? | select(.type == "ap") | .mac as $m | .beacons[]?
            | select((.hidden | not) and (.ssid // "") != "")
            | [($m | ascii_downcase), .ssid, (.channel // "")] | @tsv' >> "$aps" 2>/dev/null
        page=$((page + 1))
    done
    # Drop the Pager's own interfaces, de-duplicate. (BusyBox sort -o onto its own input is not safe.)
    cat /sys/class/net/*/address 2>/dev/null | tr 'A-F' 'a-f' | sort -u > "$aps.own"
    awk -F'\t' 'FILENAME == ARGV[1] { own[$1] = 1; next } !($1 in own)' "$aps.own" "$aps" | sort -u > "$aps.sorted"
    mv "$aps.sorted" "$aps"
    rm -f "$aps.own"
    if [ ! -s "$aps" ]; then
        rm -f "$aps"
        return 1
    fi
    local opts=() n=0
    while IFS=$'\t' read -r mac ssid ch; do
        n=$((n + 1))
        opts+=("$n) $ssid  $mac ch$ch")
    done < "$aps"
    local chosen=""
    while true; do
        pick=$(LIST_PICKER "Add in-scope AP (pick Done when finished)" "Done" "${opts[@]}" "Done") || break
        [ "$pick" = "Done" ] && break
        n="${pick%%)*}"
        case "$n" in ''|*[!0-9]*) continue ;; esac
        case " $chosen " in *" $n "*) continue ;; esac
        chosen="$chosen $n"
        sed -n "${n}p" "$aps" | awk -F'\t' '{ print "bssid\t" $1; print "ssid\t" $2 }'
    done
    rm -f "$aps"
    return 0
}

# Set PineAP filters to the scope. Saves the old config first; returns non-zero (and restores) on any failure.
enforce_scope() {
    local dir="$1" ssids macs new got
    api GET pineap/ssidfilter/get_config > "$dir/ssidfilter.before.json" || return 1
    api GET pineap/macfilter/get_config > "$dir/macfilter.before.json" || return 1
    jq -e . "$dir/ssidfilter.before.json" >/dev/null 2>&1 || return 1
    jq -e . "$dir/macfilter.before.json" >/dev/null 2>&1 || return 1

    ssids="$(awk -F'\t' '$1 == "ssid" { print $2 }' "$dir/scope.tsv" | sort -u | jq -R . | jq -s .)"
    macs="$(awk -F'\t' '$1 == "client" { print $2 }' "$dir/scope.tsv" | sort -u | jq -R . | jq -s .)"

    if [ "$(printf '%s' "$ssids" | jq length)" -gt 0 ]; then
        new="$(jq -c --argjson a "$ssids" '.mode = "allow" | .allowed_ssids = $a' "$dir/ssidfilter.before.json")"
        api PUT pineap/ssidfilter/set_config "$new" > /dev/null
        got="$(api GET pineap/ssidfilter/get_config | jq -c '[.mode, (.allowed_ssids // [] | sort)]')"
        [ "$got" = "$(printf '%s' "$new" | jq -c '[.mode, (.allowed_ssids // [] | sort)]')" ] || { restore_filters "$dir"; return 1; }
        echo "ssidfilter" >> "$dir/enforced"
    fi
    if [ "$(printf '%s' "$macs" | jq length)" -gt 0 ]; then
        new="$(jq -c --argjson a "$macs" '.mode = "allow" | .allowed_macs = $a' "$dir/macfilter.before.json")"
        api PUT pineap/macfilter/set_config "$new" > /dev/null
        got="$(api GET pineap/macfilter/get_config | jq -c '[.mode, (.allowed_macs // [] | sort)]')"
        [ "$got" = "$(printf '%s' "$new" | jq -c '[.mode, (.allowed_macs // [] | sort)]')" ] || { restore_filters "$dir"; return 1; }
        echo "macfilter" >> "$dir/enforced"
    fi
    return 0
}

# Put back the saved filter configs and verify them. Returns non-zero if any could not be verified.
restore_filters() {
    local dir="$1" f rc=0
    [ -f "$dir/enforced" ] || return 0
    while IFS= read -r f; do
        case "$f" in ssidfilter|macfilter) ;; *) continue ;; esac
        api PUT "pineap/$f/set_config" "$(jq -c . "$dir/$f.before.json")" > /dev/null
        if [ "$(api GET "pineap/$f/get_config" | jq -cS .)" = "$(jq -cS . "$dir/$f.before.json")" ]; then
            LOG "Restored PineAP $f to its pre-engagement config."
        else
            LOG "FAILED to restore PineAP $f; saved copy: $dir/$f.before.json"
            rc=1
        fi
    done < <(sort -u "$dir/enforced")
    [ "$rc" -eq 0 ] && rm -f "$dir/enforced"
    return "$rc"
}

start_engagement() {
    local name id dir resp scope_src n_ssid n_bssid n_client
    name=$(TEXT_PICKER "Engagement name" "") || exit 0
    name="$(printf '%s' "$name" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-40)"
    [ -n "$name" ] || { ERROR_DIALOG "A name is required."; exit 1; }

    resp=$(CONFIRMATION_DIALOG "I have written authorization for this engagement and its scope.")
    confirmed "$resp" || { ALERT "Not started: authorization not confirmed."; exit 0; }

    id="$(date +%Y%m%d_%H%M%S)_$name"
    dir="$BASE/$id"
    mkdir -p "$dir"
    chmod 700 "$dir"

    if [ -s "$SCOPE_TXT" ]; then
        resp=$(CONFIRMATION_DIALOG "Use scope from /root/engagements/scope.txt?")
        if confirmed "$resp"; then
            scope_from_file > "$dir/scope.tsv"
            scope_src="scope.txt"
        fi
    fi
    if [ -z "$scope_src" ]; then
        scope_from_recon > "$dir/scope.tsv" || { rm -rf "$dir"; ERROR_DIALOG "No recon APs to pick from. Is recon running?"; exit 1; }
        scope_src="picked from recon"
    fi
    sort -u "$dir/scope.tsv" > "$dir/scope.tsv.sorted" && mv "$dir/scope.tsv.sorted" "$dir/scope.tsv"
    if [ ! -s "$dir/scope.tsv" ]; then
        rm -rf "$dir"
        ERROR_DIALOG "Scope is empty. Not started."
        exit 1
    fi
    n_ssid=$(grep -c '^ssid' "$dir/scope.tsv")
    n_bssid=$(grep -c '^bssid' "$dir/scope.tsv")
    n_client=$(grep -c '^client' "$dir/scope.tsv")

    : > "$dir/start.marker"
    {
        echo "Engagement: $name"
        echo "ID: $id"
        echo "Started: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "Authorization: operator confirmed written authorization for this engagement and scope."
        echo "Scope source: $scope_src ($n_ssid SSIDs, $n_bssid AP BSSIDs, $n_client client MACs)"
    } > "$dir/engagement.txt"

    # Record the engagement as active BEFORE touching filters, so "End engagement" can always restore them.
    printf 'ID=%s\nDIR=%s\nSTART=%s\n' "$id" "$dir" "$(date +%s)" > "$ACTIVE"
    chmod 600 "$ACTIVE"
    logger -t engagement "START $id"

    resp=$(CONFIRMATION_DIALOG "Restrict PineAP to the scope? (SSID filter: $n_ssid SSIDs; client filter: $n_client MACs)")
    if confirmed "$resp"; then
        if [ "$n_ssid" -eq 0 ] && [ "$n_client" -eq 0 ]; then
            echo "PineAP enforcement: requested, but the scope has no SSIDs or client MACs to filter on" >> "$dir/engagement.txt"
        elif enforce_scope "$dir"; then
            echo "PineAP enforcement: on ($(tr '\n' ' ' < "$dir/enforced"))" >> "$dir/engagement.txt"
        else
            echo "PineAP enforcement: FAILED, filters left as before" >> "$dir/engagement.txt"
            ERROR_DIALOG "Could not set PineAP filters; they were left as before. Engagement continues without enforcement."
        fi
    else
        echo "PineAP enforcement: off" >> "$dir/engagement.txt"
    fi
    ALERT "Engagement $name started. Scope: $n_ssid SSIDs, $n_bssid BSSIDs, $n_client clients."
}

end_engagement() {
    local id dir resp report section
    id="$(active_get ID)"
    dir="$(active_get DIR)"
    [ -n "$id" ] && [ -d "$dir" ] || { ERROR_DIALOG "Active engagement record is damaged: $ACTIVE"; exit 1; }
    resp=$(CONFIRMATION_DIALOG "End engagement $id and build the report?")
    confirmed "$resp" || exit 0

    if ! restore_filters "$dir"; then
        ERROR_DIALOG "PineAP filters could not be restored. Engagement left ACTIVE; saved configs are in $dir"
        exit 1
    fi
    logger -t engagement "END $id"
    sleep 2

    report="$dir/report.txt"
    section="$dir/log_section.txt"
    # Older rotated log first, then the current one; keep only START..END for this engagement.
    cat "$LOG_FILE".old "$LOG_FILE" 2>/dev/null | awk -v s="engagement: START $id" -v e="engagement: END $id" '
        index($0, s) { on = 1 } on { print } index($0, e) { on = 0 }' > "$section"
    {
        cat "$dir/engagement.txt"
        echo "Ended: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo
        echo "== Scope"
        cat "$dir/scope.tsv"
        echo
        if ! grep -q "engagement: START $id" "$section"; then
            echo "== Activity log: START marker not found in $LOG_FILE (log rotated out, or persistent logging off)."
        else
            echo "== Payloads run"
            grep -E '\[PAYLOAD\]' "$section" || echo "(none)"
            echo
            echo "== Alerts and errors"
            grep -iE 'ALERTS PAYLOAD|\[CRITICAL\]|Deauth Flood|Handshake' "$section" | grep -v '\[PAYLOAD\]' || echo "(none)"
        fi
        echo
        echo "== Loot created during the engagement"
        find /root/loot -type f -newer "$dir/start.marker" 2>/dev/null | while IFS= read -r f; do
            printf '%s  %s bytes  sha256 %s\n' "$f" "$(wc -c < "$f")" "$(sha256sum "$f" | cut -d' ' -f1)"
        done
        echo
        echo "== Recon findings"
        echo "For the recon-data report (APs, clients, handshakes, encryption, WiGLE), run the"
        echo "Engagement Report Generator payload (user/reconnaissance/recondb_reporting)."
        echo
        echo "== Full system log for the engagement window: $section"
    } > "$report"
    chmod 600 "$report" "$section"
    rm -f "$ACTIVE"
    ALERT "Engagement ended. Activity report: $report. For recon findings run Engagement Report Generator."
}

status() {
    local dir
    dir="$(active_get DIR)"
    PROMPT "Active: $(active_get ID)
Since: $(date -d "@$(active_get START)" '+%Y-%m-%d %H:%M' 2>/dev/null)
Scope: $(grep -c '^ssid' "$dir/scope.tsv") SSIDs, $(grep -c '^bssid' "$dir/scope.tsv") BSSIDs, $(grep -c '^client' "$dir/scope.tsv") clients
Enforcement: $(sed -n 's/^PineAP enforcement: //p' "$dir/engagement.txt")"
}

if [ -f "$ACTIVE" ]; then
    choice=$(LIST_PICKER "Engagement: $(active_get ID)" "Status" "End engagement" "Exit" "Status") || exit 0
    case "$choice" in
        "Status") status ;;
        "End engagement") end_engagement ;;
        *) exit 0 ;;
    esac
else
    choice=$(LIST_PICKER "Engagement Manager (inactive)" "Start engagement" "Exit" "Start engagement") || exit 0
    [ "$choice" = "Start engagement" ] && start_engagement
fi
