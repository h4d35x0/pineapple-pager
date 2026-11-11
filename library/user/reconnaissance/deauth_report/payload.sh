#!/bin/bash
# Title: Deauth Report
# Author: h4d35x0
# Description: Sums up the deauth/disassoc floods recorded by the Deauth Recorder alert: which APs and clients were targeted, when and how often. Passive.
# Version: 1.0
# Category: reconnaissance
#
# Reads /root/loot/deauth/events.tsv (and the rotated events.1.tsv), written by alerts/deauth_flood_detected/deauth_recorder (install both).
# Per targeted AP: events, first/last seen, distinct clients, broadcast floods, which side the frames claimed
# to come from, the 3 most targeted clients, and the SSID if PineAP recon currently sees that BSSID.
# Flags the Pager's own interfaces, and marks in/out of scope when an Engagement Manager engagement is active.
#
# Limits: deauth/disassoc frames are unauthenticated unless both ends use 802.11w (PMF), so the claimed source
# is usually spoofed and does not identify the attacker. This reports targets and timing, not attribution of
# a person or device. Context: R. Anderson, Security Engineering 3rd ed., s21.5.2.1 "WiFi". The reference
# library has no 802.11 title, so the reading of these fields is general knowledge, not book-sourced.

DIR="${DEAUTH_DIR:-/root/loot/deauth}"
EVENTS="$DIR/events.tsv"
OLDER="$DIR/events.1.tsv"
LOCK="$DIR/.lock"
API_SOCK="${API_SOCK:-/tmp/api.sock}"
SG="${SCOPE_GUARD:-/root/payloads/user/general/engagement_manager/scope_guard.sh}"
umask 077
TS="$(date +%Y%m%d_%H%M%S)"
SSIDS="/tmp/deauth_report_ssids.$$"
OWN="/tmp/deauth_report_own.$$"
SCOPE="/tmp/deauth_report_scope.$$"
ROWS="/tmp/deauth_report_rows.$$"

cleanup() { rm -f "$SSIDS" "$OWN" "$SCOPE" "$ROWS"; }
trap cleanup EXIT

# BSSID -> SSID from PineAP recon (best effort; empty if recon is not running).
recon_ssids() {
    local page=0 pages=1 doc
    : > "$SSIDS"
    while [ "$page" -lt "$pages" ] && [ "$page" -lt 200 ]; do
        doc="$(curl -s --max-time 15 --unix-socket "$API_SOCK" "http://localhost/api/recon/wifi/devices?page=$page")" || return 0
        pages="$(printf '%s' "$doc" | jq -r '.pages // empty' 2>/dev/null)"
        case "$pages" in ''|*[!0-9]*) return 0 ;; esac
        printf '%s\n' "$doc" | jq -r '.devices[]? | select(.type == "ap") | .mac as $m | .beacons[]?
            | select((.hidden | not) and (.ssid // "") != "") | [($m | ascii_downcase), .ssid] | @tsv' \
            >> "$SSIDS" 2>/dev/null
        page=$((page + 1))
    done
}

# Per-AP scope verdicts when an engagement is active: "ap<TAB>in|out|unknown|unreadable".
scope_marks() {
    : > "$SCOPE"
    [ -f "$SG" ] || return 0
    # shellcheck disable=SC1090
    . "$SG"
    type scope_check >/dev/null 2>&1 || return 0
    [ -f "$SCOPE_GUARD_ACTIVE" ] || return 0
    local ap verdict s dir
    dir="$(sed -n 's/^DIR=//p' "$SCOPE_GUARD_ACTIVE" | head -n 1)"
    if [ -z "$dir" ] || [ ! -r "$dir/scope.tsv" ]; then
        cut -f3 "$1" | sort -u | awk 'NF { print $0 "\tunreadable" }' > "$SCOPE"
        return 0
    fi
    cut -f3 "$1" | sort -u | while IFS= read -r ap; do
        [ -n "$ap" ] || continue
        if scope_check "$ap"; then
            verdict=in
        elif ! grep -q "^$ap	" "$SSIDS"; then
            # Not listed by BSSID, and recon does not see it now, so an SSID entry cannot be ruled out.
            verdict=unknown
        else
            # Scope may name the network by SSID; use what recon currently reports for this BSSID.
            verdict=out
            while IFS= read -r s; do
                if scope_check "$s"; then verdict=in; break; fi
            done < <(awk -F'\t' -v m="$ap" '$1 == m { print $2 }' "$SSIDS")
        fi
        printf '%s\t%s\n' "$ap" "$verdict"
    done > "$SCOPE"
}

# Print the report body for events at or after epoch $1.
summarise() {
    local since="$1"
    cat "$OLDER" "$EVENTS" 2>/dev/null | awk -F'\t' -v since="$since" '$1 + 0 >= since' > "$ROWS"
    recon_ssids
    cat /sys/class/net/*/address 2>/dev/null | tr 'A-F' 'a-f' | sort -u > "$OWN"
    scope_marks "$ROWS"
    awk -F'\t' '
        FILENAME == ARGV[1] { if (!($1 in ssid)) ssid[$1] = $2; else if (index("," ssid[$1] ",", "," $2 ",") == 0) ssid[$1] = ssid[$1] "," $2; next }
        FILENAME == ARGV[2] { own[$1] = 1; next }
        FILENAME == ARGV[3] { scope[$1] = $2; next }
        {
            BC = "ff:ff:ff:ff:ff:ff"
            # The firmware reports a broadcast flood from both directions: "broadcast flood on X"
            # (ap=X, client=BC) and "flood on network BC to X" (ap=BC, client=X). The real target is the
            # non-broadcast BSSID in either case.
            apf = $3; clf = $4
            if (apf == BC && clf != "" && clf != BC) { ap = clf; bcastflood = 1 }
            else { ap = (apf == "" ? "unknown" : apf); bcastflood = (clf == BC || $6 == BC) }
            n[ap]++; total++
            if (!(ap in first) || $1 < firstE[ap]) { firstE[ap] = $1; first[ap] = $2 }
            if (!(ap in last) || $1 > lastE[ap]) { lastE[ap] = $1; last[ap] = $2 }
            if (bcastflood) bcast[ap]++
            else if (clf != "" && clf != BC) { if (!((ap, clf) in cl)) { cl[ap, clf] = 0; ncl[ap]++ } cl[ap, clf]++ }
            src = $5
            if (src != "" && src != BC && src == clf) fromcl[ap]++
            else if (src != "" && src == apf) fromap[ap]++
            else other[ap]++
        }
        END {
            for (ap in n) {
                flag = ""
                if (ap in own) flag = flag " [THIS PAGER]"
                if (scope[ap] == "in") flag = flag " [in scope]"
                if (scope[ap] == "out") flag = flag " [OUT OF SCOPE]"
                if (scope[ap] == "unreadable") flag = flag " [ENGAGEMENT SCOPE UNREADABLE]"
                if (scope[ap] == "unknown") flag = flag " [scope unknown: SSID not in recon]"
                top = ""
                for (k = 1; k <= 3; k++) {
                    best = ""; bn = 0
                    for (key in cl) {
                        split(key, kk, SUBSEP)
                        if (kk[1] != ap || (kk[2] in used)) continue
                        if (cl[key] > bn) { bn = cl[key]; best = kk[2] }
                    }
                    if (best == "") break
                    used[best] = 1
                    top = top (top == "" ? "" : ", ") best " x" bn
                }
                split("", used)
                printf "%d\tAP %s (%s)%s\n", n[ap], ap, (ap in ssid ? ssid[ap] : "SSID not in recon"), flag
                printf "%d\t  events %d, first %s, last %s\n", n[ap], n[ap], first[ap], last[ap]
                printf "%d\t  clients %d, broadcast floods %d; claimed source: AP %d, client %d, other %d\n", \
                    n[ap], ncl[ap] + 0, bcast[ap] + 0, fromap[ap] + 0, fromcl[ap] + 0, other[ap] + 0
                if (top != "") printf "%d\t  most targeted: %s\n", n[ap], top
            }
        }' "$SSIDS" "$OWN" "$SCOPE" "$ROWS" | sort -t"$(printf '\t')" -k1,1 -n -r -s | cut -f2-
}

report() {
    local since="$1" label="$2" out events aps own_hits
    if [ ! -s "$EVENTS" ] && [ ! -s "$OLDER" ]; then
        ALERT "No deauth floods recorded yet. Is the Deauth Recorder alert installed?"
        exit 0
    fi
    out="$DIR/report_$TS.txt"
    {
        echo "Deauth Report $TS ($label)"
        echo "Claimed source is usually spoofed; this shows targets and timing, not the attacker."
        echo
        summarise "$since"
    } > "$out"
    chmod 600 "$out"
    events=$(wc -l < "$ROWS")
    aps=$(grep -c '^AP ' "$out")
    own_hits=$(grep -c '^AP .*\[THIS PAGER\]' "$out")
    grep -E '^(AP |  )' "$out" | while IFS= read -r line; do LOG "$line"; done
    if [ "$events" -eq 0 ]; then
        ALERT "No deauth floods in $label."
    elif [ "$own_hits" -gt 0 ]; then
        ALERT "Deauth ($label): $events events, $aps APs, INCLUDING THIS PAGER. Details in payload log and $out"
    else
        ALERT "Deauth ($label): $events events against $aps APs. Details in payload log and $out"
    fi
}

clear_history() {
    local resp
    local n
    n=$(cat "$OLDER" "$EVENTS" 2>/dev/null | wc -l)
    [ "$n" -gt 0 ] || { ALERT "No history to clear."; exit 0; }
    resp=$(CONFIRMATION_DIALOG "Delete all $n recorded deauth events? Reports already written are kept.")
    [ "$resp" = "${DUCKYSCRIPT_USER_CONFIRMED:-1}" ] || exit 0
    if ! mkdir "$LOCK" 2>/dev/null; then
        ERROR_DIALOG "The recorder is rotating its file right now. Try again in a moment."
        exit 1
    fi
    rm -f "$EVENTS" "$OLDER"
    rmdir "$LOCK"
    ALERT "Deauth history cleared."
}

now=$(date +%s)
choice=$(LIST_PICKER "Deauth Report" "Last 24 hours" "Last 7 days" "All recorded" "Clear history" "Exit" "Last 24 hours") || exit 0
case "$choice" in
    "Last 24 hours") report $((now - 86400)) "last 24 hours" ;;
    "Last 7 days") report $((now - 604800)) "last 7 days" ;;
    "All recorded") report 0 "all recorded" ;;
    "Clear history") clear_history ;;
    *) exit 0 ;;
esac
