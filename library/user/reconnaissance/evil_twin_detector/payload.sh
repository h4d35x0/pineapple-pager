#!/bin/bash
# Title: Evil Twin Detector
# Author: h4d35x0
# Description: Passive check for evil twins and karma-style rogue APs using the access points PineAP recon already sees. Sends nothing.
# Version: 1.0
# Category: reconnaissance
#
# How it works: reads the recon data PineAP has already collected (local API, recon/wifi/devices), so it adds no
# scanning and no transmissions. Requires recon to be running. The Pager's own interfaces are ignored.
#
# Findings:
#   HIGH  one SSID broadcast both open/WEP and with WPA         (downgrade twin: a lure next to the real network)
#   HIGH  one BSSID answering probes for >= KARMA_MIN SSIDs     (karma responder, i.e. another PineAP-style device)
#   HIGH  a trusted SSID now seen with weaker encryption than its baseline
#   MED   a trusted SSID seen from a BSSID not in the baseline (new AP or a twin; check where it is)
#   LOW   one SSID seen with different WPA generations         (often just mixed hardware on one network)
# The baseline is optional: "Learn baseline" trusts what is in range now, so only learn it somewhere you trust.
#
# Sources: context from R. Anderson, Security Engineering 3rd ed., s21.5.2.1 "WiFi" (WiFi at the network edge
# stays fragile). The reference library has no 802.11 title, so the specific heuristics above are general
# knowledge, not book-sourced.
#
# Complements find_hackers (user/reconnaissance), which flags evil twins by manufacturer (OUI) odd-one-out
# plus a Bluetooth sweep. This payload covers the signals it does not: encryption downgrade, karma response
# count, and baseline drift (including a same-vendor twin an OUI check misses). Run both for fuller coverage.

DIR="${EVIL_TWIN_DIR:-/root/loot/evil_twin}"
BASELINE="$DIR/baseline.tsv"
API_SOCK="${API_SOCK:-/tmp/api.sock}"
KARMA_MIN="${KARMA_MIN:-5}"
TS="$(date +%Y%m%d_%H%M%S)"
RAW="/tmp/evil_twin_raw.$$"
APS="/tmp/evil_twin_aps.$$"
RESP="/tmp/evil_twin_resp.$$"
OWN="/tmp/evil_twin_own.$$"

cleanup() { rm -f "$RAW" "$APS" "$RESP" "$OWN"; }
trap cleanup EXIT

mkdir -p "$DIR"

# Fetch every page of recon devices into $RAW (one JSON document per line).
fetch_devices() {
    local page=0 pages=1 doc
    : > "$RAW"
    while [ "$page" -lt "$pages" ] && [ "$page" -lt 200 ]; do
        doc="$(curl -s --max-time 15 --unix-socket "$API_SOCK" "http://localhost/api/recon/wifi/devices?page=$page")" || return 1
        pages="$(printf '%s' "$doc" | jq -r '.pages // empty' 2>/dev/null)"
        case "$pages" in
            ''|*[!0-9]*) return 1 ;;
        esac
        printf '%s\n' "$doc" | jq -c '.' >> "$RAW" 2>/dev/null || return 1
        page=$((page + 1))
    done
    return 0
}

# APs as TSV: bssid, ssid, encryption, channel, signal (visible SSIDs only).
# Probe responses as TSV: bssid, number of distinct SSIDs it answered for.
extract() {
    jq -r '.devices[]? | select(.type == "ap") | .mac as $m | .beacons[]?
           | select((.hidden | not) and (.ssid // "") != "")
           | [($m | ascii_downcase), .ssid, (.encryption_str // ""), (.channel // ""), (.signal // "")] | @tsv' \
        "$RAW" > "$APS"
    jq -r '.devices[]? | select(.type == "ap")
           | [(.mac | ascii_downcase), ([.responses[]?.ssid | select(. != null and . != "")] | unique | length)] | @tsv' \
        "$RAW" > "$RESP"
    cat /sys/class/net/*/address 2>/dev/null | tr 'A-F' 'a-f' | sort -u > "$OWN"
}

# Analyse $APS/$RESP against the optional baseline; print findings as "LEVEL<TAB>text".
analyse() {
    awk -F'\t' -v karma_min="$KARMA_MIN" -v base="$BASELINE" '
        function rank(e,   u) {
            u = toupper(e)
            if (u == "" || u == "OPEN" || u == "NONE") return 0
            if (u ~ /^WEP/) return 1
            if (u == "WPA") return 2
            if (u == "WPA/WPA2") return 3
            if (u == "WPA2") return 4
            if (u == "WPA2/WPA3") return 5
            if (u ~ /^WPA3/) return 6
            return 3
        }
        function label(e) { return (e == "" ? "OPEN" : e) }
        FILENAME == ARGV[1] { own[$1] = 1; next }
        FILENAME == ARGV[2] {
            if (($1 in own)) next
            if ($2 + 0 >= karma_min) print "HIGH\tBSSID " $1 " answered probes for " $2 " different SSIDs (karma responder / PineAP-style device)"
            next
        }
        FILENAME == ARGV[3] {
            if (($1 in own)) next
            key = $1 SUBSEP $2
            if (key in seen) next
            seen[key] = 1
            ssid = $2; e = label($3); r = rank($3)
            n[ssid]++
            encs[ssid] = (ssid in encs ? encs[ssid] : "")
            if (index("|" encs[ssid] "|", "|" e "|") == 0) encs[ssid] = encs[ssid] (encs[ssid] == "" ? "" : "|") e
            if (!(ssid in minr) || r < minr[ssid]) minr[ssid] = r
            if (!(ssid in maxr) || r > maxr[ssid]) maxr[ssid] = r
            detail[ssid] = detail[ssid] " " $1 "(" e ",ch" $4 "," $5 "dBm)"
            bss[ssid, $1] = r
            next
        }
        END {
            while ((getline line < base) > 0) {
                split(line, f, "\t")
                if (f[1] == "") continue
                trusted[f[1]] = 1
                tb[f[1], f[2]] = 1
                if (!(f[1] in tmin) || rank(f[3]) < tmin[f[1]]) tmin[f[1]] = rank(f[3])
            }
            for (s in n) {
                if (minr[s] <= 1 && maxr[s] >= 2)
                    print "HIGH\tSSID \"" s "\" is broadcast both open/WEP and with WPA:" detail[s]
                else if (maxr[s] != minr[s])
                    print "LOW\tSSID \"" s "\" seen with different WPA generations (" encs[s] "):" detail[s]
                if (s in trusted) {
                    if (minr[s] < tmin[s])
                        print "HIGH\tTrusted SSID \"" s "\" now seen with weaker encryption than its baseline:" detail[s]
                    for (k in bss) {
                        split(k, kk, SUBSEP)
                        if (kk[1] == s && !((s, kk[2]) in tb))
                            print "MED\tTrusted SSID \"" s "\" from a BSSID not in the baseline: " kk[2]
                    }
                }
            }
        }' "$OWN" "$RESP" "$APS" | awk -F'\t' '
            { o = ($1 == "HIGH" ? 1 : ($1 == "MED" ? 2 : 3)); print o "\t" $0 }' | sort -n -s -k1,1 | cut -f2-
}

scan() {
    local sp report high med low aps
    sp=$(START_SPINNER "Reading PineAP recon data...")
    if ! fetch_devices; then
        STOP_SPINNER "$sp"
        ERROR_DIALOG "Could not read recon data. Is recon running?"
        exit 1
    fi
    extract
    STOP_SPINNER "$sp"
    aps="$(awk -F'\t' 'FILENAME == ARGV[1] { own[$1] = 1; next } !($1 in own) { print $1 }' "$OWN" "$APS" | sort -u | wc -l)"
    report="$DIR/report_$TS.txt"
    {
        echo "Evil Twin Detector report $TS"
        echo "APs analysed: $aps  (baseline: $( [ -s "$BASELINE" ] && echo "$(cut -f1 "$BASELINE" | sort -u | wc -l) trusted SSIDs" || echo none))"
        echo
        analyse
    } > "$report"
    cp "$report" "$DIR/latest.txt"
    high=$(grep -c '^HIGH' "$report")
    med=$(grep -c '^MED' "$report")
    low=$(grep -c '^LOW' "$report")
    grep -E '^(HIGH|MED|LOW)' "$report" | while IFS= read -r line; do LOG "$line"; done
    if [ "$((high + med + low))" -eq 0 ]; then
        ALERT "No evil-twin indicators among $aps APs."
    else
        ALERT "Evil twin check: $high HIGH, $med MED, $low LOW. Details in payload log and $report"
    fi
}

learn_baseline() {
    local sp count resp
    sp=$(START_SPINNER "Reading PineAP recon data...")
    if ! fetch_devices; then
        STOP_SPINNER "$sp"
        ERROR_DIALOG "Could not read recon data. Is recon running?"
        exit 1
    fi
    extract
    STOP_SPINNER "$sp"
    awk -F'\t' 'FILENAME == ARGV[1] { own[$1] = 1; next } !($1 in own) { print $2 "\t" $1 "\t" $3 }' \
        "$OWN" "$APS" | sort -u > "$BASELINE.new"
    count="$(cut -f1 "$BASELINE.new" | sort -u | wc -l)"
    resp=$(CONFIRMATION_DIALOG "Trust all $count SSIDs in range now as the baseline? Only do this somewhere you trust.")
    if [ "$resp" != "${DUCKYSCRIPT_USER_CONFIRMED:-1}" ]; then
        rm -f "$BASELINE.new"
        exit 0
    fi
    mv "$BASELINE.new" "$BASELINE"
    ALERT "Baseline saved: $count SSIDs, $(wc -l < "$BASELINE") BSSIDs."
}

choice=$(LIST_PICKER "Evil Twin Detector" "Scan now" "Learn baseline (trust current)" "Clear baseline" "Exit" "Scan now") || exit 0
case "$choice" in
    "Scan now") scan ;;
    "Learn baseline (trust current)") learn_baseline ;;
    "Clear baseline")
        resp=$(CONFIRMATION_DIALOG "Delete the trusted baseline?")
        if [ "$resp" = "${DUCKYSCRIPT_USER_CONFIRMED:-1}" ]; then
            rm -f "$BASELINE"
            ALERT "Baseline cleared."
        fi
        ;;
    *) exit 0 ;;
esac
