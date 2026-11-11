#!/bin/bash
# Title: Deauth Recorder
# Author: h4d35x0
# Description: Records every deauth/disassoc flood alert (AP, client, claimed source, destination) to /root/loot/deauth/events.tsv for the Deauth Report payload. Silent.
# Version: 1.0
# Category: alerts
#
# One TSV line per alert in events.tsv (older lines in events.1.tsv): epoch, local time, ap, client, source, destination, firmware message.
# MACs are as the firmware reported them. Deauth/disassoc frames are unauthenticated unless both ends use
# 802.11w (PMF), so "source" is whatever the frame claimed; it is usually spoofed to the AP or the client and
# does not identify the attacker. The record says who was targeted, when and how often.
# Client MACs are personal data: the file lives under /root/loot so Loot Vault encrypts it with the rest.

DIR="${DEAUTH_DIR:-/root/loot/deauth}"
EVENTS="$DIR/events.tsv"
LOCK="$DIR/.lock"
# Up to 2 x MAX_LINES events are kept: events.tsv plus one rotated generation, events.1.tsv.
MAX_LINES="${DEAUTH_MAX_LINES:-10000}"

# One field: lowercase MACs, no tabs or newlines.
field() { printf '%s' "$1" | tr '\t\r\n' '   '; }
mac() { field "$1" | tr 'A-F' 'a-f'; }

# Nothing to record outside a deauth alert (for example a manual launch).
[ -n "$_ALERT_DENIAL_AP_MAC_ADDRESS$_ALERT_DENIAL_CLIENT_MAC_ADDRESS$_ALERT_DENIAL_SOURCE_MAC_ADDRESS$_ALERT_DENIAL_DESTINATION_MAC_ADDRESS$_ALERT_DENIAL_MESSAGE" ] || exit 0

umask 077
mkdir -p "$DIR" && chmod 700 "$DIR" || exit 0

line="$(date +%s)	$(date '+%Y-%m-%d %H:%M:%S')	$(mac "$_ALERT_DENIAL_AP_MAC_ADDRESS")	$(mac "$_ALERT_DENIAL_CLIENT_MAC_ADDRESS")	$(mac "$_ALERT_DENIAL_SOURCE_MAC_ADDRESS")	$(mac "$_ALERT_DENIAL_DESTINATION_MAC_ADDRESS")	$(field "$_ALERT_DENIAL_MESSAGE" | cut -c1-512)"

# Appends need no lock: one short line written with O_APPEND (well under PIPE_BUF) lands whole, so alerts that
# fire together never lose or interleave lines.
printf '%s\n' "$line" >> "$EVENTS"

# Rotation renames the full file to events.1.tsv (the previous generation is replaced), so nothing is rewritten
# and an append racing the rename still lands in one of the two files. mkdir is atomic: only one alert rotates;
# if the lock is busy another alert is already rotating, so skip. A lock older than a minute is left over
# from a killed rotation and is removed so rotation cannot stop for good.
if [ -d "$LOCK" ] && [ $(( $(date +%s) - $(date -r "$LOCK" +%s 2>/dev/null || date +%s) )) -gt 60 ]; then
    rmdir "$LOCK" 2>/dev/null
fi
lines() { wc -l 2>/dev/null < "$EVENTS" || echo 0; }
if [ "$(lines)" -ge "$MAX_LINES" ] && mkdir "$LOCK" 2>/dev/null; then
    if [ "$(lines)" -ge "$MAX_LINES" ]; then
        mv "$EVENTS" "$DIR/events.1.tsv"
    fi
    rmdir "$LOCK"
fi
exit 0
