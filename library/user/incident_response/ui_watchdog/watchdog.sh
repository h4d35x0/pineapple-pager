#!/bin/bash
# watchdog.sh: UI watchdog loop, part of UI Watchdog (h4d35x0). Run by /etc/init.d/ui_watchdog (procd).
#
#   watchdog.sh          loop forever, one check every INTERVAL seconds
#   watchdog.sh --once   one check now; saves diagnostics if it fails; prints the result
#
# A check passes when the UI process (pineapple) is running AND the local API it serves (/tmp/api.sock)
# answers within API_TIMEOUT seconds. After FAILS_NEEDED failed checks in a row it saves one diagnostics
# bundle per incident to /root/logs/ui_watchdog/ and, only if AUTO_RESTART=1 in the config, restarts the UI
# (at most once per RESTART_GAP seconds). A changed UI PID and a new firmware crash log are logged too.
#
# Limit: a UI that still answers its API but has stopped drawing the screen is NOT detected. The framebuffer
# is not a usable signal: it legitimately stops changing while the screen is idle or dimmed.

CONF="${UI_WATCHDOG_CONF:-/root/ui_watchdog.conf}"
OUT="${UI_WATCHDOG_DIR:-/root/logs/ui_watchdog}"
API_SOCK="${API_SOCK:-/tmp/api.sock}"
CRASH_LOG="${UI_CRASH_LOG:-/root/pineapple-crash.log}"
PROC="${UI_PROC:-pineapple}"
INTERVAL="${UI_WATCHDOG_INTERVAL:-60}"
API_TIMEOUT=10
FAILS_NEEDED=3
BOOT_GRACE="${UI_WATCHDOG_BOOT_GRACE:-180}"
RESTART_GAP="${UI_WATCHDOG_RESTART_GAP:-1800}"
KEEP_BUNDLES=20
# The config holds one setting, AUTO_RESTART=0|1 (written by the payload). It is parsed, not sourced.
AUTO_RESTART="$(sed -n 's/^AUTO_RESTART=\([01]\)$/\1/p' "$CONF" 2>/dev/null | tail -n 1)"
[ -n "$AUTO_RESTART" ] || AUTO_RESTART=0

umask 077

say() { logger -t ui_watchdog "$*"; }

# Newest PID of the UI process, empty if none.
ui_pid() { pidof "$PROC" 2>/dev/null | tr ' ' '\n' | sort -n | tail -n 1; }

# One check. Sets REASON (empty when healthy) and API_SECS.
check() {
    local pid
    REASON=""
    API_SECS=""
    pid="$(ui_pid)"
    if [ -z "$pid" ]; then
        REASON="ui_process_missing"
        return 1
    fi
    if ! API_SECS="$(curl -s -o /dev/null -w '%{time_total}' --max-time "$API_TIMEOUT" \
        --unix-socket "$API_SOCK" "http://localhost/api/recon/wifi/status")"; then
        REASON="api_no_answer"
        return 1
    fi
    return 0
}

# BusyBox on the Pager has no stat(1); date -r prints a file mtime.
mtime() { date -r "$1" +%s 2>/dev/null || echo 0; }

# Save one diagnostics bundle; prints its path.
capture() {
    local reason="$1" pid d t
    pid="$(ui_pid)"
    d="$OUT/$(date +%Y%m%d_%H%M%S)_$reason"
    mkdir -p "$d" || return 1
    {
        echo "reason: $reason"
        echo "date: $(date)"
        echo "uptime: $(cat /proc/uptime)"
        echo "ui pid: ${pid:-none}"
        if [ "$reason" = api_no_answer ]; then echo "api: no answer within $API_TIMEOUT s"; else echo "api: ${API_SECS:-not checked} s"; fi
    } > "$d/summary.txt"
    if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
        cat "/proc/$pid/status" > "$d/ui_status.txt" 2>/dev/null
        cat "/proc/$pid/wchan" > "$d/ui_wchan.txt" 2>/dev/null
        for t in /proc/"$pid"/task/*; do
            printf '%s %s %s\n' "${t##*/}" "$(cut -d' ' -f3 "$t/stat" 2>/dev/null)" "$(cat "$t/wchan" 2>/dev/null)"
        done > "$d/ui_threads.txt" 2>/dev/null
    fi
    ps w > "$d/ps.txt" 2>&1
    top -b -n 1 > "$d/top.txt" 2>&1
    free > "$d/free.txt" 2>&1
    df -h > "$d/df.txt" 2>&1
    logread > "$d/logread.txt" 2>&1
    dmesg > "$d/dmesg.txt" 2>&1
    [ -f /tmp/uierrors.log ] && cp /tmp/uierrors.log "$d/" 2>/dev/null
    [ -f "$CRASH_LOG" ] && tail -n 500 "$CRASH_LOG" > "$d/pineapple-crash.tail.txt" 2>/dev/null
    chmod -R go-rwx "$d" 2>/dev/null
    # Retention: keep the newest KEEP_BUNDLES bundles.
    find "$OUT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort |
        awk -v k="$KEEP_BUNDLES" '{ a[NR] = $0 } END { for (i = 1; i <= NR - k; i++) print a[i] }' |
        while IFS= read -r old; do
            rm -rf "$old"
        done
    printf '%s\n' "$d"
}

restart_ui() {
    local now last
    now="$(date +%s)"
    last="$(cat "$OUT/.last_restart" 2>/dev/null || echo 0)"
    if [ $((now - last)) -lt "$RESTART_GAP" ]; then
        say "auto-restart skipped: last restart $((now - last)) s ago (minimum gap $RESTART_GAP s)"
        return 0
    fi
    echo "$now" > "$OUT/.last_restart"
    say "auto-restart: restarting pineapplepager"
    ${UI_RESTART_CMD:-/etc/init.d/pineapplepager restart} >/dev/null 2>&1
}

if [ "$1" = "--once" ]; then
    mkdir -p "$OUT"
    if check; then
        echo "OK: UI pid $(ui_pid), API answered in ${API_SECS} s"
        exit 0
    fi
    d="$(capture "$REASON")"
    say "check failed ($REASON), diagnostics saved to $d"
    echo "FAILED: $REASON. Diagnostics saved to $d"
    exit 1
fi

mkdir -p "$OUT"
say "started (interval ${INTERVAL}s, $FAILS_NEEDED failures to act, auto-restart $AUTO_RESTART)"

# Boot grace: the UI and its API take a while to come up after power-on.
up="$(cut -d. -f1 /proc/uptime)"
[ "$up" -lt "$BOOT_GRACE" ] && sleep $((BOOT_GRACE - up))

fails=0
captured=0
last_pid="$(ui_pid)"
last_crash="$(mtime "$CRASH_LOG")"
while :; do
    pid="$(ui_pid)"
    if [ -n "$pid" ] && [ -n "$last_pid" ] && [ "$pid" != "$last_pid" ]; then
        say "UI process restarted (pid $last_pid -> $pid)"
    fi
    [ -n "$pid" ] && last_pid="$pid"

    crash="$(mtime "$CRASH_LOG")"
    if [ "$crash" != "$last_crash" ] && [ "$crash" != 0 ]; then
        say "firmware crash log changed, diagnostics saved to $(capture ui_crash_log)"
    fi
    last_crash="$crash"

    if check; then
        [ "$fails" -ge "$FAILS_NEEDED" ] && say "recovered after $fails failed checks"
        fails=0
        captured=0
    else
        fails=$((fails + 1))
        if [ "$fails" -ge "$FAILS_NEEDED" ] && [ "$captured" -eq 0 ]; then
            captured=1
            say "UI unhealthy ($REASON, $fails checks in a row), diagnostics saved to $(capture "$REASON")"
            [ "$AUTO_RESTART" = 1 ] && restart_ui
        fi
    fi
    sleep "$INTERVAL"
done
