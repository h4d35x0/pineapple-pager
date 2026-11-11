#!/bin/bash
# Title: UI Watchdog
# Author: h4d35x0
# Description: Optional background check that the Pager UI is alive. If it stops answering, saves diagnostics to /root/logs/ui_watchdog before anyone has to power-cycle. Off until enabled here.
# Version: 1.0
# Category: incident_response
#
# Enable installs a procd service (/etc/init.d/ui_watchdog) that runs watchdog.sh from this folder, so it keeps
# running after this payload exits and starts again at boot. Disable stops and removes the service; saved
# diagnostics are kept. Nothing runs until you enable it.
#
# Every 60 s it checks that the UI process is running and that its local API answers within 10 s. After 3
# failed checks in a row (about 3 minutes) it saves one bundle: logread, dmesg, ps, top, memory, disk, the UI
# process and thread states, /tmp/uierrors.log and the firmware crash log. "Enable + auto-restart" also
# restarts the UI after saving, at most once per 30 minutes. A changed UI PID or a new crash log is logged.
#
# Limit: a UI that still answers its API but has stopped drawing the screen is not detected; see watchdog.sh.
# Why: on 2026-11-09 the screen went black, the Pager had to be forced off and the RAM-only log was lost.
# The persistent system log (/root/logs/system.log) now keeps the log; this keeps the process state too.

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WATCHDOG="$SELF_DIR/watchdog.sh"
INIT="${UI_WATCHDOG_INIT:-/etc/init.d/ui_watchdog}"
CONF="${UI_WATCHDOG_CONF:-/root/ui_watchdog.conf}"
OUT="${UI_WATCHDOG_DIR:-/root/logs/ui_watchdog}"

confirmed() { [ "$1" = "${DUCKYSCRIPT_USER_CONFIRMED:-1}" ]; }

installed() { [ -f "$INIT" ]; }
# procd's view of the service; a pgrep on the path would also match any shell whose command line names it.
running() {
    ubus call service list '{"name":"ui_watchdog"}' 2>/dev/null |
        jq -e '.ui_watchdog.instances // {} | to_entries | any(.value.running == true)' >/dev/null 2>&1
}
# Any leftover loop process, matched on its exact arguments.
loop_alive() { ps w | awk -v w="$WATCHDOG" '$0 ~ /bash/ && $NF == w { f = 1 } END { exit !f }'; }

enable() {
    local auto="$1"
    if [ ! -f "$WATCHDOG" ]; then
        ERROR_DIALOG "watchdog.sh is missing from $SELF_DIR"
        exit 1
    fi
    chmod 755 "$WATCHDOG"
    printf 'AUTO_RESTART=%s\n' "$auto" > "$CONF"
    chmod 600 "$CONF"
    cat > "$INIT" <<EOF
#!/bin/sh /etc/rc.common
# UI Watchdog service, installed by the UI Watchdog payload (h4d35x0). Remove with the payload's Disable.
START=99
USE_PROCD=1

start_service() {
    [ -f "$WATCHDOG" ] || return 0
    procd_open_instance
    procd_set_param command /bin/bash "$WATCHDOG"
    procd_set_param respawn
    procd_close_instance
}
EOF
    chmod 755 "$INIT"
    "$INIT" enable
    "$INIT" start
    sleep 2
    if running; then
        if [ "$auto" = 1 ]; then
            ALERT "UI Watchdog enabled with auto-restart. Diagnostics go to $OUT"
        else
            ALERT "UI Watchdog enabled (diagnostics only). Diagnostics go to $OUT"
        fi
    else
        ERROR_DIALOG "UI Watchdog service did not start. See logread for ui_watchdog."
        exit 1
    fi
}

disable() {
    local resp i
    resp=$(CONFIRMATION_DIALOG "Stop and remove the UI Watchdog service? Saved diagnostics are kept.")
    confirmed "$resp" || exit 0
    "$INIT" stop >/dev/null 2>&1
    "$INIT" disable >/dev/null 2>&1
    rm -f "$INIT" "$CONF"
    i=0
    while { running || loop_alive; } && [ "$i" -lt 5 ]; do sleep 1; i=$((i + 1)); done
    if running || loop_alive; then
        ERROR_DIALOG "Service removed but a watchdog process is still running."
        exit 1
    fi
    ALERT "UI Watchdog disabled and removed."
}

status() {
    local state auto bundles latest
    if ! installed; then
        state="off"
    elif running; then
        state="running"
    else
        state="installed but NOT running"
    fi
    auto="$(sed -n 's/^AUTO_RESTART=//p' "$CONF" 2>/dev/null)"
    bundles="$(find "$OUT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)"
    latest="$(find "$OUT" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1)"
    PROMPT "UI Watchdog: $state
Auto-restart: $( [ "$auto" = 1 ] && echo on || echo off)
Diagnostic bundles: $bundles
Latest: ${latest:+$(basename "$latest")}"
}

check_now() {
    local result
    result="$(bash "$WATCHDOG" --once)"
    LOG "$result"
    case "$result" in
        OK*) ALERT "$result" ;;
        *) ERROR_DIALOG "$result" ;;
    esac
}

if installed; then
    choice=$(LIST_PICKER "UI Watchdog" "Status" "Check now" "Disable" "Exit" "Status") || exit 0
else
    choice=$(LIST_PICKER "UI Watchdog (off)" "Enable (diagnostics only)" "Enable + auto-restart" "Check now" "Exit" "Enable (diagnostics only)") || exit 0
fi
case "$choice" in
    "Enable (diagnostics only)") enable 0 ;;
    "Enable + auto-restart") enable 1 ;;
    "Status") status ;;
    "Check now") check_now ;;
    "Disable") disable ;;
    *) exit 0 ;;
esac
