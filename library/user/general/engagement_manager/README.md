# Engagement Manager

A WiFi Pineapple Pager payload that turns an authorized test into a bounded engagement: it records scope and authorization, can restrict PineAP to in-scope targets, and builds an activity report at the end. It does nothing until you start an engagement.

- **Author:** h4d35x0
- **Version:** 1.0
- **Category:** general

## What it does

- **Start** - name the engagement, confirm you have written authorization, and set scope (from `/root/engagements/scope.txt` or by picking APs from live recon). Optionally restrict PineAP to in-scope SSIDs/clients; the existing filters are saved first.
- **Status** - show the active engagement and its scope.
- **End** - restore the PineAP filters exactly, verify they match, and write an activity report.

Nothing is enforced until you start an engagement, and if the filters cannot be restored the engagement stays active so you are never left in an unknown state.

## scope_guard.sh

The folder ships a helper, `scope_guard.sh`, that other payloads can source to honour the active scope:

```sh
SG=/root/payloads/user/general/engagement_manager/scope_guard.sh
[ -f "$SG" ] && . "$SG"
if type scope_check >/dev/null 2>&1 && ! scope_check "$TARGET_BSSID"; then
    ERROR_DIALOG "$TARGET_BSSID is out of scope"; exit 1
fi
```

`scope_check` returns success when no engagement is active, so payloads that opt in keep working normally off-engagement.

## Requirements

- The persistent system log (`/mmc/root/logs/system.log`) for the activity report.
- `jq`, `curl`.

## Output

- A per-engagement directory under `/root/engagements/` with the scope, authorization record, saved filters and `report.txt`.

## Install

```sh
scp -r engagement_manager root@172.16.52.1:/mmc/root/payloads/user/general/
```

## Notes

- PineAP filters only govern which networks PineAP serves and who may connect to it; they do not restrict deauth or other payloads. Other payloads opt into scope via `scope_guard.sh`.
- The report is an activity/audit log (payloads run, loot created with checksums, timeline). For a recon-findings report (APs, clients, handshakes, encryption), run the **Engagement Report Generator** (`recondb_reporting`).
