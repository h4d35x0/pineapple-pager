# UI Watchdog

A WiFi Pineapple Pager payload that watches the device UI and, if it stops responding, saves a diagnostics bundle before anyone has to power-cycle. It is off until you enable it.

- **Author:** h4d35x0
- **Version:** 1.0
- **Category:** incident_response

## What it does

When enabled, it installs a small background service (procd) that every 60 seconds checks:

- the UI process is running, and
- the local API answers within 10 seconds.

After three failed checks in a row it saves one diagnostics bundle per incident to `/root/logs/ui_watchdog/` (logread, dmesg, process and thread states, memory, disk, `/tmp/uierrors.log`, the firmware crash log). **Enable + auto-restart** also restarts the UI after saving, at most once every 30 minutes.

## Menu

- **Enable (diagnostics only)** / **Enable + auto-restart** - install and start the service.
- **Status** - show whether it is running, the auto-restart state, and saved bundles.
- **Check now** - run one check immediately.
- **Disable** - stop and remove the service (saved diagnostics are kept).

## Requirements

- `jq`, `curl`. Uses the device's own service manager (procd) so it restarts at boot.

## Install

```sh
scp -r ui_watchdog root@172.16.52.1:/mmc/root/payloads/user/incident_response/
```

Then run **UI Watchdog** from the payloads menu under **incident_response** and choose Enable.

## Notes

- A UI that still answers its API but has stopped drawing the screen is not detected; the framebuffer is not a reliable signal because it legitimately stops changing when the screen is idle or dimmed.
- The folder ships `watchdog.sh`, the loop the service runs. The payload finds it relative to itself, so keep the two together.
