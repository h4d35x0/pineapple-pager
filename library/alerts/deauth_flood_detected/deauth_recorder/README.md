# Deauth Recorder

A WiFi Pineapple Pager **alert** payload that records every deauthentication/disassociation flood the firmware detects. Silent: it writes a log line and nothing else.

- **Author:** h4d35x0
- **Version:** 1.0
- **Category:** alerts (deauth_flood_detected)

## What it does

On each `deauth_flood_detected` alert, appends one tab-separated line to `/root/loot/deauth/events.tsv`:

`epoch, local time, AP, client, claimed source, claimed destination, firmware message`

MACs are stored as the firmware reported them. The file is root-only and rotates automatically (it keeps up to two generations). Because it lives under `/root/loot`, Loot Vault encrypts it with the rest of your loot.

Pair it with the **Deauth Report** payload to turn the log into a per-AP summary.

## Install

Alert payloads live under `alerts/<event>/`:

```sh
scp -r deauth_recorder root@172.16.52.1:/mmc/root/payloads/alerts/deauth_flood_detected/
```

It then runs automatically whenever the firmware raises a deauth-flood alert.

## Notes

- The claimed source MAC in a deauth frame is usually spoofed; the record documents who was targeted and when, not who attacked.
