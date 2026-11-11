# Deauth Report

A WiFi Pineapple Pager payload that summarises the deauthentication/disassociation floods recorded by the Deauth Recorder alert: which APs and clients were targeted, when and how often. Passive.

- **Author:** h4d35x0
- **Version:** 1.0
- **Category:** reconnaissance

## What it does

Reads `/root/loot/deauth/events.tsv` (written by the Deauth Recorder alert) and, per targeted AP, reports:

- number of events, first and last seen
- distinct clients hit and broadcast floods
- which side the frames claimed to come from
- the three most-targeted clients
- the SSID, if PineAP recon currently sees that BSSID
- a **[THIS PAGER]** flag if the Pager's own AP was the target
- in / out of scope, when an Engagement Manager engagement is active

## Menu

- **Last 24 hours** / **Last 7 days** / **All recorded** - build a report over that window.
- **Clear history** - delete the recorded events (reports already written are kept).

## Requirements

- The **Deauth Recorder** alert (`alerts/deauth_flood_detected/deauth_recorder`) must be installed; it is what records the events.
- `jq`, `curl` (present on firmware 2.0.0).

## Output

- Reports: `/root/loot/deauth/report_TIMESTAMP.txt`.

## Install

```sh
scp -r deauth_report root@172.16.52.1:/mmc/root/payloads/user/reconnaissance/
```

## Notes

- Deauth/disassoc frames are unauthenticated unless both ends use 802.11w (PMF), so the claimed source is usually spoofed. This report shows **targets and timing, not the attacker**.
