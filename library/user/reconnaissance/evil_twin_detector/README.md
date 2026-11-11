# Evil Twin Detector

A WiFi Pineapple Pager payload that checks the access points PineAP recon already sees for evil-twin and karma-style rogue APs. It is passive: it reads recon data over the local API and transmits nothing.

- **Author:** h4d35x0
- **Version:** 1.0
- **Category:** reconnaissance

## What it does

Reads the recon device list and flags:

- **HIGH** - one SSID broadcast both open/WEP and with WPA (a downgrade twin).
- **HIGH** - one BSSID answering probes for many different SSIDs (a karma responder, i.e. another PineAP-style device).
- **HIGH** - a trusted SSID now seen with weaker encryption than its baseline.
- **MED** - a trusted SSID seen from a BSSID that is not in the baseline.
- **LOW** - one SSID seen with different WPA generations.

The baseline is optional. "Learn baseline" trusts whatever is in range at that moment, so only learn it somewhere you trust.

## Menu

- **Scan now** - analyse what recon currently sees and write a report.
- **Learn baseline (trust current)** - record the SSIDs/BSSIDs in range now as trusted.
- **Clear baseline** - delete the trusted baseline.

## Requirements

- Recon must be running (the payload reads its data; it does not scan itself).
- `jq` (present on firmware 2.0.0).

## Output

- Reports: `/root/loot/evil_twin/report_TIMESTAMP.txt` and `latest.txt`.
- Baseline: `/root/loot/evil_twin/baseline.tsv`.

## Install

```sh
scp -r evil_twin_detector root@172.16.52.1:/mmc/root/payloads/user/reconnaissance/
```

## Notes

- Complements `find_hackers`, which flags evil twins by manufacturer (OUI) and includes a Bluetooth sweep. This payload covers signals it does not: encryption downgrade, karma response count, and baseline drift (including a same-vendor twin an OUI check misses). Run both for fuller coverage.
- The specific heuristics are general knowledge; background on Wi-Fi at the network edge is in R. Anderson, *Security Engineering* 3rd ed., section 21.5.2.1.
