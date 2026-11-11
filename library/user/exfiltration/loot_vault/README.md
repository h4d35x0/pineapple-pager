# Loot Vault

A WiFi Pineapple Pager payload that encrypts `/root/loot` to your certificate, so a lost Pager does not mean lost client data. Only the private key on your workstation can decrypt it.

- **Author:** h4d35x0
- **Version:** 1.0
- **Category:** exfiltration

## One-time setup (on your workstation)

The private key never goes on the Pager.

```sh
openssl req -x509 -newkey rsa:4096 -nodes -days 3650 -subj "/CN=loot-vault" \
    -keyout loot_vault.key -out loot_vault.crt
scp loot_vault.crt root@172.16.52.1:/root/loot_vault.crt
```

Keep `loot_vault.key` somewhere safe (a password manager). Without it the vault cannot be opened.

## What it does

- **Encrypt loot** - packs everything under `/root/loot` into one CMS AES-256-GCM file in `/root/loot_vault`.
- **Encrypt + delete plaintext** - the same, then deletes each plaintext file, but only after the vault file verifies and only files whose SHA-256 is unchanged since they were archived.
- **Show vault** - list the encrypted archives and the certificate in use.

File names live only inside the encrypted archive.

## Decrypt (on your workstation)

```sh
openssl cms -decrypt -binary -inform DER -in loot_TIMESTAMP.cms \
    -inkey loot_vault.key -recip loot_vault.crt | tar -xf -
```

## Install

```sh
scp -r loot_vault root@172.16.52.1:/mmc/root/payloads/user/exfiltration/
```

## Notes

- CMS AuthEnvelopedData with AES-256-GCM (RFC 5083/5084) also rejects tampered files.
- The Pager can encrypt but never decrypt, which is the point: see R. Anderson, *Security Engineering* 3rd ed., section 5.3.4.
