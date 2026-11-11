#!/bin/bash
# Title: Loot Vault
# Author: h4d35x0
# Description: Encrypts /root/loot to your certificate (CMS, AES-256-GCM). Only the private key on your workstation can decrypt it. Can then remove the plaintext.
# Version: 1.0
# Category: exfiltration
#
# One-time setup on your workstation (the private key never goes on the Pager):
#   openssl req -x509 -newkey rsa:4096 -nodes -days 3650 -subj "/CN=loot-vault" \
#       -keyout loot_vault.key -out loot_vault.crt
#   scp loot_vault.crt root@172.16.52.1:/root/loot_vault.crt
#   Keep loot_vault.key somewhere safe (a password manager); without it the vault cannot be opened.
#
# Decrypt on the workstation:
#   openssl cms -decrypt -binary -inform DER -in loot_<time>.cms -inkey loot_vault.key \
#       -recip loot_vault.crt | tar -xf -
#
# Each run packs every file under /root/loot into one tar inside one encrypted file in /root/loot_vault.
# File names are only inside the encrypted archive. "Encrypt + delete plaintext" deletes a file only if the
# vault file verified and the file is unchanged since it was archived (same SHA-256).
#
# Sources: public-key encryption so the device can encrypt but not decrypt, per R. Anderson, Security
# Engineering 3rd ed., s5.3.4 "Public key encryption and trapdoor one-way permutations". CMS
# AuthEnvelopedData with AES-256-GCM (RFC 5083/5084) also rejects tampered files (tested on this Pager:
# OpenSSL 3.0.16, decrypt fails with exit 4 after a one-byte change).

LOOT="${LOOT_DIR:-/root/loot}"
VAULT="${VAULT_DIR:-/root/loot_vault}"
CERT="${VAULT_CERT:-/root/loot_vault.crt}"
TS="$(date +%Y%m%d_%H%M%S)"
LIST="/tmp/loot_vault_list.$$"
SUMS="/tmp/loot_vault_sums.$$"

cleanup() { rm -f "$LIST" "$SUMS"; }
trap cleanup EXIT

confirmed() { [ "$1" = "${DUCKYSCRIPT_USER_CONFIRMED:-1}" ]; }

check_cert() {
    if [ ! -f "$CERT" ]; then
        PROMPT "No vault certificate at $CERT. Create one on your workstation (see the payload header) and copy the .crt here. Never copy the private key to the Pager."
        exit 0
    fi
    if ! openssl x509 -in "$CERT" -noout 2>/dev/null; then
        ERROR_DIALOG "$CERT is not a valid X.509 certificate."
        exit 1
    fi
    if openssl pkey -in "$CERT" -noout 2>/dev/null || grep -q 'PRIVATE KEY' "$CERT" 2>/dev/null; then
        ERROR_DIALOG "$CERT contains a PRIVATE KEY. Remove it from the Pager; only the certificate belongs here."
        exit 1
    fi
}

# Serials as lowercase hex without leading zeros. x509 prints hex ("349C..."); CMS prints "0x349C..." or,
# for small serials, decimal.
cert_serial() {
    openssl x509 -in "$CERT" -noout -serial | cut -d= -f2 | tr 'A-F' 'a-f' | sed 's/^0*//'
}
recipient_serial() {
    local v
    v="$(openssl cms -cmsout -print -inform DER -in "$1" 2>/dev/null | sed -n 's/^ *serialNumber: *//p' | head -n 1)"
    case "$v" in
        0x*|0X*) printf '%s' "${v#0[xX]}" | tr 'A-F' 'a-f' | sed 's/^0*//' ;;
        ''|*[!0-9]*) printf 'unparsed:%s' "$v" ;;
        *) printf '%x' "$v" ;;
    esac
}

encrypt_loot() {
    local delete="$1" out sp n bytes deleted=0 skipped=0 f sum
    check_cert
    mkdir -p "$VAULT"
    chmod 700 "$VAULT"
    [ -d "$LOOT" ] || { ALERT "No loot directory ($LOOT)."; exit 0; }

    (cd "$LOOT" && find . -type f) | sort > "$LIST"
    n=$(wc -l < "$LIST")
    if [ "$n" -eq 0 ]; then
        ALERT "Loot is empty; nothing to encrypt."
        exit 0
    fi
    (cd "$LOOT" && while IFS= read -r f; do sha256sum "$f"; done < "$LIST") > "$SUMS"
    bytes=$(cd "$LOOT" && while IFS= read -r f; do wc -c < "$f"; done < "$LIST" | awk '{ s += $1 } END { print s + 0 }')

    out="$VAULT/loot_$TS.cms"
    sp=$(START_SPINNER "Encrypting $n files...")
    (cd "$LOOT" && tar -cf - -T "$LIST") | openssl cms -encrypt -binary -aes-256-gcm -outform DER -out "$out" "$CERT"
    local rc=$?
    STOP_SPINNER "$sp"

    # Verify: non-empty, parses as AuthEnvelopedData, and is addressed to this certificate's serial.
    if [ "$rc" -ne 0 ] || [ ! -s "$out" ] || \
        ! openssl cms -cmsout -print -inform DER -in "$out" 2>/dev/null | grep -q 'authEnvelopedData' || \
        [ "$(recipient_serial "$out")" != "$(cert_serial)" ]; then
        rm -f "$out"
        ERROR_DIALOG "Encryption failed or could not be verified. Plaintext loot left untouched."
        exit 1
    fi
    chmod 600 "$out"
    LOG "Vault file $out: $n files, $bytes bytes, $(wc -c < "$out") bytes encrypted."

    if [ "$delete" = "yes" ]; then
        resp=$(CONFIRMATION_DIALOG "Encrypted $n files. Delete the plaintext copies now?")
        if confirmed "$resp"; then
            while IFS= read -r line; do
                sum="${line%% *}"
                f="${line#*  }"
                if [ "$(cd "$LOOT" && sha256sum "$f" 2>/dev/null | cut -d' ' -f1)" = "$sum" ]; then
                    rm -f "$LOOT/$f" && deleted=$((deleted + 1))
                else
                    skipped=$((skipped + 1))
                    LOG "Kept (changed since archived): $f"
                fi
            done < "$SUMS"
            # BusyBox find has no -empty/-delete; rmdir only removes empty directories.
            find "$LOOT" -depth -mindepth 1 -type d -exec rmdir {} \; 2>/dev/null
            ALERT "Vault: $n files encrypted to $(basename "$out"). Deleted $deleted, kept $skipped changed."
            return
        fi
    fi
    ALERT "Vault: $n files encrypted to $(basename "$out"). Plaintext kept."
}

show_vault() {
    local count
    count=$(find "$VAULT" -name 'loot_*.cms' 2>/dev/null | wc -l)
    PROMPT "Vault: $VAULT
Encrypted archives: $count
Latest: $(find "$VAULT" -name 'loot_*.cms' 2>/dev/null | sort | tail -n 1 | xargs -r basename)
Certificate: $(openssl x509 -in "$CERT" -noout -subject -enddate 2>/dev/null | tr '\n' ' ')"
}

choice=$(LIST_PICKER "Loot Vault" "Encrypt loot" "Encrypt + delete plaintext" "Show vault" "Exit" "Encrypt loot") || exit 0
case "$choice" in
    "Encrypt loot") encrypt_loot no ;;
    "Encrypt + delete plaintext") encrypt_loot yes ;;
    "Show vault") show_vault ;;
    *) exit 0 ;;
esac
