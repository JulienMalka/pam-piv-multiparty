#!/usr/bin/env bash
# piv-multiparty enrolment helper.
#
# Provisions one YubiKey for a (user, group) pair:
#   1. Rotates the PIV mgmt key off the factory default to a fresh
#      random value, writes it to a 0600 file.
#   2. Generates an ECCP256 keypair on-card in slot 9a (non-exportable).
#   3. Self-signs a placeholder certificate so the slot is fully
#      populated (piv-multiparty itself only reads CKA_EC_POINT).
#   4. Prints the authfile line; you append it under sudo.
#
# Run once per (card, group). Repeat with a second physical YubiKey
# for the second group.
#
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 -u USER -g GROUP [-k MGMT_KEY_OUT] [-K MGMT_KEY_IN] [-p PIN] [-c CN] [-t TOUCH]

  -u USER          User the authfile entry is for (matches PAM_USER).
  -g GROUP         Group label (must appear in the module's groups= arg).
  -k MGMT_KEY_OUT  File to write the new random mgmt key into.
                   Default: \$HOME/.piv-mgmt-key-<USER>-<GROUP>
  -K MGMT_KEY_IN   File to read the *current* mgmt key from. Default:
                   the PIV factory default (010203...08). Pass this if
                   you've already rotated the key on this card.
  -p PIN           PIV PIN. Default: 123456 (factory). Change the PIN
                   after enrolment with: yubico-piv-tool -a change-pin
  -c CN            Certificate Common Name. Default: "<USER> (<GROUP>)".
  -t TOUCH         Slot-9a touch policy: never | cached | always.
                   Default: always (each sign needs a touch).
  -h               This help.
EOF
}

target_user=
group=
key_out=
key_in_file=
pin=123456
cn=
touch_policy=always

while getopts ":u:g:k:K:p:c:t:h" opt; do
  case "$opt" in
    u) target_user=$OPTARG ;;
    g) group=$OPTARG ;;
    k) key_out=$OPTARG ;;
    K) key_in_file=$OPTARG ;;
    p) pin=$OPTARG ;;
    c) cn=$OPTARG ;;
    t) touch_policy=$OPTARG ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

[[ -n "$target_user" && -n "$group" ]] || { usage >&2; exit 2; }

case "$touch_policy" in
  never|cached|always) ;;
  *) echo "error: -t must be one of: never, cached, always" >&2; exit 2 ;;
esac

key_out=${key_out:-"$HOME/.piv-mgmt-key-${target_user}-${group}"}
cn=${cn:-"${target_user} (${group})"}

if [[ -n "$key_in_file" ]]; then
  start_key=$(< "$key_in_file")
else
  start_key=010203040506070801020304050607080102030405060708
fi

for cmd in yubico-piv-tool openssl; do
  command -v "$cmd" >/dev/null || { echo "error: $cmd not in PATH" >&2; exit 1; }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "==> Checking PIV applet"
yubico-piv-tool -a status >/dev/null

echo "==> Rotating PIV management key"
new_key=$(openssl rand -hex 24)
yubico-piv-tool --key="$start_key" -a set-mgm-key \
                --new-key="$new_key" --touch-policy=never >/dev/null
umask 077
printf '%s\n' "$new_key" > "$key_out"
echo "    new mgmt key written to $key_out (mode 0600)"

echo "==> Generating slot-9a keypair (ECCP256, touch-policy=${touch_policy})"
yubico-piv-tool --key="$new_key" -a generate -s 9a -A ECCP256 \
                --touch-policy="$touch_policy" > 9a.pub.pem

echo "==> Self-signing slot-9a certificate (CN=${cn})"
if [[ "$touch_policy" != "never" ]]; then
  echo "    ! TOUCH the YubiKey when it blinks (touch-policy=${touch_policy})."
fi
yubico-piv-tool --key="$new_key" -P "$pin" -a verify-pin -a selfsign-certificate \
                -s 9a -S "/CN=${cn}/" --valid-days=3650 \
                < 9a.pub.pem > 9a.cert.pem

echo "==> Importing certificate into slot 9a"
yubico-piv-tool --key="$new_key" -a import-certificate -s 9a < 9a.cert.pem

spki=$(openssl x509 -in 9a.cert.pem -noout -pubkey \
       | openssl pkey -pubin -outform DER | base64 -w0)
line="${target_user}:group=${group}:spki=${spki}"

cat <<EOF

==> Enrolment complete.

Authfile line:

  ${line}

Append with:

  echo '${line}' | sudo tee -a /var/lib/piv-multiparty/${target_user}.map >/dev/null

Management key stored at: ${key_out}
EOF
