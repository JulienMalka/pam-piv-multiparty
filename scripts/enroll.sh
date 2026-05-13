#!/usr/bin/env bash
# piv-multiparty enrolment helper.
#
# Provisions one security for a (user, group) pair:
#   1. Seals the PIV mgmt key: rotates from the factory default to a
#      fresh random value and discards it.
#   2. Generates an ECCP256 keypair on-card in slot 9a (non-exportable).
#   3. Self-signs a placeholder certificate so the slot is fully
#      populated (piv-multiparty itself only reads CKA_EC_POINT).
#   4. Rotates the PIV PIN off the factory default to a new value.
#   5. Prints a NixOS `entries.<user>` snippet for you to paste into
#      your configuration; `nixos-rebuild switch` applies it.
#
# The card must start in factory mgmt-key state. If it doesn't, run
# `yubico-piv-tool -a reset` first.
#
# Run once per (card, group). Repeat with a second physical YubiKey
# for the second group.
#
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 -u USER -g GROUP

  -u USER          User the authfile entry is for (matches PAM_USER).
  -g GROUP         Group label (must appear in the module's groups= arg).
  -h               This help.

The card must start with the factory mgmt key. Run
\`yubico-piv-tool -a reset\` first if it doesn't.
EOF
}

target_user=
group=
pin=123456

while getopts ":u:g:h" opt; do
  case "$opt" in
    u) target_user=$OPTARG ;;
    g) group=$OPTARG ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

[[ -n "$target_user" && -n "$group" ]] || { usage >&2; exit 2; }

cn="${target_user} (${group})"

start_key=010203040506070801020304050607080102030405060708

for cmd in yubico-piv-tool openssl; do
  command -v "$cmd" >/dev/null || { echo "error: $cmd not in PATH" >&2; exit 1; }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "==> Checking PIV applet"
yubico-piv-tool -a status >/dev/null

echo "==> Sealing PIV management key (random, discarded)"
new_key=$(openssl rand -hex 24)
if ! out=$(yubico-piv-tool --key="$start_key" -a set-mgm-key \
              --new-key="$new_key" 2>&1); then
  printf '%s\n' "$out" >&2
  if [[ "$out" == *uthentication* ]]; then
    cat >&2 <<'EOF'

The card's PIV management key is not the factory default
(010203...08). This script only enrols cards in factory state.

Reset the card to factory first:

  # block the PIN (3 wrong attempts)
  for i in 1 2 3; do yubico-piv-tool -a verify-pin -P 000000 || true; done

  # block the PUK (3 wrong attempts; --new-pin sets the new PUK here)
  for i in 1 2 3; do yubico-piv-tool -a change-puk -P 00000000 --new-pin 11111111 || true; done

  # now reset (wipes ALL PIV slots, not just 9a)
  yubico-piv-tool -a reset

Then rerun this script.
EOF
  fi
  exit 1
fi
echo "    mgmt key set and not retained; re-provisioning requires reset"

echo "==> Generating slot-9a keypair (ECCP256, touch-policy=always)"
yubico-piv-tool --key="$new_key" -a generate -s 9a -A ECCP256 \
                --touch-policy=always > 9a.pub.pem

echo "==> Self-signing slot-9a certificate (CN=${cn})"
echo "    ! TOUCH the YubiKey when it blinks."
yubico-piv-tool --key="$new_key" -P "$pin" -a verify-pin -a selfsign-certificate \
                -s 9a -S "/CN=${cn}/" --valid-days=3650 \
                < 9a.pub.pem > 9a.cert.pem

echo "==> Importing certificate into slot 9a"
yubico-piv-tool --key="$new_key" -a import-certificate -s 9a < 9a.cert.pem

echo "==> Rotating PIV PIN"
if [[ ! -t 0 ]]; then
  echo "error: stdin is not a tty; enrolment requires interactive PIN entry" >&2
  exit 2
fi
read -rs -p "    New PIN (6-8 chars, hidden): " new_pin; echo
read -rs -p "    Confirm: "                   confirm; echo
if [[ "$new_pin" != "$confirm" ]]; then
  echo "error: PINs do not match" >&2
  exit 2
fi
if (( ${#new_pin} < 6 || ${#new_pin} > 8 )); then
  echo "error: new PIN must be 6-8 characters (got ${#new_pin})" >&2
  exit 2
fi
if [[ "$new_pin" == "$pin" ]]; then
  echo "error: new PIN must differ from the factory default" >&2
  exit 2
fi
yubico-piv-tool -a change-pin --pin="$pin" --new-pin="$new_pin" >/dev/null
echo "    PIN rotated."

spki=$(openssl x509 -in 9a.cert.pem -noout -pubkey \
       | openssl pkey -pubin -outform DER | base64 -w0)

cat <<EOF

==> Enrolment complete.

Add this entry to your NixOS configuration under
security.pam.multiparty.entries.${target_user}:

  { group = "${group}"; spki = "${spki}"; }

EOF
