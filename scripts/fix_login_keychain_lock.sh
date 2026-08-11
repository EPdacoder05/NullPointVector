#!/bin/bash
# Fix macOS "sharingd / iCloudHelper wants login keychain" on lid-open.
#
# Cause: login keychain locks on sleep (and/or password ≠ Mac login password).
# Apple Continuity (sharingd) then prompts on wake. This is NOT NullPoint Guard,
# and TestFlight iPhone testers never see these Mac dialogs.
#
# Run ONCE in Terminal (may ask for your Mac/login keychain password):
#   bash scripts/fix_login_keychain_lock.sh
set -euo pipefail
KC="${HOME}/Library/Keychains/login.keychain-db"
if [[ ! -f "$KC" ]]; then
  echo "No login.keychain-db at $KC"
  exit 1
fi

echo "Before:"
security show-keychain-info "$KC" 2>&1 || true

# Omit -l (lock on sleep) and -u (lock after timeout) → stay unlocked with session.
security set-keychain-settings "$KC"

echo
echo "After:"
security show-keychain-info "$KC" 2>&1 || true

echo
echo "If prompts CONTINUE after sleep, sync the keychain password:"
echo "  1. Open Keychain Access"
echo "  2. Select 'login' keychain → Edit → Change Password for Keychain 'login'…"
echo "  3. Set it to YOUR CURRENT Mac login password"
echo "  4. Sleep → wake once to verify"
echo
echo "Optional: System Settings → Apple ID → iCloud → turn off features you do not use"
echo "(Handoff / Continuity reduce sharingd chatter; not required if password sync works)."
