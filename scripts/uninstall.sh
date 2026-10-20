#!/bin/bash
# Removes altiward-forwarder-hook. Keeps each user's queue of events not yet sent
# (~/Library/Application Support/com.altiward.forwarder) unless run with --purge.
#   sudo "/Library/Application Support/Altiward Forwarder/uninstall.sh" [--purge]
#
# Remove the profile that sets Privileges' PostChangeExecutablePath to the hook as well, or
# Privileges will try to run a file that's gone.
set -euo pipefail
LABEL=com.altiward.forwarder.flush
DIR="/Library/Application Support/Altiward Forwarder"
if [ "$(id -u)" != 0 ]; then echo "Run with sudo." >&2; exit 1; fi

for uid in $(ps -axo uid=,comm= | awk '$2 ~ /loginwindow$/ { print $1 }' | sort -u); do
  launchctl bootout "gui/$uid/$LABEL" 2>/dev/null || true
done
rm -f "/Library/LaunchAgents/$LABEL.plist"
rm -rf "$DIR"
pkgutil --forget com.altiward.forwarder.pkg >/dev/null 2>&1 || true

queued=0
for q in /Users/*/Library/Application\ Support/com.altiward.forwarder/queue; do
  [ -d "$q" ] || continue
  n="$(find "$q" -name '*.json' | wc -l | tr -d ' ')"
  queued=$((queued + n))
  if [ "${1:-}" = "--purge" ]; then rm -rf "$(dirname "$q")"; fi
done
if [ "${1:-}" = "--purge" ]; then
  echo "Removed altiward-forwarder-hook and its queues ($queued unsent events deleted)."
else
  echo "Removed altiward-forwarder-hook. Kept each user's queue ($queued events not yet sent); run with --purge to delete them."
fi
