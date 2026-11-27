#!/bin/sh
# Removes Varta from macOS:  sudo sh uninstall.sh   (--purge also deletes rules and settings)
if [ "$(id -u)" != 0 ]; then echo "Run with sudo: sudo sh $0"; exit 1; fi
launchctl bootout system/com.varta.vartad 2>/dev/null || true
pkill -x varta-gui 2>/dev/null || true
rm -f /Library/LaunchDaemons/com.varta.vartad.plist /Library/LaunchAgents/com.varta.gui.plist
# vartad removes its pf rules when it stops; flush again in case it was killed.
pfctl -a com.apple/varta_ask -F all >/dev/null 2>&1 || true
rm -rf /Applications/Varta.app /var/run/varta
if [ "$1" = "--purge" ]; then rm -rf "/Library/Application Support/Varta"; echo "Rules and settings removed."; fi
echo "Varta removed."
