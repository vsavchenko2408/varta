#!/bin/sh
# Installs or updates Varta on macOS. Run from the unpacked folder:
#   sudo sh install.sh            (add --update-db to refresh the IP database)
# Puts Varta.app (GUI + vartad) into /Applications, starts vartad with launchd and the GUI
# at every login. Rules and settings in "/Library/Application Support/Varta" are kept.
set -e
SRC=$(cd "$(dirname "$0")" && pwd)
APP=/Applications/Varta.app
DAEMON_PLIST=/Library/LaunchDaemons/com.varta.vartad.plist
AGENT_PLIST=/Library/LaunchAgents/com.varta.gui.plist
DATA="/Library/Application Support/Varta"

if [ "$(id -u)" != 0 ]; then echo "Run with sudo: sudo sh $0"; exit 1; fi
[ -d "$SRC/Varta.app" ] || { echo "Varta.app is missing in $SRC"; exit 1; }

echo "==> Stopping the old version"
launchctl bootout system/com.varta.vartad 2>/dev/null || true
pkill -x varta-gui 2>/dev/null || true
sleep 1

echo "==> Copying Varta.app to /Applications"
rm -rf "$APP"
/usr/bin/ditto "$SRC/Varta.app" "$APP"
chown -R root:wheel "$APP"
chmod -R go-w "$APP"
# Downloaded from the internet: without this, Gatekeeper refuses the unsigned app.
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true

mkdir -p "$DATA"
if [ -n "$VARTA_SKIP_DB" ]; then
    echo "==> Skipping the IP database (VARTA_SKIP_DB)"
elif [ "$1" = "--update-db" ] || [ ! -f "$DATA/ipdb/asn-ipv4.csv" ]; then
    echo "==> Downloading the offline IP database (~90 MB)"
    "$APP/Contents/MacOS/vartad" --update-db || echo "IP database download failed - run later: sudo $APP/Contents/MacOS/vartad --update-db"
else
    echo "==> IP database already present (refresh: sudo $APP/Contents/MacOS/vartad --update-db)"
fi

echo "==> Starting the vartad service"
cat > "$DAEMON_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.varta.vartad</string>
    <key>ProgramArguments</key><array><string>$APP/Contents/MacOS/vartad</string></array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardErrorPath</key><string>/var/log/vartad.log</string>
</dict>
</plist>
PLIST
chown root:wheel "$DAEMON_PLIST"; chmod 644 "$DAEMON_PLIST"
launchctl bootstrap system "$DAEMON_PLIST"

echo "==> GUI at login (menu bar icon)"
cat > "$AGENT_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.varta.gui</string>
    <key>ProgramArguments</key><array><string>$APP/Contents/MacOS/varta-gui</string><string>--hidden</string></array>
    <key>RunAtLoad</key><true/>
    <key>LimitLoadToSessionType</key><string>Aqua</string>
</dict>
</plist>
PLIST
chown root:wheel "$AGENT_PLIST"; chmod 644 "$AGENT_PLIST"

# Start the GUI for whoever is logged in at the screen now.
USER_NOW=$(stat -f%Su /dev/console)
if [ -n "$USER_NOW" ] && [ "$USER_NOW" != root ]; then
    launchctl asuser "$(id -u "$USER_NOW")" sudo -u "$USER_NOW" open -a "$APP" || true
fi

echo ""
echo "Done. Varta is running. Log: /var/log/vartad.log"
echo "Emergency stop: sudo launchctl bootout system/com.varta.vartad"
