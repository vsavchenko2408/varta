#!/bin/sh
# Removes vartad/varta-gui. Rules in /etc/varta are kept unless you pass --purge.
set -e
sudo systemctl disable --now vartad 2>/dev/null || true
sudo rm -f /etc/systemd/system/vartad.service /usr/local/sbin/vartad /usr/local/bin/varta-gui /usr/local/bin/varta
sudo systemctl daemon-reload
rm -f "$HOME/.local/share/applications/varta-gui.desktop" "$HOME/.config/autostart/varta-gui.desktop"
if [ "$1" = "--purge" ]; then sudo rm -rf /etc/varta /var/lib/varta; fi
echo "Varta removed."
