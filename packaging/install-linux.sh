#!/bin/sh
# Builds and installs Varta (varta CLI, vartad daemon, varta-gui) on Debian/Ubuntu.
# Run from the project root as your normal user:  sh packaging/install-linux.sh
set -e
cd "$(dirname "$0")/.."

echo "==> Installing build dependencies"
sudo apt-get install -y build-essential cmake pkg-config curl nftables \
    libnetfilter-queue-dev qt6-base-dev qt6-tools-dev qt6-l10n-tools

echo "==> Building"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
(cd build && ctest --output-on-failure)

echo "==> Installing to /usr/local"
sudo cmake --install build --prefix /usr/local
sudo install -d -m 755 /etc/varta /var/lib/varta
sudo install -m 644 packaging/vartad.service /etc/systemd/system/vartad.service

echo "==> Group 'varta' (members may answer firewall prompts)"
sudo groupadd -f varta
sudo usermod -aG varta "$USER"

echo "==> Downloading the offline IP database (~90 MB)"
sudo /usr/local/sbin/vartad --update-db || echo "   (failed - run 'sudo vartad --update-db' later)"

echo "==> Starting vartad"
sudo systemctl daemon-reload
sudo systemctl enable --now vartad

echo "==> Menu entry + autostart for the GUI"
mkdir -p "$HOME/.local/share/applications" "$HOME/.config/autostart"
cp packaging/varta-gui.desktop "$HOME/.local/share/applications/"
sed 's|^Exec=varta-gui$|Exec=varta-gui --hidden|' packaging/varta-gui.desktop > "$HOME/.config/autostart/varta-gui.desktop"

echo
echo "Done. Log out and back in once (so the 'varta' group applies), then start"
echo "'Varta Firewall' from the menu. Emergency stop:  sudo systemctl stop vartad"
