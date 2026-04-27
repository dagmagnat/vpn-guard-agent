#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root: sudo bash install.sh"
  exit 1
fi

apt-get update
apt-get install -y python3 python3-venv python3-pip conntrack nftables wireguard-tools

mkdir -p /opt/vpn-guard /etc/vpn-guard /var/lib/vpn-guard
cp -r vpn_guard pyproject.toml requirements.txt /opt/vpn-guard/
cp -n config.example.yml /etc/vpn-guard/config.yml

python3 -m venv /opt/vpn-guard/.venv
/opt/vpn-guard/.venv/bin/pip install --upgrade pip
/opt/vpn-guard/.venv/bin/pip install -e /opt/vpn-guard
ln -sf /opt/vpn-guard/.venv/bin/vpn-guard /usr/local/bin/vpn-guard

echo "Installed. Try: vpn-guard scan"
echo "Config: /etc/vpn-guard/config.yml"
