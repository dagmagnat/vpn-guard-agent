from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml

DEFAULT_CONFIG_PATHS = [
    Path('/etc/vpn-guard/config.yml'),
    Path('./config.yml'),
    Path('./config.example.yml'),
]

@dataclass
class Config:
    raw: dict[str, Any]
    config_path: Path | None = None

    @property
    def xray_access_log(self) -> Path:
        return Path(self.raw.get('paths', {}).get('xray_access_log', '/var/log/xray/access.log'))

    @property
    def openvpn_status_log(self) -> Path:
        return Path(self.raw.get('paths', {}).get('openvpn_status_log', '/etc/openvpn/openvpn-status.log'))

    @property
    def db_path(self) -> Path:
        return Path(self.raw.get('paths', {}).get('db_path', '/var/lib/vpn-guard/vpn-guard.sqlite3'))

    @property
    def thresholds(self) -> dict[str, int]:
        defaults = {
            'tcp_connections_high': 300,
            'udp_connections_high': 500,
            'unique_destinations_high': 200,
            'upload_mb_per_hour_high': 1000,
            'blacklist_hits_high': 1,
        }
        defaults.update(self.raw.get('thresholds', {}) or {})
        return defaults

    @property
    def blocklists(self) -> list[str]:
        return list(self.raw.get('blocklists', []) or [])

    @property
    def whitelist(self) -> set[str]:
        return set(self.raw.get('whitelist', []) or [])

    @property
    def firewall_backend(self) -> str:
        return self.raw.get('firewall', {}).get('backend', 'nftables')

    @property
    def nft_table(self) -> str:
        return self.raw.get('firewall', {}).get('nft_table', 'vpn_guard')

    @property
    def nft_set(self) -> str:
        return self.raw.get('firewall', {}).get('nft_set', 'blocked_ips')


def load_config(path: str | None = None) -> Config:
    paths = [Path(path)] if path else DEFAULT_CONFIG_PATHS
    for candidate in paths:
        if candidate.exists():
            with candidate.open('r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            return Config(raw=data, config_path=candidate)
    return Config(raw={}, config_path=None)
