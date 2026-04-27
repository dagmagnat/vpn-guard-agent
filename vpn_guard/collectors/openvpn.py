from __future__ import annotations

from pathlib import Path
from vpn_guard.models import ClientStats


def collect(path: Path) -> dict[str, ClientStats]:
    if not path.exists():
        return {}
    stats: dict[str, ClientStats] = {}
    in_clients = False
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        if line.startswith('Common Name,Real Address'):
            in_clients = True
            continue
        if line.startswith('ROUTING TABLE'):
            in_clients = False
        if not in_clients or ',' not in line:
            continue
        parts = line.split(',')
        if len(parts) < 5:
            continue
        real = parts[1].rsplit(':', 1)[0]
        try:
            rx = int(parts[2])
            tx = int(parts[3])
        except ValueError:
            rx = tx = 0
        stats[real] = ClientStats(ip=real, source='openvpn', rx_bytes=rx, tx_bytes=tx, notes=[f'openvpn CN={parts[0]}'])
    return stats
