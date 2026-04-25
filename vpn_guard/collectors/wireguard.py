from __future__ import annotations

from vpn_guard.models import ClientStats
from vpn_guard.utils import run_command


def collect() -> dict[str, ClientStats]:
    proc = run_command(['wg', 'show', 'all', 'dump'])
    if proc.returncode != 0:
        return {}
    stats: dict[str, ClientStats] = {}
    for line in proc.stdout.splitlines():
        parts = line.split('\t')
        # peer lines: interface public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
        if len(parts) < 8 or parts[1] == 'private-key':
            continue
        endpoint = parts[3]
        if endpoint == '(none)' or ':' not in endpoint:
            continue
        client_ip = endpoint.rsplit(':', 1)[0]
        try:
            rx = int(parts[6])
            tx = int(parts[7])
        except ValueError:
            rx = tx = 0
        stats[client_ip] = ClientStats(ip=client_ip, source='wireguard', rx_bytes=rx, tx_bytes=tx)
    return stats
