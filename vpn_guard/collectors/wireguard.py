from __future__ import annotations

from ipaddress import ip_network
from vpn_guard.models import ClientStats
from vpn_guard.utils import run_command


def _bin_exists(name: str) -> bool:
    return run_command(['bash', '-lc', f'command -v {name} >/dev/null 2>&1']).returncode == 0


def _client_ip_from_allowed(allowed_ips: str) -> str:
    # Usually: 10.8.0.2/32 or 10.8.0.2/32,fd42::2/128
    for item in (allowed_ips or '').split(','):
        item = item.strip()
        if not item or ':' in item:
            continue
        return item.split('/', 1)[0]
    return ''


def _collect_with(binary: str, source_name: str) -> dict[str, ClientStats]:
    if not _bin_exists(binary):
        return {}

    proc = run_command([binary, 'show', 'all', 'dump'])
    if proc.returncode != 0:
        return {}

    stats: dict[str, ClientStats] = {}
    for line in proc.stdout.splitlines():
        parts = line.split('\t')
        # Interface line: interface private-key public-key listen-port fwmark
        # Peer line: interface public-key preshared-key endpoint allowed-ips latest-handshake transfer-rx transfer-tx persistent-keepalive
        if len(parts) < 9 or parts[1] == 'private-key':
            continue

        iface = parts[0]
        public_key = parts[1]
        endpoint = parts[3]
        allowed_ips = parts[4]
        client_ip = _client_ip_from_allowed(allowed_ips)
        if not client_ip:
            continue

        try:
            latest = int(parts[5])
        except ValueError:
            latest = 0
        try:
            rx = int(parts[6])  # bytes received from peer by server
            tx = int(parts[7])  # bytes sent to peer by server
        except ValueError:
            rx = tx = 0

        item = ClientStats(
            ip=client_ip,
            source=source_name,
            rx_bytes=rx,
            tx_bytes=tx,
            interface=iface,
            peer_public_key=public_key,
            endpoint=endpoint if endpoint != '(none)' else '',
            allowed_ips=allowed_ips,
            latest_handshake=latest,
            notes=[f'{source_name} iface={iface}', f'endpoint={endpoint}', f'allowed={allowed_ips}'],
        )
        stats[client_ip] = item
    return stats


def collect() -> dict[str, ClientStats]:
    data: dict[str, ClientStats] = {}
    for binary, source in (('wg', 'wireguard'), ('awg', 'amneziawg')):
        for ip, stats in _collect_with(binary, source).items():
            if ip in data:
                data[ip].merge(stats)
            else:
                data[ip] = stats
    return data


def client_networks(peer_stats: dict[str, ClientStats]) -> list[str]:
    networks: list[str] = []
    for peer in peer_stats.values():
        for item in (peer.allowed_ips or '').split(','):
            item = item.strip()
            if not item or ':' in item:
                continue
            try:
                networks.append(str(ip_network(item, strict=False)))
            except ValueError:
                pass
    return networks
