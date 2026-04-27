from __future__ import annotations

from collections import defaultdict
import re
from ipaddress import ip_address, ip_network
from vpn_guard.models import ClientStats
from vpn_guard.utils import run_command

SRC_RE = re.compile(r'\bsrc=([^\s]+)')
DST_RE = re.compile(r'\bdst=([^\s]+)')
PROTO_RE = re.compile(r'^(tcp|udp)\s+', re.IGNORECASE)
BYTES_RE = re.compile(r'\bbytes=(\d+)')


def _networks(items: list[str]) -> list:
    out = []
    for item in items:
        try:
            out.append(ip_network(item, strict=False))
        except ValueError:
            pass
    return out


def _in_any(ip: str, networks: list) -> bool:
    try:
        addr = ip_address(ip)
        return any(addr in n for n in networks)
    except ValueError:
        return False


def collect(blocklists: list[str], whitelist: set[str], vpn_client_networks: list[str] | None = None) -> dict[str, ClientStats]:
    bad_networks = _networks(blocklists)
    vpn_networks = _networks(vpn_client_networks or [])

    stats: dict[str, ClientStats] = defaultdict(lambda: ClientStats(ip='', source='conntrack'))
    proc = run_command(['conntrack', '-L'])
    if proc.returncode != 0:
        proc = run_command(['bash', '-lc', 'cat /proc/net/nf_conntrack 2>/dev/null || cat /proc/net/ip_conntrack 2>/dev/null'])
    if proc.returncode != 0:
        return {}

    for line in proc.stdout.splitlines():
        proto_match = PROTO_RE.search(line)
        proto = proto_match.group(1).lower() if proto_match else ''
        srcs = SRC_RE.findall(line)
        dsts = DST_RE.findall(line)
        if not srcs or not dsts:
            continue

        src = srcs[0]
        dst = dsts[0]

        # For WG/AWG the real useful client id is the tunnel IP (10.x/172.x/192.168.x),
        # but only if it belongs to one of the peer AllowedIPs collected from wg/awg.
        if src in whitelist:
            continue
        if vpn_networks:
            if not _in_any(src, vpn_networks):
                continue
        else:
            # Old behavior: do not treat random LAN/private addresses as clients.
            if src.startswith(('127.', '10.', '192.168.', '172.16.')):
                continue

        item = stats[src]
        item.ip = src
        if proto == 'tcp':
            item.tcp_connections += 1
        elif proto == 'udp':
            item.udp_connections += 1
        item.unique_destinations.add(dst)

        byte_values = [int(x) for x in BYTES_RE.findall(line)]
        if byte_values:
            item.tx_bytes += byte_values[0]
        if len(byte_values) > 1:
            item.rx_bytes += byte_values[1]

        try:
            dst_ip = ip_address(dst)
            if any(dst_ip in n for n in bad_networks):
                item.blacklist_hits += 1
                item.notes.append(f'blacklist destination {dst}')
        except ValueError:
            pass
    return dict(stats)
