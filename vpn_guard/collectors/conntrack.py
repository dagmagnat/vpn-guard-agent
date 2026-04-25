from __future__ import annotations

from collections import defaultdict
import re
from ipaddress import ip_address, ip_network
from vpn_guard.models import ClientStats
from vpn_guard.utils import run_command

SRC_RE = re.compile(r'\bsrc=([^\s]+)')
DST_RE = re.compile(r'\bdst=([^\s]+)')
PROTO_RE = re.compile(r'^(tcp|udp)\s+', re.IGNORECASE)


def collect(blocklists: list[str], whitelist: set[str]) -> dict[str, ClientStats]:
    networks = []
    for item in blocklists:
        try:
            networks.append(ip_network(item, strict=False))
        except ValueError:
            pass

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
        if src in whitelist or src.startswith(('127.', '10.', '192.168.', '172.16.')):
            continue
        item = stats[src]
        item.ip = src
        if proto == 'tcp':
            item.tcp_connections += 1
        elif proto == 'udp':
            item.udp_connections += 1
        item.unique_destinations.add(dst)
        try:
            dst_ip = ip_address(dst)
            if any(dst_ip in n for n in networks):
                item.blacklist_hits += 1
                item.notes.append(f'blacklist destination {dst}')
        except ValueError:
            pass
    return dict(stats)
