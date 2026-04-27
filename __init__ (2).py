from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path
import re
from ipaddress import ip_address, ip_network
from vpn_guard.models import ClientStats

# Common Xray access lines contain: from CLIENT:PORT accepted tcp:DEST:PORT
FROM_RE = re.compile(r'from\s+([^\s:]+):\d+', re.IGNORECASE)
DEST_RE = re.compile(r'accepted\s+(tcp|udp):([^\s:]+)', re.IGNORECASE)


def tail_lines(path: Path, limit: int = 5000) -> list[str]:
    if not path.exists():
        return []
    with path.open('r', encoding='utf-8', errors='ignore') as f:
        return list(deque(f, maxlen=limit))


def collect(path: Path, blocklists: list[str], whitelist: set[str], limit: int = 5000) -> dict[str, ClientStats]:
    networks = []
    for item in blocklists:
        try:
            networks.append(ip_network(item, strict=False))
        except ValueError:
            pass

    stats: dict[str, ClientStats] = defaultdict(lambda: ClientStats(ip='', source='xray'))
    for line in tail_lines(path, limit):
        fm = FROM_RE.search(line)
        dm = DEST_RE.search(line)
        if not fm:
            continue
        src = fm.group(1)
        if src in whitelist:
            continue
        item = stats[src]
        item.ip = src
        if dm:
            proto = dm.group(1).lower()
            dst = dm.group(2)
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
