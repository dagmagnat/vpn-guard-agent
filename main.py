from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

@dataclass
class ClientStats:
    # For WireGuard/AmneziaWG this is the internal tunnel IP, e.g. 10.8.0.5
    ip: str
    source: str = 'unknown'
    tcp_connections: int = 0
    udp_connections: int = 0
    unique_destinations: set[str] = field(default_factory=set)
    blacklist_hits: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    notes: list[str] = field(default_factory=list)
    seen_at: datetime = field(default_factory=datetime.utcnow)

    # VPN peer metadata. Filled by WireGuard/AmneziaWG collectors when available.
    interface: str = ''
    peer_public_key: str = ''
    endpoint: str = ''
    allowed_ips: str = ''
    latest_handshake: int = 0

    @property
    def unique_destinations_count(self) -> int:
        return len(self.unique_destinations)

    def merge(self, other: 'ClientStats') -> 'ClientStats':
        self.tcp_connections += other.tcp_connections
        self.udp_connections += other.udp_connections
        self.unique_destinations |= other.unique_destinations
        self.blacklist_hits += other.blacklist_hits
        self.rx_bytes += other.rx_bytes
        self.tx_bytes += other.tx_bytes
        self.notes.extend(x for x in other.notes if x not in self.notes)

        for attr in ('interface', 'peer_public_key', 'endpoint', 'allowed_ips'):
            if not getattr(self, attr) and getattr(other, attr):
                setattr(self, attr, getattr(other, attr))
        if not self.latest_handshake and other.latest_handshake:
            self.latest_handshake = other.latest_handshake

        if self.source == 'unknown':
            self.source = other.source
        elif other.source and other.source not in self.source:
            self.source += f',{other.source}'
        return self
