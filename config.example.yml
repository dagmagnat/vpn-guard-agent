from __future__ import annotations

from vpn_guard.models import ClientStats


def score_client(c: ClientStats, thresholds: dict[str, int]) -> tuple[int, str, list[str]]:
    score = 0
    reasons: list[str] = []

    if c.tcp_connections >= thresholds['tcp_connections_high']:
        score += 30
        reasons.append(f'high TCP connections: {c.tcp_connections}')
    if c.udp_connections >= thresholds['udp_connections_high']:
        score += 25
        reasons.append(f'high UDP connections: {c.udp_connections}')
    if c.unique_destinations_count >= thresholds['unique_destinations_high']:
        score += 25
        reasons.append(f'many unique destinations: {c.unique_destinations_count}')
    if c.blacklist_hits >= thresholds['blacklist_hits_high']:
        score += 70
        reasons.append(f'blacklist hits: {c.blacklist_hits}')
    upload_mb = c.tx_bytes / 1024 / 1024
    if upload_mb >= thresholds['upload_mb_per_hour_high']:
        score += 20
        reasons.append(f'high uploaded bytes: {upload_mb:.1f} MB')

    if score >= 100:
        risk = 'CRITICAL'
    elif score >= 70:
        risk = 'HIGH'
    elif score >= 40:
        risk = 'MEDIUM'
    else:
        risk = 'LOW'
    return score, risk, reasons
