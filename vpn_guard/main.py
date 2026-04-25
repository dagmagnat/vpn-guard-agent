from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from pathlib import Path
import json
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from vpn_guard.config import load_config
from vpn_guard.models import ClientStats
from vpn_guard.scoring import score_client
from vpn_guard.utils import human_bytes
from vpn_guard.collectors import conntrack, xray, wireguard, openvpn
from vpn_guard.firewall import nftables, iptables

app = typer.Typer(help='VPN Guard Agent: anti-abuse monitor for VPN/proxy servers')
console = Console()


def merge_all(*items: dict[str, ClientStats]) -> dict[str, ClientStats]:
    merged: dict[str, ClientStats] = {}
    for dataset in items:
        for ip, stats in dataset.items():
            if not ip:
                continue
            if ip not in merged:
                merged[ip] = stats
            else:
                merged[ip].merge(stats)
    return merged


def collect_all(config_path: str | None = None) -> tuple[dict[str, ClientStats], object]:
    cfg = load_config(config_path)
    data = merge_all(
        conntrack.collect(cfg.blocklists, cfg.whitelist),
        xray.collect(cfg.xray_access_log, cfg.blocklists, cfg.whitelist),
        wireguard.collect(),
        openvpn.collect(cfg.openvpn_status_log),
    )
    return data, cfg


def print_clients(data: dict[str, ClientStats], cfg, only_suspicious: bool = False, limit: int = 50):
    table = Table(title='VPN Guard Agent — client activity')
    table.add_column('Risk')
    table.add_column('Score', justify='right')
    table.add_column('Client IP')
    table.add_column('Source')
    table.add_column('TCP', justify='right')
    table.add_column('UDP', justify='right')
    table.add_column('Dest', justify='right')
    table.add_column('RX')
    table.add_column('TX')
    table.add_column('Reason')

    rows = []
    for client in data.values():
        score, risk, reasons = score_client(client, cfg.thresholds)
        if only_suspicious and score < 40:
            continue
        rows.append((score, risk, client, reasons))

    rows.sort(key=lambda x: x[0], reverse=True)
    for score, risk, client, reasons in rows[:limit]:
        table.add_row(
            risk,
            str(score),
            client.ip,
            client.source,
            str(client.tcp_connections),
            str(client.udp_connections),
            str(client.unique_destinations_count),
            human_bytes(client.rx_bytes),
            human_bytes(client.tx_bytes),
            '; '.join(reasons[:2]) or '-',
        )
    console.print(table)


@app.command()
def scan(
    config: str | None = typer.Option(None, '--config', '-c', help='Path to config.yml'),
    suspicious: bool = typer.Option(False, '--suspicious', '-s', help='Show only suspicious clients'),
    limit: int = typer.Option(50, '--limit', '-n', help='Rows limit'),
):
    """Scan active VPN/proxy activity and print a risk table."""
    data, cfg = collect_all(config)
    if not data:
        console.print('[yellow]No data collected. Check permissions and installed tools: conntrack, wg, nft, xray logs.[/yellow]')
        return
    print_clients(data, cfg, suspicious, limit)


@app.command()
def top(config: str | None = typer.Option(None, '--config', '-c')):
    """Show the most suspicious clients."""
    data, cfg = collect_all(config)
    print_clients(data, cfg, True, 30)


@app.command('init-firewall')
def init_firewall(config: str | None = typer.Option(None, '--config', '-c')):
    """Create nftables table/set/chains used by vpn-guard."""
    cfg = load_config(config)
    if cfg.firewall_backend != 'nftables':
        console.print('[yellow]init-firewall is only needed for nftables backend.[/yellow]')
        return
    for line in nftables.init(cfg.nft_table, cfg.nft_set):
        console.print(line)


@app.command()
def block(ip: str, config: str | None = typer.Option(None, '--config', '-c')):
    """Block a client IP."""
    cfg = load_config(config)
    if cfg.firewall_backend == 'iptables':
        result = iptables.block(ip)
    else:
        nftables.init(cfg.nft_table, cfg.nft_set)
        result = nftables.block(ip, cfg.nft_table, cfg.nft_set)
    console.print(f'[red]{result}[/red]')


@app.command()
def unblock(ip: str, config: str | None = typer.Option(None, '--config', '-c')):
    """Unblock a client IP."""
    cfg = load_config(config)
    if cfg.firewall_backend == 'iptables':
        result = iptables.unblock(ip)
    else:
        result = nftables.unblock(ip, cfg.nft_table, cfg.nft_set)
    console.print(f'[green]{result}[/green]')


@app.command('abuse-check')
def abuse_check(config: str | None = typer.Option(None, '--config', '-c')):
    """Show clients that touched configured abuse/blacklist networks."""
    data, cfg = collect_all(config)
    hits = []
    for client in data.values():
        if client.blacklist_hits > 0:
            score, risk, reasons = score_client(client, cfg.thresholds)
            hits.append((score, risk, client, reasons))
    if not hits:
        console.print('[green]No blacklist hits found in current data/log window.[/green]')
        return
    print_clients({x[2].ip: x[2] for x in hits}, cfg, False, 100)


@app.command()
def report(
    config: str | None = typer.Option(None, '--config', '-c'),
    output: Path = typer.Option(Path('vpn-guard-report.json'), '--output', '-o'),
):
    """Export JSON report for hosting support or internal audit."""
    data, cfg = collect_all(config)
    payload = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'config': str(cfg.config_path) if cfg.config_path else None,
        'clients': [],
    }
    for client in data.values():
        score, risk, reasons = score_client(client, cfg.thresholds)
        payload['clients'].append({
            'ip': client.ip,
            'source': client.source,
            'score': score,
            'risk': risk,
            'tcp_connections': client.tcp_connections,
            'udp_connections': client.udp_connections,
            'unique_destinations': client.unique_destinations_count,
            'blacklist_hits': client.blacklist_hits,
            'rx_bytes': client.rx_bytes,
            'tx_bytes': client.tx_bytes,
            'reasons': reasons,
            'notes': client.notes[:10],
        })
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
    console.print(f'[green]Report written to {output}[/green]')


@app.command()
def menu(config: str | None = typer.Option(None, '--config', '-c')):
    """Interactive menu."""
    while True:
        console.print(Panel('1) Scan\n2) Suspicious only\n3) Abuse check\n4) Block IP\n5) Unblock IP\n6) Init firewall\n0) Exit', title='VPN Guard Agent'))
        choice = typer.prompt('Select')
        if choice == '1':
            scan(config=config)
        elif choice == '2':
            top(config=config)
        elif choice == '3':
            abuse_check(config=config)
        elif choice == '4':
            ip = typer.prompt('IP to block')
            block(ip, config=config)
        elif choice == '5':
            ip = typer.prompt('IP to unblock')
            unblock(ip, config=config)
        elif choice == '6':
            init_firewall(config=config)
        elif choice == '0':
            raise typer.Exit()
        else:
            console.print('[yellow]Unknown choice[/yellow]')

if __name__ == '__main__':
    app()
