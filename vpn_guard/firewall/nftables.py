from __future__ import annotations

from vpn_guard.utils import run_command


def init(table: str = 'vpn_guard', set_name: str = 'blocked_ips') -> list[str]:
    commands = [
        ['nft', 'add', 'table', 'inet', table],
        ['nft', 'add', 'set', 'inet', table, set_name, '{', 'type', 'ipv4_addr;', 'flags', 'interval;', '}'],
        ['nft', 'add', 'chain', 'inet', table, 'input', '{', 'type', 'filter', 'hook', 'input', 'priority', '0;', 'policy', 'accept;', '}'],
        ['nft', 'add', 'chain', 'inet', table, 'forward', '{', 'type', 'filter', 'hook', 'forward', 'priority', '0;', 'policy', 'accept;', '}'],
        ['nft', 'add', 'chain', 'inet', table, 'output', '{', 'type', 'filter', 'hook', 'output', 'priority', '0;', 'policy', 'accept;', '}'],
        ['nft', 'add', 'rule', 'inet', table, 'input', 'ip', 'saddr', f'@{set_name}', 'drop'],
        ['nft', 'add', 'rule', 'inet', table, 'forward', 'ip', 'saddr', f'@{set_name}', 'drop'],
        ['nft', 'add', 'rule', 'inet', table, 'output', 'ip', 'daddr', f'@{set_name}', 'drop'],
    ]
    out: list[str] = []
    for cmd in commands:
        proc = run_command(cmd)
        if proc.returncode == 0:
            out.append('OK: ' + ' '.join(cmd))
        elif 'File exists' not in proc.stderr and 'already exists' not in proc.stderr:
            out.append('WARN: ' + proc.stderr.strip())
    return out


def block(ip: str, table: str = 'vpn_guard', set_name: str = 'blocked_ips') -> str:
    proc = run_command(['nft', 'add', 'element', 'inet', table, set_name, '{', ip, '}'])
    return proc.stderr.strip() or proc.stdout.strip() or f'blocked {ip}'


def unblock(ip: str, table: str = 'vpn_guard', set_name: str = 'blocked_ips') -> str:
    proc = run_command(['nft', 'delete', 'element', 'inet', table, set_name, '{', ip, '}'])
    return proc.stderr.strip() or proc.stdout.strip() or f'unblocked {ip}'
