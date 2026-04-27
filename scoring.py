from __future__ import annotations

from vpn_guard.utils import run_command


def block(ip: str) -> str:
    a = run_command(['iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'])
    if a.returncode != 0:
        run_command(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
    b = run_command(['iptables', '-C', 'FORWARD', '-s', ip, '-j', 'DROP'])
    if b.returncode != 0:
        run_command(['iptables', '-A', 'FORWARD', '-s', ip, '-j', 'DROP'])
    return f'blocked {ip} via iptables'


def unblock(ip: str) -> str:
    run_command(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'])
    run_command(['iptables', '-D', 'FORWARD', '-s', ip, '-j', 'DROP'])
    return f'unblocked {ip} via iptables'
