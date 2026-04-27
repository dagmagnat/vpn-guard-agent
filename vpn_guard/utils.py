from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Sequence


def run_command(args: Sequence[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, text=True, capture_output=True, check=check)


def human_bytes(num: int) -> str:
    value = float(num)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if value < 1024:
            return f'{value:.1f} {unit}'
        value /= 1024
    return f'{value:.1f} PB'


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
