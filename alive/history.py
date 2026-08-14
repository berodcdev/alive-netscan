"""Histórico entre execuções: marca quem é novo na rede e quem saiu.

O estado fica em ``$XDG_STATE_HOME/alive/history.json`` (por padrão
``~/.local/state/alive/history.json``), uma entrada por subrede.

Detalhe importante: aparelhos com MAC aleatório trocam de MAC a cada rede (e,
no iOS/Android, periodicamente). Usar o MAC como chave faria todo celular
parecer "novo" a cada scan — então para esses a chave é o IP.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .scanner import is_random_mac

VERSION = 1


def state_path() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "alive" / "history.json"


def host_key(host: dict) -> str:
    """Identidade estável de um host entre scans."""
    mac = host.get("mac")
    if mac and not is_random_mac(mac):
        return f"mac:{mac}"
    return f"ip:{host['ip']}"


@dataclass
class Diff:
    """Comparação com o scan anterior da mesma subrede."""

    new_keys: set[str] = field(default_factory=set)
    gone: list[dict] = field(default_factory=list)
    previous_time: Optional[float] = None
    first_run: bool = True

    @property
    def ago(self) -> Optional[str]:
        """Quanto tempo desde o scan anterior, em texto curto."""
        if not self.previous_time:
            return None
        secs = max(0, int(time.time() - self.previous_time))
        if secs < 60:
            return f"{secs}s"
        if secs < 3600:
            return f"{secs // 60}min"
        if secs < 86400:
            return f"{secs // 3600}h"
        return f"{secs // 86400}d"


def _load_all() -> dict:
    try:
        with state_path().open(encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and data.get("version") == VERSION:
            return data
    except (OSError, ValueError):
        pass
    return {"version": VERSION, "networks": {}}


def compare(hosts: list[dict], cidr: Optional[str]) -> Diff:
    """Compara a lista atual com o último scan salvo desta subrede."""
    if not cidr:
        return Diff()
    entry = _load_all().get("networks", {}).get(cidr)
    if not isinstance(entry, dict):
        return Diff()

    before = {h.get("key"): h for h in entry.get("hosts", []) if isinstance(h, dict)}
    now = {host_key(h): h for h in hosts}
    gone = [h for k, h in before.items() if k not in now]
    return Diff(
        new_keys={k for k in now if k not in before},
        gone=gone,
        previous_time=entry.get("time"),
        first_run=False,
    )


def save(hosts: list[dict], cidr: Optional[str]) -> None:
    """Grava o snapshot atual. Silencioso em qualquer falha de I/O."""
    if not cidr:
        return
    data = _load_all()
    data.setdefault("networks", {})[cidr] = {
        "time": time.time(),
        "hosts": [
            {
                "key": host_key(h),
                "ip": h["ip"],
                "mac": h.get("mac"),
                "name": h.get("name"),
                "type": h["device"].label if h.get("device") else None,
            }
            for h in hosts
        ],
    }
    try:
        path = state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False)
        tmp.replace(path)
    except OSError:
        pass
