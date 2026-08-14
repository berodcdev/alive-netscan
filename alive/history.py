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
    """Compara a lista atual com o último scan salvo desta subrede.

    Também anota em cada host ``first_seen``, ``seen_count`` e ``presence``
    (fração dos scans desta rede em que o host apareceu) — é o que responde
    "esse aparelho é de casa ou apareceu agora?".
    """
    if not cidr:
        return Diff()
    entry = _load_all().get("networks", {}).get(cidr)
    if not isinstance(entry, dict):
        return Diff()

    before = {h.get("key"): h for h in entry.get("hosts", []) if isinstance(h, dict)}
    total_scans = int(entry.get("total_scans") or 1)
    now = {host_key(h): h for h in hosts}

    prev_time = entry.get("time")
    for key, h in now.items():
        prev = before.get(key)
        if prev:
            # Snapshots gravados por versões antigas não têm first_seen: o
            # horário do próprio snapshot é a melhor aproximação.
            h["first_seen"] = (
                prev.get("first_seen") or prev.get("last_seen") or prev_time
            )
            h["seen_count"] = int(prev.get("seen_count") or 1) + 1
        else:
            h["first_seen"] = None  # visto agora pela primeira vez
            h["seen_count"] = 1
        h["presence"] = min(1.0, h["seen_count"] / max(1, total_scans + 1))

    gone = [h for k, h in before.items() if k not in now]
    return Diff(
        new_keys={k for k in now if k not in before},
        gone=gone,
        previous_time=entry.get("time"),
        first_run=False,
    )


def seen_label(host: dict, first_run: bool = False) -> str:
    """Texto curto da coluna VISTO: '1ª vez', 'sempre' ou 'há 3d'."""
    if first_run:
        return "—"
    first = host.get("first_seen")
    if not first:
        return "1ª vez"
    if (host.get("presence") or 0) >= 0.8 and (host.get("seen_count") or 0) >= 3:
        return "sempre"
    secs = max(0, int(time.time() - first))
    if secs < 3600:
        return f"há {max(1, secs // 60)}min"
    if secs < 86400:
        return f"há {secs // 3600}h"
    if secs < 86400 * 30:
        return f"há {secs // 86400}d"
    return f"há {secs // (86400 * 30)}mes"


def save(hosts: list[dict], cidr: Optional[str]) -> None:
    """Grava o snapshot atual. Silencioso em qualquer falha de I/O."""
    if not cidr:
        return
    data = _load_all()
    now = time.time()
    previous = data.get("networks", {}).get(cidr) or {}
    data.setdefault("networks", {})[cidr] = {
        "time": now,
        "total_scans": int(previous.get("total_scans") or 0) + 1,
        "hosts": [
            {
                "key": host_key(h),
                "ip": h["ip"],
                "mac": h.get("mac"),
                "name": h.get("name"),
                "type": h["device"].label if h.get("device") else None,
                "first_seen": h.get("first_seen") or now,
                "last_seen": now,
                "seen_count": int(h.get("seen_count") or 1),
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
