"""Descoberta de hosts vivos: ping sweep paralelo, wrapper nmap e tabela ARP."""

from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

IS_MAC = platform.system() == "Darwin"


def _run(cmd: list[str], timeout: float = 30.0) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return out.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


# --------------------------------------------------------------------------- #
# Normalização de MAC
# --------------------------------------------------------------------------- #
def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """Normaliza para o formato ``aa:bb:cc:dd:ee:ff`` minúsculo."""
    if not mac:
        return None
    hexs = re.findall(r"[0-9a-fA-F]{1,2}", mac)
    if len(hexs) != 6:
        return None
    parts = [h.zfill(2).lower() for h in hexs]
    if all(p == "00" for p in parts) or all(p == "ff" for p in parts):
        return None
    return ":".join(parts)


def is_random_mac(mac: Optional[str]) -> bool:
    """True se o MAC é *locally administered* — ou seja, aleatório/privado.

    iOS, Android e macOS sortearam um MAC por rede ("endereço WiFi privado").
    Esses MACs ligam o bit 0x02 do primeiro octeto, então o segundo dígito hex
    cai em {2, 6, a, e}. Não existe OUI para consultar: nenhum fabricante é
    dono da faixa. Vale distinguir isso de "não achei o fabricante".
    """
    if not mac:
        return False
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    # bit 1 = locally administered; bit 0 = multicast (não deveria aparecer aqui)
    return bool(first & 0b10) and not bool(first & 0b1)


# --------------------------------------------------------------------------- #
# Ping (por host)
# --------------------------------------------------------------------------- #
def _ping_cmd(ip: str, timeout: float) -> list[str]:
    if IS_MAC:
        # -W em milissegundos no macOS
        return ["ping", "-c", "1", "-t", "1", "-W", str(int(timeout * 1000)), ip]
    # Linux: -W em segundos (inteiro, mínimo 1)
    return ["ping", "-c", "1", "-w", str(max(1, int(round(timeout)))), ip]


def _ping_one(ip: str, timeout: float) -> Optional[str]:
    try:
        res = subprocess.run(
            _ping_cmd(ip, timeout),
            capture_output=True,
            text=True,
            timeout=timeout + 1.5,
            check=False,
        )
        return ip if res.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def ping_sweep(
    network: ipaddress.IPv4Network,
    timeout: float = 1.0,
    workers: int = 64,
    progress: Optional[Callable[[], None]] = None,
) -> set[str]:
    """Pinga todos os hosts da subrede em paralelo. Retorna IPs que responderam."""
    hosts = [str(h) for h in network.hosts()]
    alive: set[str] = set()
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(_ping_one, ip, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                alive.add(res)
            if progress:
                progress()
    return alive


# --------------------------------------------------------------------------- #
# nmap (opcional)
# --------------------------------------------------------------------------- #
def has_nmap() -> bool:
    return shutil.which("nmap") is not None


def nmap_scan(cidr: str) -> tuple[set[str], dict[str, str]]:
    """Roda ``nmap -sn`` e devolve (ips_vivos, {ip: mac})."""
    out = _run(["nmap", "-sn", "-n", cidr], timeout=120.0)
    alive: set[str] = set()
    macs: dict[str, str] = {}
    cur_ip: Optional[str] = None
    for line in out.splitlines():
        m = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            cur_ip = m.group(1)
            alive.add(cur_ip)
            continue
        m = re.search(r"MAC Address: ([0-9A-Fa-f:]{17})", line)
        if m and cur_ip:
            mac = normalize_mac(m.group(1))
            if mac:
                macs[cur_ip] = mac
    return alive, macs


# --------------------------------------------------------------------------- #
# Tabela ARP
# --------------------------------------------------------------------------- #
def read_arp_table() -> dict[str, str]:
    """Lê a tabela ARP do SO. Retorna {ip: mac_normalizado}."""
    table: dict[str, str] = {}

    if shutil.which("ip") and not IS_MAC:
        out = _run(["ip", "neigh"])
        # ex.: "192.168.0.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        for line in out.splitlines():
            m = re.search(
                r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-fA-F:]{17})",
                line.strip(),
            )
            if m:
                mac = normalize_mac(m.group(2))
                if mac:
                    table[m.group(1)] = mac
        if table:
            return table

    # macOS e fallback Linux: arp -a
    out = _run(["arp", "-a"])
    # ex.: "router (192.168.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
    for line in out.splitlines():
        m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line)
        if m:
            mac = normalize_mac(m.group(2))
            if mac:
                table[m.group(1)] = mac
    return table


# --------------------------------------------------------------------------- #
# Orquestração
# --------------------------------------------------------------------------- #
def scan(
    network: ipaddress.IPv4Network,
    *,
    use_nmap: bool = True,
    timeout: float = 1.0,
    workers: int = 64,
    progress: Optional[Callable[[], None]] = None,
    local_ip: Optional[str] = None,
    gateway: Optional[str] = None,
) -> list[dict]:
    """Descobre hosts vivos e associa MACs. Retorna lista de {ip, mac}.

    Estratégia híbrida: usa nmap quando disponível e habilitado; sempre
    complementa com ping sweep + tabela ARP para máxima cobertura.
    """
    alive: set[str] = set()
    macs: dict[str, str] = {}

    if use_nmap and has_nmap():
        n_alive, n_macs = nmap_scan(str(network))
        alive |= n_alive
        macs.update(n_macs)

    # Ping sweep sempre roda (rápido, popula ARP, cobre hosts que o nmap perdeu).
    alive |= ping_sweep(network, timeout=timeout, workers=workers, progress=progress)

    # Garantir gateway e host local na lista.
    for extra in (local_ip, gateway):
        if extra and ipaddress.ip_address(extra) in network:
            alive.add(extra)

    # Enriquecer MACs a partir da tabela ARP (não sobrescreve MACs do nmap).
    arp = read_arp_table()
    for ip, mac in arp.items():
        if ip in alive:
            macs.setdefault(ip, mac)

    hosts = [{"ip": ip, "mac": macs.get(ip)} for ip in alive]
    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return hosts
