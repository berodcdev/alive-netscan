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
    return ["ping", "-c", "1", "-w", str(max(1, round(timeout))), ip]


def _ping_one(ip: str, timeout: float) -> Optional[dict]:
    """Pinga um host. Devolve {rtt, ttl} — dados que a resposta já carrega."""
    try:
        res = subprocess.run(
            _ping_cmd(ip, timeout),
            capture_output=True,
            text=True,
            timeout=timeout + 1.5,
            check=False,
        )
        if res.returncode != 0:
            return None
    except (OSError, subprocess.SubprocessError):
        return None

    out = res.stdout or ""
    info: dict = {}
    m = re.search(r"time[=<]([\d.]+)\s*ms", out)
    if m:
        info["rtt"] = float(m.group(1))
    # O TTL de volta revela a família do SO (64 unix/android, 128 windows,
    # 255 equipamento de rede) — vem de graça no mesmo pacote.
    m = re.search(r"\bttl[=\s](\d+)", out, re.IGNORECASE)
    if m:
        info["ttl"] = int(m.group(1))
    return info


def ping_sweep(
    network: ipaddress.IPv4Network,
    timeout: float = 1.0,
    workers: int = 64,
    progress: Optional[Callable[[], None]] = None,
) -> dict[str, dict]:
    """Pinga todos os hosts da subrede em paralelo. Retorna {ip: {rtt, ttl}}."""
    hosts = [str(h) for h in network.hosts()]
    alive: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(_ping_one, ip, timeout): ip for ip in hosts}
        for fut in as_completed(futures):
            res = fut.result()
            if res is not None:
                alive[futures[fut]] = res
            if progress:
                progress()
    return alive


def os_family_from_ttl(ttl: Optional[int]) -> Optional[str]:
    """Família de SO a partir do TTL de retorno (heurística clássica)."""
    if not ttl:
        return None
    # O TTL decresce 1 por salto; na LAN há 0 ou 1 salto até o host.
    if ttl > 200:
        return "rede/embarcado"  # 255: roteador, impressora, switch
    if ttl > 100:
        return "Windows"  # 128
    if ttl > 30:
        return "Linux/Apple"  # 64
    return None


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
# Estados de vizinho do `ip neigh`. Nem toda entrada da tabela ARP é um host
# presente: STALE é cache que o kernel ainda não revalidou — o aparelho pode ter
# saído da rede há horas. Tratar tudo como "vivo" faz a ferramenta afirmar uma
# presença que não verificou. FAILED/INCOMPLETE nem têm MAC.
_ARP_CONFIRMED = {"REACHABLE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
_ARP_DEAD = {"FAILED", "INCOMPLETE"}
_ARP_STATES = _ARP_CONFIRMED | _ARP_DEAD | {"STALE"}


def read_arp_entries() -> dict[str, dict]:
    """Lê a tabela ARP do SO. Retorna {ip: {"mac": str, "state": str}}.

    ``state`` é ``"confirmado"`` (o kernel falou com o vizinho nesta varredura)
    ou ``"stale"`` (só cache). O ``arp -a`` do macOS não expõe o estado, então
    lá tudo vira ``"confirmado"``.
    """
    table: dict[str, dict] = {}

    if shutil.which("ip") and not IS_MAC:
        out = _run(["ip", "neigh"])
        # ex.: "192.168.0.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        # Flags opcionais (router, proxy, extern_learn) podem vir antes do
        # estado, então procuramos o estado entre os tokens finais.
        for line in out.splitlines():
            m = re.search(
                r"^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+"
                r"([0-9a-fA-F:]{17})\s*(.*)$",
                line.strip(),
            )
            if not m:
                continue
            mac = normalize_mac(m.group(2))
            if not mac:
                continue
            state = next(
                (t for t in m.group(3).upper().split() if t in _ARP_STATES), ""
            )
            if state in _ARP_DEAD:
                continue
            table[m.group(1)] = {
                "mac": mac,
                "state": "stale" if state == "STALE" else "confirmado",
            }
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
                table[m.group(1)] = {"mac": mac, "state": "confirmado"}
    return table


def read_arp_table() -> dict[str, str]:
    """Só {ip: mac_normalizado}, sem o estado do vizinho."""
    return {ip: entry["mac"] for ip, entry in read_arp_entries().items()}


# --------------------------------------------------------------------------- #
# Orquestração
# --------------------------------------------------------------------------- #
def scan(
    network: ipaddress.IPv4Network,
    *,
    use_nmap: bool = True,
    use_ping: bool = True,
    timeout: float = 1.0,
    workers: int = 64,
    progress: Optional[Callable[[], None]] = None,
    local_ip: Optional[str] = None,
    gateway: Optional[str] = None,
) -> list[dict]:
    """Descobre hosts vivos e associa MACs. Retorna lista de {ip, mac, rtt, ttl, via}.

    Estratégia híbrida: usa nmap quando disponível e habilitado; sempre
    complementa com ping sweep + tabela ARP para máxima cobertura.
    """
    alive: dict[str, str] = {}  # ip -> como foi descoberto
    macs: dict[str, str] = {}
    stats: dict[str, dict] = {}

    if use_nmap and has_nmap():
        n_alive, n_macs = nmap_scan(str(network))
        for ip in n_alive:
            alive[ip] = "nmap"
        macs.update(n_macs)

    # Ping sweep (rápido, popula o ARP, cobre hosts que o nmap perdeu). Em modo
    # passivo não roda: nenhum pacote sai daqui para os hosts.
    if use_ping:
        pinged = ping_sweep(network, timeout=timeout, workers=workers, progress=progress)
        for ip, info in pinged.items():
            alive[ip] = "ping"
            stats[ip] = info
    elif progress:
        progress()

    # Garantir gateway e host local na lista.
    for extra in (local_ip, gateway):
        if extra and ipaddress.ip_address(extra) in network:
            alive.setdefault(extra, "local")

    # A tabela ARP é fonte de hosts, não só de MACs: o ping sweep dispara um ARP
    # request para cada IP, então quem responde ARP mas ignora ICMP (Windows com
    # firewall, IoT, impressora) fica registrado aqui — e estaria invisível.
    arp = read_arp_entries()
    arp_states: dict[str, str] = {}
    for ip, entry in arp.items():
        try:
            in_net = ipaddress.ip_address(ip) in network
        except ValueError:
            continue
        if not in_net:
            continue
        macs.setdefault(ip, entry["mac"])
        arp_states[ip] = entry["state"]
        alive.setdefault(ip, "arp")

    hosts = [
        {
            "ip": ip,
            "mac": macs.get(ip),
            "rtt": stats.get(ip, {}).get("rtt"),
            "ttl": stats.get(ip, {}).get("ttl"),
            "via": via,
            "arp_state": arp_states.get(ip),
        }
        for ip, via in alive.items()
    ]
    hosts.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return hosts
