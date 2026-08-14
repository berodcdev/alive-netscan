"""Sondas ativas de fingerprint: portas TCP, SSDP/UPnP e NetBIOS.

Complementam o mDNS (que só cobre bem o ecossistema Apple/Google) e resolvem a
maior parte dos hosts que apareceriam como DESCONHECIDO: celulares com MAC
aleatório, TVs, câmeras, NAS e máquinas Windows.

Tudo aqui é best-effort e com deadline: nenhuma sonda pode travar o scan.
"""

from __future__ import annotations

import re
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

# --------------------------------------------------------------------------- #
# Fingerprint por porta TCP
#
# Cada porta aberta é traduzida para um rótulo curto de serviço, que alimenta
# tanto a coluna SERVIÇOS quanto a classificação. As portas escolhidas são as
# que *identificam* o tipo de aparelho — não é um port scan geral.
# --------------------------------------------------------------------------- #
PORT_SERVICE: dict[int, str] = {
    22: "ssh",
    53: "dns",
    80: "http",
    139: "smb",
    443: "https",
    445: "smb",
    554: "rtsp",        # câmera IP / DVR
    631: "ipp",         # impressora
    1883: "mqtt",       # IoT
    3389: "rdp",        # Windows
    5555: "adb",        # Android com depuração
    5900: "vnc",
    8009: "cast",       # Chromecast / Google TV
    8096: "jellyfin",
    8291: "mikrotik",
    8883: "mqtt",
    9100: "jetdirect",  # impressora
    32400: "plex",
    37777: "dvr",       # Dahua/Intelbras
    62078: "ios",       # lockdownd — só iPhone/iPad escuta aqui
}

DEFAULT_PORTS: tuple[int, ...] = tuple(sorted(PORT_SERVICE))


def _port_open(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def probe_ports(
    ips: list[str],
    ports: tuple[int, ...] = DEFAULT_PORTS,
    timeout: float = 0.6,
    workers: int = 192,
    progress: Optional[Callable[[], None]] = None,
) -> dict[str, set[str]]:
    """Testa um punhado de portas por host. Retorna {ip: {serviço, ...}}."""
    if not ips:
        return {}
    found: dict[str, set[str]] = {}
    lock = threading.Lock()

    def check(pair: tuple[str, int]) -> None:
        ip, port = pair
        if _port_open(ip, port, timeout):
            with lock:
                found.setdefault(ip, set()).add(PORT_SERVICE[port])
        if progress:
            progress()

    pairs = [(ip, p) for ip in ips for p in ports]
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(pairs)))) as pool:
        list(pool.map(check, pairs))
    return found


# --------------------------------------------------------------------------- #
# SSDP / UPnP
#
# Um M-SEARCH multicast faz TVs, roteadores, consoles e IoT se anunciarem com
# nome e modelo — inclusive aparelhos que não falam mDNS.
# --------------------------------------------------------------------------- #
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

_M_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")


def _header(text: str, name: str) -> Optional[str]:
    m = re.search(rf"^{name}\s*:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    return m.group(1).strip() if m else None


def discover_ssdp(duration: float = 2.5, details: bool = True) -> dict[str, dict]:
    """Escuta respostas SSDP por ``duration`` segundos.

    Retorna {ip: {"name": str|None, "server": str|None, "model": str|None,
                  "types": set[str]}}.
    Se ``details``, busca o XML de descrição (LOCATION) para pegar o
    ``friendlyName`` — é o que dá nomes como "Sala (Samsung TV)".
    """
    results: dict[str, dict] = {}
    locations: dict[str, str] = {}

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.5)
        for _ in range(2):  # UDP: duas tentativas cobrem perda de pacote
            try:
                sock.sendto(_M_SEARCH, (SSDP_ADDR, SSDP_PORT))
            except OSError:
                break

        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            ip = addr[0]
            text = data.decode("utf-8", "replace")
            entry = results.setdefault(
                ip, {"name": None, "server": None, "model": None, "types": set()}
            )
            server = _header(text, "SERVER")
            if server and not entry["server"]:
                entry["server"] = server
            st = _header(text, "ST") or _header(text, "NT")
            if st:
                entry["types"].add(st)
            loc = _header(text, "LOCATION")
            if loc:
                locations.setdefault(ip, loc)
    except OSError:
        return results
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    if details and locations:
        _fill_upnp_details(results, locations)
    return results


def _fill_upnp_details(results: dict[str, dict], locations: dict[str, str]) -> None:
    """Baixa o XML de descrição UPnP de cada host (paralelo, com deadline)."""
    from urllib.request import urlopen

    def fetch(item: tuple[str, str]) -> None:
        ip, url = item
        try:
            with urlopen(url, timeout=1.5) as resp:  # noqa: S310 - URL vem da própria LAN
                xml = resp.read(65536).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - aparelho pode não servir o XML
            return
        entry = results.setdefault(
            ip,
            {
                "name": None,
                "server": None,
                "model": None,
                "manufacturer": None,
                "types": set(),
            },
        )
        friendly = _tag(xml, "friendlyName")
        model = _tag(xml, "modelName")
        manufacturer = _tag(xml, "manufacturer")
        dev_type = _tag(xml, "deviceType")
        if friendly and not entry["name"]:
            entry["name"] = friendly
        if manufacturer:
            entry["manufacturer"] = manufacturer
        if model or manufacturer:
            entry["model"] = " ".join(filter(None, [manufacturer, model]))
        if dev_type:
            entry["types"].add(dev_type)

    items = list(locations.items())
    with ThreadPoolExecutor(max_workers=max(1, min(16, len(items)))) as pool:
        pool.map(fetch, items)


def _tag(xml: str, tag: str) -> Optional[str]:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    val = re.sub(r"\s+", " ", m.group(1)).strip()
    return val or None


# --------------------------------------------------------------------------- #
# NetBIOS (UDP 137)
#
# Windows, Samba e NAS respondem o próprio nome mesmo sem DNS reverso — é o
# jeito mais barato de preencher a coluna HOST nessas redes.
# --------------------------------------------------------------------------- #
def _encode_netbios_name(name: str = "*") -> bytes:
    """Codificação de nome NetBIOS de 1º nível (16 bytes -> 32 chars)."""
    padded = name.encode("ascii")[:16].ljust(16, b"\x00")
    out = bytearray()
    for byte in padded:
        out.append(ord("A") + (byte >> 4))
        out.append(ord("A") + (byte & 0x0F))
    return bytes(out)


_NBSTAT_QUERY = (
    struct.pack(">HHHHHH", 0x8228, 0x0000, 1, 0, 0, 0)
    + b"\x20"
    + _encode_netbios_name("*")
    + b"\x00"
    + struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT, classe IN
)


def _parse_nbstat(data: bytes) -> Optional[str]:
    """Extrai o nome único de workstation da resposta NBSTAT."""
    try:
        i = 12  # header
        while i < len(data) and data[i] != 0:
            i += 1 + data[i]
        i += 1
        i += 2 + 2 + 4 + 2  # type, class, ttl, rdlength
        if i >= len(data):
            return None
        count = data[i]
        i += 1
        for _ in range(count):
            if i + 18 > len(data):
                break
            raw = data[i : i + 15].decode("ascii", "ignore").strip()
            suffix = data[i + 15]
            flags = struct.unpack(">H", data[i + 16 : i + 18])[0]
            i += 18
            is_group = bool(flags & 0x8000)
            # sufixo 0x00 + nome único = nome da máquina
            if not is_group and suffix == 0x00 and raw and raw != "__MSBROWSE__":
                return raw
    except (IndexError, struct.error):
        return None
    return None


def _netbios_one(ip: str, timeout: float) -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(_NBSTAT_QUERY, (ip, 137))
            data, _ = s.recvfrom(2048)
        return _parse_nbstat(data)
    except OSError:
        return None


def query_netbios(
    ips: list[str], timeout: float = 1.0, workers: int = 64
) -> dict[str, str]:
    """Consulta o nome NetBIOS de cada host. Retorna {ip: nome}."""
    if not ips:
        return {}
    names: dict[str, str] = {}
    lock = threading.Lock()

    def work(ip: str) -> None:
        name = _netbios_one(ip, timeout)
        if name:
            with lock:
                names[ip] = name

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ips)))) as pool:
        list(pool.map(work, ips))
    return names
