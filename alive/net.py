"""Descoberta da rede local: interface, IP, subrede (CIDR), gateway e SSID.

Todas as funções degradam com elegância: se uma ferramenta do SO não existir
ou o parsing falhar, retornam ``None`` em vez de lançar exceção.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Optional

IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"


@dataclass
class NetInfo:
    """Informações da rede local detectada."""

    interface: Optional[str]
    ip: Optional[str]
    network: Optional[ipaddress.IPv4Network]
    gateway: Optional[str]
    ssid: Optional[str]

    @property
    def cidr(self) -> Optional[str]:
        return str(self.network) if self.network else None


def _run(cmd: list[str], timeout: float = 4.0) -> str:
    """Executa um comando e devolve stdout (string vazia em qualquer erro)."""
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return out.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return ""


def get_local_ip() -> Optional[str]:
    """Descobre o IP local abrindo um socket UDP (não envia pacotes, sem root)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1.0)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# Interface + gateway padrão
# --------------------------------------------------------------------------- #
def get_default_interface_and_gateway() -> tuple[Optional[str], Optional[str]]:
    """Retorna (interface, gateway) da rota padrão."""
    if IS_MAC:
        return _mac_default_route()
    return _linux_default_route()


def _mac_default_route() -> tuple[Optional[str], Optional[str]]:
    out = _run(["route", "-n", "get", "default"])
    iface = gw = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("interface:"):
            iface = line.split(":", 1)[1].strip()
        elif line.startswith("gateway:"):
            gw = line.split(":", 1)[1].strip()
    return iface, gw


def _linux_default_route() -> tuple[Optional[str], Optional[str]]:
    # Preferir `ip`, cair para `route -n`.
    if shutil.which("ip"):
        out = _run(["ip", "route", "show", "default"])
        # ex.: "default via 192.168.0.1 dev wlan0 proto dhcp ..."
        m = re.search(r"default via (\S+) dev (\S+)", out)
        if m:
            return m.group(2), m.group(1)
    out = _run(["route", "-n"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[0] == "0.0.0.0":
            return parts[7], parts[1]
    return None, None


# Interfaces virtuais: VPN, túneis, containers. Quando a rota padrão sai por uma
# delas, a "rede local" detectada é a da VPN — não a WiFi que o usuário quer ver.
_VIRTUAL_PREFIXES = (
    "utun", "tun", "tap", "ppp", "wg", "ipsec", "gpd", "tailscale", "zt",
    "docker", "br-", "veth", "vmnet", "virbr",
)


def is_virtual_interface(iface: Optional[str]) -> bool:
    """True para VPN/túnel/bridge virtual (não é a rede WiFi/LAN física)."""
    if not iface:
        return False
    return iface.lower().startswith(_VIRTUAL_PREFIXES)


def get_interface_ip(iface: Optional[str]) -> Optional[str]:
    """IP IPv4 atribuído a uma interface específica."""
    if not iface:
        return None
    if IS_LINUX and shutil.which("ip"):
        out = _run(["ip", "-o", "-f", "inet", "addr", "show", iface])
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    out = _run(["ifconfig", iface])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    return None


def get_gateway_for_interface(iface: Optional[str]) -> Optional[str]:
    """Gateway da rota padrão de uma interface específica (best-effort)."""
    if not iface:
        return None
    if IS_MAC:
        out = _run(["route", "-n", "get", "-ifscope", iface, "default"])
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("gateway:"):
                return line.split(":", 1)[1].strip()
        return None
    if shutil.which("ip"):
        out = _run(["ip", "route", "show", "default", "dev", iface])
        m = re.search(r"default via (\S+)", out)
        if m:
            return m.group(1)
    return None


# --------------------------------------------------------------------------- #
# Máscara / rede
# --------------------------------------------------------------------------- #
def get_network_for_interface(
    iface: Optional[str], ip: Optional[str]
) -> Optional[ipaddress.IPv4Network]:
    """Deriva o CIDR da interface. Fallback: /24 sobre o IP local."""
    netmask = None
    if iface:
        netmask = _mac_netmask(iface) if IS_MAC else _linux_netmask(iface)

    if ip and netmask:
        try:
            return ipaddress.ip_network(f"{ip}/{netmask}", strict=False)  # type: ignore[return-value]
        except ValueError:
            pass

    if ip:
        try:
            return ipaddress.ip_network(f"{ip}/24", strict=False)  # type: ignore[return-value]
        except ValueError:
            return None
    return None


def _mac_netmask(iface: str) -> Optional[str]:
    out = _run(["ifconfig", iface])
    # ex.: "inet 192.168.0.42 netmask 0xffffff00 broadcast 192.168.0.255"
    m = re.search(r"inet \S+ netmask (0x[0-9a-fA-F]+)", out)
    if m:
        hexmask = int(m.group(1), 16)
        return str(ipaddress.IPv4Address(hexmask))
    return None


def _linux_netmask(iface: str) -> Optional[str]:
    if shutil.which("ip"):
        out = _run(["ip", "-o", "-f", "inet", "addr", "show", iface])
        # ex.: "3: wlan0    inet 192.168.0.42/24 brd ..."
        m = re.search(r"inet \S+/(\d+)", out)
        if m:
            return m.group(1)  # prefixo já serve para ip_network
    out = _run(["ifconfig", iface])
    m = re.search(r"netmask (\d+\.\d+\.\d+\.\d+)", out)
    if m:
        return m.group(1)
    return None


# --------------------------------------------------------------------------- #
# SSID (best-effort)
# --------------------------------------------------------------------------- #
def get_ssid(iface: Optional[str]) -> Optional[str]:
    """Nome da rede WiFi conectada. Best-effort; None se indisponível."""
    if IS_MAC:
        return _mac_ssid(iface)
    return _linux_ssid(iface)


def _mac_ssid(iface: Optional[str]) -> Optional[str]:
    if iface:
        out = _run(["networksetup", "-getairportnetwork", iface])
        # "Current Wi-Fi Network: MinhaRede"
        m = re.search(r"Current Wi-Fi Network:\s*(.+)", out)
        if m:
            return m.group(1).strip()
        # macOS 14+ esconde o SSID de várias APIs sem permissão de localização;
        # o resumo do ipconfig ainda o expõe, sem sudo.
        out = _run(["ipconfig", "getsummary", iface])
        m = re.search(r"^\s*SSID\s*:\s*(.+)$", out, re.MULTILINE)
        if m:
            return m.group(1).strip()
    # Fallback: system_profiler (mais lento, mas robusto em macOS novo)
    out = _run(["system_profiler", "SPAirPortDataType"], timeout=8.0)
    m = re.search(r"Current Network Information:\s*\n\s*(.+?):\s*\n", out)
    if m:
        return m.group(1).strip()
    return None


def _linux_ssid(iface: Optional[str] = None) -> Optional[str]:
    if shutil.which("iwgetid"):
        out = _run(["iwgetid", "-r"]).strip()
        if out:
            return out
    if shutil.which("nmcli"):
        out = _run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"])
        for line in out.splitlines():
            if line.startswith("yes:"):
                return line.split(":", 1)[1].strip() or None
    # `iw` funciona em adaptadores USB fora do NetworkManager (ex.: wlx...),
    # onde iwgetid/nmcli costumam não responder.
    if iface and shutil.which("iw"):
        out = _run(["iw", "dev", iface, "link"])
        m = re.search(r"^\s*SSID:\s*(.+)$", out, re.MULTILINE)
        if m:
            return m.group(1).strip() or None
    if iface and shutil.which("wpa_cli"):
        out = _run(["wpa_cli", "-i", iface, "status"])
        m = re.search(r"^ssid=(.+)$", out, re.MULTILINE)
        if m:
            return m.group(1).strip() or None
    return None


# --------------------------------------------------------------------------- #
# MAC da interface local
# --------------------------------------------------------------------------- #
def get_interface_mac(iface: Optional[str]) -> Optional[str]:
    """MAC da própria interface. A tabela ARP nunca lista a máquina local."""
    if not iface:
        return None
    if IS_LINUX:
        try:
            with open(f"/sys/class/net/{iface}/address", encoding="utf-8") as fh:
                mac = fh.read().strip()
            if mac:
                return mac.lower()
        except OSError:
            pass
        if shutil.which("ip"):
            out = _run(["ip", "link", "show", iface])
            m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", out)
            if m:
                return m.group(1).lower()
    out = _run(["ifconfig", iface])
    m = re.search(r"\bether\s+([0-9a-fA-F:]{17})", out)
    if m:
        return m.group(1).lower()
    return None


def discover() -> NetInfo:
    """Reúne todas as informações da rede local."""
    iface, gateway = get_default_interface_and_gateway()
    ip = get_local_ip()
    network = get_network_for_interface(iface, ip)
    ssid = get_ssid(iface)
    return NetInfo(interface=iface, ip=ip, network=network, gateway=gateway, ssid=ssid)
