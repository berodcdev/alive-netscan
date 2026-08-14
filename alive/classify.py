"""Inferência do tipo de dispositivo a partir de fabricante, mDNS, portas e UPnP.

A função ``classify`` devolve ``(DeviceType, inferred)``. ``inferred=True``
significa "melhor palpite" — a UI marca esses com ``?`` para não fingir certeza
onde há apenas probabilidade (o caso clássico é o celular de MAC aleatório).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .scanner import is_random_mac


@dataclass
class DeviceType:
    label: str  # tag em maiúsculo, ex.: "CELULAR"
    color: str  # cor rich, ex.: "cyan"


# Tipos canônicos ---------------------------------------------------------- #
ROUTER = DeviceType("ROTEADOR", "red")
NETDEV = DeviceType("REDE", "bright_red")  # AP, repetidor, switch gerenciado
COMPUTER = DeviceType("COMPUTADOR", "bright_cyan")
PHONE = DeviceType("CELULAR", "green")
TV = DeviceType("TV/STREAM", "blue")
SPEAKER = DeviceType("ASSISTENTE", "yellow")
PRINTER = DeviceType("IMPRESSORA", "white")
CAMERA = DeviceType("CAMERA", "magenta")
SBC = DeviceType("SERVIDOR", "bright_magenta")
IOT = DeviceType("IOT", "bright_yellow")
GAME = DeviceType("CONSOLE", "bright_green")
WATCH = DeviceType("WEARABLE", "cyan")
UNKNOWN = DeviceType("DESCONHECIDO", "bright_black")

# Serviços que, sozinhos, provam o tipo do aparelho.
_DECISIVE: list[tuple[tuple[str, ...], DeviceType]] = [
    (("ios",), PHONE),          # porta 62078 (lockdownd): só iPhone/iPad
    (("adb",), PHONE),          # porta 5555: Android com depuração
    (("ipp", "ipps", "pdl-datastream", "printer", "jetdirect"), PRINTER),
    (("amzn-alexa",), SPEAKER),
    (("amzn-wplay",), TV),
    (("dvr",), CAMERA),         # porta 37777: DVR Dahua/Intelbras
    (("mikrotik",), NETDEV),
    (("plex", "jellyfin"), SBC),
]

# Fabricantes de equipamento de rede: se não é o gateway, é AP/repetidor/switch.
_NET_VENDORS = (
    "tp-link", "mercusys", "d-link", "ubiquiti", "aruba", "mikrotik", "netgear",
    "zyxel", "cisco", "ruckus", "keenetic", "tenda", "intelbras",
)


def _has(services: set[str], *names: str) -> bool:
    return any(n in services for n in names)


def classify(
    *,
    ip: str,
    mac: Optional[str],
    vendor: Optional[str],
    hostname: Optional[str],
    mdns_name: Optional[str],
    services: Optional[set[str]],
    gateway: Optional[str],
    upnp: Optional[dict] = None,
) -> tuple[DeviceType, bool]:
    """Combina os sinais disponíveis e retorna (tipo mais provável, é_palpite)."""
    services = services or set()
    upnp = upnp or {}
    v = (vendor or "").lower()
    upnp_text = " ".join(
        filter(None, [upnp.get("server"), upnp.get("model"), upnp.get("name")])
    ).lower()
    upnp_types = " ".join(upnp.get("types") or ()).lower()
    text = " ".join(filter(None, [hostname, mdns_name, upnp_text])).lower()

    # 1) Gateway é sempre o roteador.
    if gateway and ip == gateway:
        return ROUTER, False

    # 2) Serviços/portas decisivos.
    for keys, dev in _DECISIVE:
        if _has(services, *keys):
            return dev, False
    if _has(services, "googlecast", "cast"):
        # Chromecast/Nest Audio/Google TV. Hostname de áudio -> assistente.
        if any(k in text for k in ("nest", "home", "mini", "audio", "speaker")):
            return SPEAKER, False
        return TV, False
    if _has(services, "rtsp"):
        # RTSP é câmera na esmagadora maioria dos casos (mas media servers usam).
        return CAMERA, not _has(services, "dvr")

    # 3) Palavras-chave em hostname / mDNS / UPnP.
    keyword_map: list[tuple[tuple[str, ...], DeviceType]] = [
        (("iphone",), PHONE),
        (("ipad",), PHONE),
        (("macbook", "imac", "mac-mini", "macmini", "mac-studio"), COMPUTER),
        (("apple-tv", "appletv"), TV),
        (("apple-watch", "watch"), WATCH),
        (("echo", "alexa"), SPEAKER),
        (("chromecast", "google-nest", "nest-", "googlehome"), SPEAKER),
        (("firetv", "fire-tv", "fire-stick"), TV),
        (("roku",), TV),
        (("playstation", "ps4", "ps5"), GAME),
        (("xbox",), GAME),
        (("nintendo", "switch"), GAME),
        (("raspberrypi", "raspberry"), SBC),
        (("printer", "hp-", "epson", "brother", "canon"), PRINTER),
        (("camera", "cam-", "ipcam", "dvr", "nvr", "vip-", "vhd"), CAMERA),
        (("tv", "smart-tv", "bravia", "aquos"), TV),
        (("repetidor", "repeater", "extender", "access-point", "-ap"), NETDEV),
        (("android",), PHONE),
        (("galaxy",), PHONE),
    ]
    for keys, dev in keyword_map:
        if any(k in text for k in keys):
            return dev, False

    # 4) Tipo de dispositivo declarado via UPnP.
    if "internetgatewaydevice" in upnp_types:
        return NETDEV, False
    if "printer" in upnp_types:
        return PRINTER, False
    if "mediarenderer" in upnp_types or "mediaserver" in upnp_types:
        return TV, "mediarenderer" not in upnp_types

    # 5) Heurística por fabricante (OUI).
    vendor_map: list[tuple[tuple[str, ...], DeviceType]] = [
        (("amazon",), SPEAKER),
        (("google", "nest labs"), SPEAKER),
        (("roku",), TV),
        (("sony", "samsung electronics", "lg electronics", "tcl", "vizio", "hisense"), TV),
        (("raspberry pi", "raspberry"), SBC),
        (("hikvision", "dahua", "reolink", "ezviz"), CAMERA),
        (("espressif", "tuya", "sonoff", "shelly", "itead", "multilaser"), IOT),
        (("nintendo", "sony interactive", "microsoft"), GAME),
        (("xiaomi", "huawei", "oneplus", "motorola", "oppo", "vivo", "realme"), PHONE),
        (("apple",), COMPUTER),  # Apple genérico -> computador (celulares acima)
        (
            (
                "intel", "dell", "asus", "lenovo", "micro-star", "gigabyte",
                "hewlett", "positivo", "acer", "clevo",
            ),
            COMPUTER,
        ),
    ]
    for keys, dev in vendor_map:
        if any(k in v for k in keys):
            return dev, False

    # 6) Equipamento de rede (não é o gateway, então é AP/repetidor/switch).
    if any(k in v for k in _NET_VENDORS):
        # A Intelbras vende de câmera a roteador; sem outro sinal, fica no palpite.
        return NETDEV, True

    # 7) Serviços genéricos de sistema operacional completo.
    if _has(services, "rdp", "smb", "afp", "vnc"):
        return COMPUTER, False
    if _has(services, "workstation", "ssh"):
        return COMPUTER, not _has(services, "workstation")

    # 8) MAC aleatório sem nenhum outro sinal: quase sempre celular com
    #    "endereço WiFi privado" ligado (padrão no iOS e no Android).
    if is_random_mac(mac):
        return PHONE, True

    return UNKNOWN, False
