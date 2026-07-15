"""Inferência do tipo de dispositivo a partir de fabricante, mDNS e hostname."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class DeviceType:
    label: str  # tag em maiúsculo, ex.: "CELULAR"
    color: str  # cor rich, ex.: "cyan"


# Tipos canônicos ---------------------------------------------------------- #
ROUTER = DeviceType("ROTEADOR", "red")
COMPUTER = DeviceType("COMPUTADOR", "bright_cyan")
PHONE = DeviceType("CELULAR", "green")
TV = DeviceType("TV/STREAM", "blue")
SPEAKER = DeviceType("ASSISTENTE", "yellow")
PRINTER = DeviceType("IMPRESSORA", "white")
SBC = DeviceType("SERVIDOR", "bright_magenta")
IOT = DeviceType("IOT", "bright_yellow")
GAME = DeviceType("CONSOLE", "bright_green")
WATCH = DeviceType("WEARABLE", "cyan")
UNKNOWN = DeviceType("DESCONHECIDO", "bright_black")


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
) -> DeviceType:
    """Combina os sinais disponíveis e retorna o tipo mais provável."""
    services = services or set()
    v = (vendor or "").lower()
    text = " ".join(filter(None, [hostname, mdns_name])).lower()

    # 1) Gateway é sempre o roteador.
    if gateway and ip == gateway:
        return ROUTER

    # 2) Sinais fortes de serviço mDNS.
    if _has(services, "ipp", "ipps", "pdl-datastream", "printer"):
        return PRINTER
    if _has(services, "googlecast"):
        # Chromecast/Nest Audio/Google TV. Se hostname sugere áudio -> speaker.
        if any(k in text for k in ("nest", "home", "mini", "audio", "speaker")):
            return SPEAKER
        return TV
    if _has(services, "amzn-wplay"):
        return TV  # Fire TV
    if _has(services, "amzn-alexa"):
        return SPEAKER

    # 3) Palavras-chave em hostname/mDNS.
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
        (("tv", "smart-tv", "bravia", "aquos"), TV),
        (("android",), PHONE),
        (("galaxy",), PHONE),
    ]
    for keys, dev in keyword_map:
        if any(k in text for k in keys):
            return dev

    # 4) Heurística por fabricante (OUI).
    vendor_map: list[tuple[tuple[str, ...], DeviceType]] = [
        (("amazon", "amazon technologies"), SPEAKER),
        (("google", "nest labs", "nest"), SPEAKER),
        (("roku",), TV),
        (("sony", "samsung electronics", "lg electronics", "tcl", "vizio", "hisense"), TV),
        (("raspberry pi", "raspberry"), SBC),
        (("espressif", "tuya", "sonoff", "shelly", "itead", "tp-link technologies"), IOT),
        (("nintendo", "sony interactive", "microsoft"), GAME),
        (
            ("xiaomi", "huawei", "oneplus", "motorola", "oppo", "vivo", "realme"),
            PHONE,
        ),
        (("apple",), COMPUTER),  # Apple genérico -> computador (celulares pegos acima)
        (("intel", "dell", "asus", "lenovo", "micro-star", "gigabyte", "hewlett"), COMPUTER),
    ]
    for keys, dev in vendor_map:
        if any(k in v for k in keys):
            # Refino: serviços de workstation/ssh reforçam computador.
            if dev is COMPUTER and _has(services, "workstation", "ssh", "smb"):
                return COMPUTER
            return dev

    # 5) Serviços genéricos de computador.
    if _has(services, "workstation", "ssh", "smb"):
        return COMPUTER

    return UNKNOWN
