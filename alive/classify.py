"""Inferência do tipo de dispositivo a partir de fabricante, mDNS, portas e UPnP.

A função ``classify`` devolve ``(DeviceType, inferred)``. ``inferred=True``
significa "melhor palpite" — a UI marca esses com ``?`` para não fingir certeza
onde há apenas probabilidade (o caso clássico é o celular de MAC aleatório).
"""

from __future__ import annotations

import re
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

# Ordem de leitura da rede com --sort type: infraestrutura primeiro, aparelho
# pessoal depois, desconhecido por último. Alfabética não diz nada.
_TYPE_ORDER = (
    ROUTER, NETDEV, SBC, PRINTER, CAMERA, COMPUTER, PHONE, TV, SPEAKER,
    GAME, WATCH, IOT, UNKNOWN,
)
TYPE_RANK = {d.label: i for i, d in enumerate(_TYPE_ORDER)}

# Serviços que, sozinhos, provam o tipo do aparelho. Muitos vêm da enumeração
# profunda de mDNS: cada tipo de serviço DNS-SD é um rótulo que denuncia o tipo.
_DECISIVE: list[tuple[tuple[str, ...], DeviceType]] = [
    (("ios",), PHONE),          # porta 62078 (lockdownd): só iPhone/iPad
    (("adb",), PHONE),          # porta 5555: Android com depuração
    (("ipp", "ipps", "pdl-datastream", "printer", "jetdirect", "uscan", "scanner"),
     PRINTER),
    (("amzn-alexa",), SPEAKER),
    (("amzn-wplay",), TV),
    (("sonos", "soundtouch"), SPEAKER),
    (("dvr", "axis-video", "onvif"), CAMERA),  # DVR, câmera Axis (mDNS) ou ONVIF
    (("mikrotik",), NETDEV),
    (("plex", "jellyfin"), SBC),
    (("esphomelib", "esphome"), IOT),
    (("octoprint",), IOT),      # impressora 3D
    (("hue", "philips-hue", "philipshue"), IOT),  # ponte Philips Hue
    (("home-assistant", "hass"), SBC),
]

# Fabricantes de equipamento de rede: se não é o gateway, é AP/repetidor/switch.
_NET_VENDORS = (
    "tp-link", "mercusys", "d-link", "ubiquiti", "aruba", "mikrotik", "netgear",
    "zyxel", "cisco", "ruckus", "keenetic", "tenda", "intelbras",
    # ONT/CPE de operadora e os repetidores que vêm junto.
    "zte", "huawei", "sagemcom", "askey", "arris", "technicolor", "fiberhome",
    "nokia", "cig", "parks", "datacom", "multilaser",
)


def _has(services: set[str], *names: str) -> bool:
    return any(n in services for n in names)


def _text_has(text: str, *keys: str) -> bool:
    """Casa palavra inteira em hostname/banner/UPnP.

    Chaves com hífen na borda (``cam-``, ``-ap``) continuam sendo fragmento,
    que é como foram escritas. As demais passam a exigir palavra inteira: sem
    isso um banner com "watchdog" virava WEARABLE por conter "watch", e
    "netvision" virava TV por conter "tv".
    """
    for k in keys:
        if k.startswith("-") or k.endswith("-"):
            if k in text:
                return True
        elif re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", text):
            return True
    return False


def _vendor_has(vendor: str, *keys: str) -> bool:
    """Casa fabricante por palavra inteira, não por pedaço do nome.

    Substring puro classificava a **Intelbras** (câmeras e roteadores) como
    COMPUTADOR, porque "intel" cabe dentro de "intelbras" — e a Intelbras é
    uma das marcas mais comuns numa rede doméstica brasileira.
    """
    return any(
        re.search(rf"(?<![a-z0-9]){re.escape(k)}(?![a-z0-9])", vendor) for k in keys
    )


# Software de servidor web embarcado, sysDescr do SNMP ou CN do certificado ->
# o aparelho que costuma emitir esse texto.
_BANNER_HINTS: list[tuple[tuple[str, ...], DeviceType]] = [
    (("goahead", "hikvision", "dahua", "webs", "jaws", "ipcamera", "axis"), CAMERA),
    (
        (
            "dropbear", "openwrt", "routeros", "mikrotik", "dd-wrt", "lighttpd/1.4.4",
            "cisco", "juniper", "aruba", "fortigate", "fortinet", "ubnt", "edgeos",
            "unifi", "zyxel",
        ),
        NETDEV,
    ),
    (
        ("cups", "jetdirect", "hp http server", "hp ethernet", "laserjet",
         "officejet", "kyocera", "lexmark", "brother"),
        PRINTER,
    ),
    (("ubuntu", "debian", "raspbian", "raspberry", "synology", "qnap", "truenas"), SBC),
]


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
    model: Optional[str] = None,
    banners: Optional[dict] = None,
    os_family: Optional[str] = None,
    snmp: Optional[dict] = None,
    tls: Optional[dict] = None,
) -> tuple[DeviceType, bool]:
    """Combina os sinais disponíveis e retorna (tipo mais provável, é_palpite)."""
    services = services or set()
    upnp = upnp or {}
    banners = banners or {}
    snmp = snmp or {}
    tls = tls or {}
    v = (vendor or "").lower()
    upnp_text = " ".join(
        filter(None, [upnp.get("server"), upnp.get("model"), upnp.get("name")])
    ).lower()
    upnp_types = " ".join(upnp.get("types") or ()).lower()
    banner_text = " ".join(str(x) for x in banners.values() if x).lower()
    # sysDescr do SNMP e CN/SAN do certificado costumam dizer o modelo em texto
    # claro ("HP LaserJet", "RouterOS", "Synology") — fortes sinais de tipo.
    snmp_text = " ".join(filter(None, [snmp.get("descr"), snmp.get("name")])).lower()
    tls_text = " ".join(
        filter(None, [tls.get("subject_cn"), tls.get("issuer"), *(tls.get("san") or [])])
    ).lower()
    banner_text = " ".join(filter(None, [banner_text, snmp_text, tls_text]))
    text = " ".join(
        filter(None, [hostname, mdns_name, model, upnp_text, banner_text])
    ).lower()

    # 1) Gateway é sempre o roteador.
    if gateway and ip == gateway:
        return ROUTER, False

    # 2) O modelo anunciado por mDNS é o sinal mais confiável que existe:
    #    o próprio aparelho dizendo o que é ("MacBook Air", "Apple TV").
    if model:
        m = model.lower()
        model_map: list[tuple[tuple[str, ...], DeviceType]] = [
            (("iphone", "ipad", "galaxy", "pixel"), PHONE),
            (("macbook", "imac", "mac mini", "mac studio", "mac pro"), COMPUTER),
            (("apple tv", "chromecast", "fire tv", "shield", "roku"), TV),
            (("homepod", "nest mini", "nest audio", "nest hub", "echo"), SPEAKER),
            (("apple watch", "galaxy watch"), WATCH),
            (("deskjet", "laserjet", "officejet", "ecotank", "pixma"), PRINTER),
        ]
        for keys, dev in model_map:
            if any(k in m for k in keys):
                return dev, False

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
        (("nintendo",), GAME),
        (("raspberrypi", "raspberry"), SBC),
        (("printer", "hp-", "epson", "brother", "canon"), PRINTER),
        (("camera", "cam-", "ipcam", "dvr", "nvr", "vip-", "vhd"), CAMERA),
        (("tv", "smart-tv", "bravia", "aquos"), TV),
        (("repetidor", "repeater", "extender", "access-point", "-ap"), NETDEV),
        (("android",), PHONE),
        (("galaxy",), PHONE),
    ]
    for keys, dev in keyword_map:
        if _text_has(text, *keys):
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
        # Antes de "sony": "Sony Interactive Entertainment" é o PlayStation, e
        # casaria com a entrada de TV se ela viesse primeiro.
        (("nintendo", "sony interactive", "microsoft"), GAME),
        (("sony", "samsung electronics", "lg electronics", "tcl", "vizio", "hisense"), TV),
        (("raspberry pi", "raspberry"), SBC),
        (("hikvision", "dahua", "reolink", "ezviz"), CAMERA),
        (("espressif", "tuya", "sonoff", "shelly", "itead", "multilaser"), IOT),
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
        if _vendor_has(v, *keys):
            return dev, False

    # 5b) Banner de servidor web/SSH embarcado.
    if banner_text:
        for keys, dev in _BANNER_HINTS:
            if any(k in banner_text for k in keys):
                return dev, False

    # 6) Equipamento de rede (não é o gateway, então é AP/repetidor/switch).
    if _vendor_has(v, *_NET_VENDORS):
        # A Intelbras vende de câmera a roteador; sem outro sinal, fica no palpite.
        return NETDEV, True

    # 7) Serviços genéricos de sistema operacional completo. Compartilhamento de
    #    arquivos e acesso remoto anunciados por mDNS também denunciam um SO
    #    completo (afpovertcp/sftp-ssh/daap = Apple/Unix; teamviewer/nvstream = PC).
    if _has(services, "rdp", "smb", "afp", "vnc"):
        return COMPUTER, False
    if _has(services, "afpovertcp", "sftp-ssh", "daap", "teamviewer", "nvstream"):
        return COMPUTER, False
    if _has(services, "workstation", "ssh"):
        return COMPUTER, not _has(services, "workstation")

    # 8) MAC aleatório sem nenhum outro sinal: quase sempre celular com
    #    "endereço WiFi privado" ligado (padrão no iOS e no Android).
    if is_random_mac(mac):
        return PHONE, True

    # 9) Último recurso: a família de SO que o TTL denuncia.
    if os_family == "Windows":
        return COMPUTER, True
    if os_family == "rede/embarcado":
        return NETDEV, True

    return UNKNOWN, False
