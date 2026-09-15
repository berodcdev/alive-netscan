"""Enriquecimento dos hosts: DNS reverso, mDNS/Bonjour e fabricante (OUI)."""

from __future__ import annotations

import socket
import threading
import time
from typing import Callable, Optional


# --------------------------------------------------------------------------- #
# Utilitário: executar com deadline rígido via threads daemon.
#
# socket.gethostbyaddr() e o download da base OUI podem bloquear por muito
# tempo sem respeitar timeout. Threads daemon nos permitem impor um teto de
# tempo e abandonar as que travaram (não impedem a saída do processo).
# --------------------------------------------------------------------------- #
def _run_bounded(
    tasks: list[tuple[str, Callable[[], Optional[str]]]],
    deadline_s: float,
) -> dict[str, str]:
    """Roda cada task em uma thread daemon; coleta o que terminar até o deadline."""
    results: dict[str, str] = {}
    lock = threading.Lock()

    def worker(key: str, fn: Callable[[], Optional[str]]) -> None:
        try:
            val = fn()
        except Exception:  # noqa: BLE001
            return
        if val:
            with lock:
                results[key] = val

    threads = [
        threading.Thread(target=worker, args=(k, fn), daemon=True) for k, fn in tasks
    ]
    for t in threads:
        t.start()
    deadline = time.monotonic() + deadline_s
    for t in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        t.join(remaining)
    return results


# --------------------------------------------------------------------------- #
# DNS reverso
# --------------------------------------------------------------------------- #
def _reverse_dns(ip: str) -> Optional[str]:
    """Nome PTR do host, ou None.

    Roteadores domésticos (ZTE, Huawei, parte dos TP-Link) respondem o próprio
    IP como PTR. Isso não é nome: aceito, ele ocupa a coluna mais larga da
    tabela repetindo o dado que já está na coluna ao lado — e ainda entra na
    classificação como se fosse um sinal.
    """
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return None
    if not name or name.strip().rstrip(".") == ip:
        return None
    return name


def resolve_hostnames(ips: list[str], timeout_total: float = 5.0) -> dict[str, str]:
    """Resolve nomes via DNS reverso em paralelo, com teto de tempo. {ip: hostname}."""
    if not ips:
        return {}
    tasks = [(ip, (lambda ip=ip: _reverse_dns(ip))) for ip in ips]
    return _run_bounded(tasks, deadline_s=timeout_total)


# --------------------------------------------------------------------------- #
# Fabricante via OUI (mac-vendor-lookup, base offline)
# --------------------------------------------------------------------------- #
def lookup_vendors(macs: list[str], timeout_total: float = 15.0) -> dict[str, str]:
    """Mapeia MAC -> fabricante usando base OUI offline. {mac: vendor}.

    O primeiro uso pode baixar a base OUI (uma vez). Todo o trabalho roda em
    uma thread daemon com teto de tempo, então um download lento nunca trava o
    processo — apenas resulta em menos fabricantes identificados.
    """
    macs = [m for m in macs if m]
    if not macs:
        return {}
    try:
        from mac_vendor_lookup import MacLookup  # import tardio (opcional)
    except ImportError:
        return {}

    result: dict[str, str] = {}

    def work() -> None:
        try:
            lookup = MacLookup()
            for mac in macs:
                try:
                    vendor = lookup.lookup(mac)
                    if vendor:
                        result[mac] = vendor
                except Exception:  # noqa: BLE001 - MAC sem correspondência
                    continue
        except Exception:  # noqa: BLE001 - falha ao carregar a base
            pass

    th = threading.Thread(target=work, daemon=True)
    th.start()
    th.join(timeout_total)
    return dict(result)


# --------------------------------------------------------------------------- #
# mDNS / Bonjour via zeroconf
# --------------------------------------------------------------------------- #
MDNS_SERVICES = [
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_homekit._tcp.local.",
    "_hap._tcp.local.",
    "_amzn-wplay._tcp.local.",
    "_amzn-alexa._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_printer._tcp.local.",
    "_workstation._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_device-info._tcp.local.",
    # iPhones/iPads anunciam companion-link mesmo com MAC aleatório: é uma das
    # poucas formas de confirmar um aparelho Apple que se esconde.
    "_companion-link._tcp.local.",
    "_rdlink._tcp.local.",
]


# Chaves de TXT que carregam o modelo do aparelho, por serviço:
#   model  -> _device-info/_airplay ("MacBookAir10,1", "AppleTV6,2")
#   md     -> _googlecast/_hap      ("Chromecast Ultra", "Nest Mini")
#   ty/usb_MDL/product -> _ipp      ("HP DeskJet 2700 series")
#   am     -> _raop/_airplay        (modelo do hardware Apple)
_MODEL_KEYS = ("model", "md", "am", "ty", "usb_MDL", "product")

# Prefixos de código de modelo da Apple -> nome legível.
_APPLE_MODELS = (
    ("MacBookAir", "MacBook Air"), ("MacBookPro", "MacBook Pro"),
    ("MacBook", "MacBook"), ("Macmini", "Mac mini"), ("MacStudio", "Mac Studio"),
    ("MacPro", "Mac Pro"), ("iMac", "iMac"), ("Mac", "Mac"),
    ("iPhone", "iPhone"), ("iPad", "iPad"), ("Watch", "Apple Watch"),
    ("AppleTV", "Apple TV"), ("AudioAccessory", "HomePod"),
)


def humanize_model(raw: Optional[str]) -> Optional[str]:
    """'MacBookAir10,1' -> 'MacBook Air'. Outros modelos passam limpos."""
    if not raw:
        return None
    s = raw.strip().strip("()")
    for prefix, nice in _APPLE_MODELS:
        if s.startswith(prefix) and (len(s) == len(prefix) or s[len(prefix)].isdigit()):
            return nice
    return s


def _extract_model(props: dict) -> Optional[str]:
    for key in _MODEL_KEYS:
        val = props.get(key)
        if val:
            model = humanize_model(val)
            # "AirPort" e afins não dizem nada; modelo tem que ser específico.
            if model and model.lower() not in ("unknown", "generic"):
                return model
    return None


def discover_mdns(duration: float = 3.0) -> dict[str, dict]:
    """Navega serviços mDNS por ``duration`` segundos.

    Retorna {ip: {"name": str|None, "services": set[str], "model": str|None,
                  "props": dict}}.
    """
    try:
        from zeroconf import ServiceBrowser, ServiceListener, Zeroconf
    except ImportError:
        return {}

    # O zeroconf abre um socket por interface e loga traceback quando alguma não
    # tem rota (VPN, túnel, interface caída). Isso não é erro nosso e não pode
    # sujar a saída da ferramenta.
    import logging

    logging.getLogger("zeroconf").setLevel(logging.CRITICAL)

    import time as _time  # local: evita depender de time no topo

    results: dict[str, dict] = {}

    def _record(
        ip: str,
        name: Optional[str],
        service_type: str,
        props: Optional[dict] = None,
    ) -> None:
        entry = results.setdefault(
            ip, {"name": None, "services": set(), "model": None, "props": {}}
        )
        short = service_type.split(".")[0].lstrip("_")
        entry["services"].add(short)
        if props:
            entry["props"].update(props)
            entry["model"] = entry["model"] or _extract_model(props)
            # 'fn' (friendly name) do Chromecast é melhor que o nome da instância.
            if props.get("fn") and not entry["name"]:
                entry["name"] = props["fn"]
        if name:
            # Nome instância antes do tipo, ex.: "Sala de Estar._googlecast._tcp"
            friendly = name.split("." + service_type.split(".")[0])[0].rstrip(".")
            # Serviços raop/airplay prefixam com o MAC: "AABBCCDDEEFF@Nome".
            if "@" in friendly:
                friendly = friendly.split("@", 1)[1]
            # Preferir um nome mais descritivo do que o já registrado.
            if friendly and (not entry["name"] or len(friendly) > len(entry["name"])):
                entry["name"] = friendly

    class _Listener(ServiceListener):
        def add_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            self._handle(zc, type_, name)

        def update_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            self._handle(zc, type_, name)

        def remove_service(self, zc: "Zeroconf", type_: str, name: str) -> None:
            pass

        def _handle(self, zc: "Zeroconf", type_: str, name: str) -> None:
            try:
                info = zc.get_service_info(type_, name, timeout=1500)
            except Exception:  # noqa: BLE001
                return
            if not info:
                return
            # TXT records: onde mora o modelo real do aparelho.
            props: dict[str, str] = {}
            try:
                for k, v in (info.properties or {}).items():
                    key = k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)
                    if isinstance(v, bytes):
                        val = v.decode("utf-8", "replace")
                    elif v is None:
                        continue
                    else:
                        val = str(v)
                    if val:
                        props[key] = val
            except Exception:  # noqa: BLE001 - TXT malformado não pode derrubar o scan
                props = {}
            for addr in info.parsed_addresses():
                if ":" in addr:  # ignora IPv6 por ora
                    continue
                _record(addr, info.name, type_, props)

    zc = None
    try:
        zc = Zeroconf()
        listener = _Listener()
        browsers = [ServiceBrowser(zc, svc, listener) for svc in MDNS_SERVICES]
        _time.sleep(duration)
        for b in browsers:
            try:
                b.cancel()
            except Exception:  # noqa: BLE001
                pass
    except Exception:  # noqa: BLE001 - mDNS é best-effort
        return results
    finally:
        if zc is not None:
            try:
                zc.close()
            except Exception:  # noqa: BLE001
                pass
    return results
