"""Sondas ativas de fingerprint: portas TCP, SSDP/UPnP e NetBIOS.

Complementam o mDNS (que só cobre bem o ecossistema Apple/Google) e resolvem a
maior parte dos hosts que apareceriam como DESCONHECIDO: celulares com MAC
aleatório, TVs, câmeras, NAS e máquinas Windows.

Tudo aqui é best-effort e com deadline: nenhuma sonda pode travar o scan.
"""

from __future__ import annotations

import html
import random
import re
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

# --------------------------------------------------------------------------- #
# Fingerprint por porta TCP
#
# Cada porta aberta é traduzida para um rótulo curto de serviço, que alimenta
# tanto a coluna SERVIÇOS quanto a classificação. As portas escolhidas são as
# que *identificam* o tipo de aparelho — não é um port scan geral.
# --------------------------------------------------------------------------- #
PORT_SERVICE: dict[int, str] = {
    21: "ftp",          # texto puro — vira achado
    22: "ssh",
    23: "telnet",       # texto puro — vira achado
    53: "dns",
    80: "http",
    139: "smb",
    443: "https",
    445: "smb",
    554: "rtsp",        # câmera IP / DVR
    631: "ipp",         # impressora
    8443: "https",      # painel HTTPS alternativo (comum em câmera/NVR/NAS)
    8554: "rtsp",       # stream RTSP alternativo (comum em câmera)
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
    jitter: float = 0.0,
    shuffle: bool = False,
) -> dict[str, set[str]]:
    """Testa um punhado de portas por host. Retorna {ip: {serviço, ...}}.

    ``shuffle``/``jitter`` (modo stealth) embaralham a ordem dos pares (ip,
    porta) e atrasam cada conexão, dissolvendo a rajada de SYNs que denuncia
    uma varredura de portas.
    """
    if not ips:
        return {}
    found: dict[str, set[str]] = {}
    lock = threading.Lock()

    def check(pair: tuple[str, int]) -> None:
        if jitter > 0:
            time.sleep(random.uniform(0, jitter))
        ip, port = pair
        if _port_open(ip, port, timeout):
            with lock:
                found.setdefault(ip, set()).add(PORT_SERVICE[port])
        if progress:
            progress()

    pairs = [(ip, p) for ip in ips for p in ports]
    if shuffle:
        random.shuffle(pairs)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(pairs)))) as pool:
        list(pool.map(check, pairs))
    return found


# --------------------------------------------------------------------------- #
# Banners
#
# Só rodam contra portas que a sonda anterior já encontrou abertas — é uma
# conexão a mais por host, e é o que separa "COMPUTADOR" de "Ubuntu 24.04" ou
# "CAMERA" de "Intelbras VIP 1230".
# --------------------------------------------------------------------------- #
_CLEAN_RE = re.compile(r"[\x00-\x1f\x7f]")


def _clean(text: Optional[str], limit: int = 60) -> Optional[str]:
    if not text:
        return None
    # A página do aparelho serve o <title> com entidades HTML: sem decodificar,
    # o modelo "Z13220" chega na tela como "&#90;&#49;&#51;&#50;&#50;&#48;".
    s = _CLEAN_RE.sub(" ", html.unescape(text)).strip()
    s = re.sub(r"\s+", " ", s)
    if not s:
        return None
    return s[:limit].strip()


# Títulos de página que não dizem nada sobre o aparelho. Promovidos a DETALHE,
# ocupam a coluna com ruído: o roteador aparecia como "302 Found".
_JUNK_TITLES = frozenset({
    "document", "index", "index of /", "untitled", "untitled document",
    "home", "home page", "login", "welcome", "new page", "page", "test",
    "null", "undefined", "error", "redirect", "redirecting", "loading",
})
_STATUS_TITLE = re.compile(r"^[1-5]\d\d\s+\w")     # "302 Found", "401 Unauthorized"
_NUMERIC_TITLE = re.compile(r"^[\d\s,.;:_+-]+$")     # "0,1,2"


def useful_title(title: Optional[str]) -> Optional[str]:
    """Filtra <title> que não identifica o aparelho."""
    if not title:
        return None
    t = title.strip()
    if len(t) < 3 or t.lower() in _JUNK_TITLES:
        return None
    if _STATUS_TITLE.match(t) or _NUMERIC_TITLE.match(t):
        return None
    return t


def _read_socket(ip: str, port: int, payload: Optional[bytes], timeout: float) -> str:
    """Abre, envia (opcional) e lê a primeira resposta. '' em qualquer erro."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if payload:
                s.sendall(payload)
            chunks = []
            total = 0
            while total < 8192:
                try:
                    data = s.recv(4096)
                except (socket.timeout, OSError):
                    break
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if not payload:  # banners passivos (SSH) vêm na primeira leitura
                    break
            return b"".join(chunks).decode("utf-8", "replace")
    except OSError:
        return ""


def _http_banner(ip: str, port: int, tls: bool, timeout: float) -> dict:
    """Server header + <title> da página inicial. Em TLS, também o certificado.

    O certificado do aparelho é ouro de reconhecimento: o CN e os nomes
    alternativos (SAN) carregam o hostname interno e o nome da organização, e a
    validade denuncia certificado vencido. A conexão TLS já acontece de qualquer
    forma para ler o banner — pegar o certificado é de graça no mesmo handshake.
    """
    request = (
        f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: alive\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    cert_info: dict = {}
    if not tls:
        text = _read_socket(ip, port, request, timeout)
    else:
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip) as s:
                    s.settimeout(timeout)
                    # DER do certificado apresentado, mesmo sem validar a cadeia.
                    der = s.getpeercert(binary_form=True)
                    if der:
                        cert_info = parse_cert_der(der)
                    s.sendall(request)
                    text = s.recv(8192).decode("utf-8", "replace")
        except (OSError, ValueError):
            return {"tls": cert_info} if cert_info else {}
    out: dict = {}
    if text:
        server = _header(text, "Server")
        if server:
            out["http_server"] = _clean(server, 40)
        m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
        if m:
            out["http_title"] = useful_title(_clean(m.group(1), 40))
    out = {k: v for k, v in out.items() if v}
    if cert_info:
        out["tls"] = cert_info
    return out


def _rtsp_probe(ip: str, port: int, timeout: float) -> dict:
    """OPTIONS + DESCRIBE numa porta RTSP. {rtsp_server, rtsp_auth} ou {}.

    O DESCRIBE diz se o stream exige senha (401/403) ou responde aberto (200).
    Lemos só a linha de status — nunca a mídia.
    """
    text = _read_socket(
        ip, port,
        f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".encode(),
        timeout,
    )
    if not text:
        return {}
    out: dict = {}
    server = _header(text, "Server")
    if server:
        out["rtsp_server"] = _clean(server, 40)
    desc = _read_socket(
        ip, port,
        (f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 2\r\n"
         "Accept: application/sdp\r\n\r\n").encode(),
        timeout,
    )
    status = desc.split("\r\n", 1)[0] if desc else ""
    if " 401" in status or " 403" in status:
        out["rtsp_auth"] = "required"
    elif " 200" in status:
        out["rtsp_auth"] = "open"
    return out


def grab_banners(
    services_by_ip: dict[str, set[str]], timeout: float = 1.5, workers: int = 32
) -> dict[str, dict]:
    """Coleta banners de quem tem SSH/HTTP/HTTPS/RTSP aberto. {ip: {...}}."""
    targets = {
        ip: svcs
        for ip, svcs in (services_by_ip or {}).items()
        if svcs & {"ssh", "http", "https", "rtsp"}
    }
    if not targets:
        return {}
    result: dict[str, dict] = {}
    lock = threading.Lock()

    def work(item: tuple[str, set[str]]) -> None:
        ip, svcs = item
        found: dict = {}
        if "ssh" in svcs:
            # O servidor SSH se apresenta sozinho: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3"
            line = _read_socket(ip, 22, None, timeout).splitlines()
            if line and line[0].startswith("SSH-"):
                found["ssh"] = _clean(line[0].split("-", 2)[-1], 40)
        if "http" in svcs:
            found.update(_http_banner(ip, 80, False, timeout))
        elif "https" in svcs:
            # Tenta a 443 e, se não veio nada, a 8443 (câmera/NVR/NAS costumam
            # servir o painel HTTPS ali).
            found.update(
                _http_banner(ip, 443, True, timeout)
                or _http_banner(ip, 8443, True, timeout)
            )
        if "rtsp" in svcs:
            # 554 é o padrão; 8554 é o alternativo comum em câmera.
            for porta in (554, 8554):
                info = _rtsp_probe(ip, porta, timeout)
                if info:
                    found.update(info)
                    break
        if found:
            with lock:
                result[ip] = found

    items = list(targets.items())
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
        list(pool.map(work, items))
    return result


# --------------------------------------------------------------------------- #
# ASN.1 / DER — leitor mínimo, compartilhado por certificado X.509 e SNMP
#
# Os dois protocolos codificam em TLV (tag, length, value). Um único leitor de
# TLV e um decodificador de OID servem aos dois, sem dependência externa.
# --------------------------------------------------------------------------- #
def _tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    """Lê um campo TLV em ``data[i:]``. Retorna (tag, valor, próximo índice)."""
    tag = data[i]
    n = data[i + 1]
    i += 2
    if n & 0x80:  # forma longa: os 7 bits baixos dizem quantos octetos de tamanho
        k = n & 0x7F
        n = int.from_bytes(data[i : i + k], "big")
        i += k
    return tag, data[i : i + n], i + n


def _oid_to_str(raw: bytes) -> str:
    """Decodifica o valor de um OID DER para a forma pontilhada."""
    if not raw:
        return ""
    arcs = [str(raw[0] // 40), str(raw[0] % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            arcs.append(str(val))
            val = 0
    return ".".join(arcs)


def _encode_oid(dotted: str) -> bytes:
    """Codifica um OID pontilhado em DER (só o valor, sem tag/length)."""
    parts = [int(x) for x in dotted.split(".")]
    out = bytearray([40 * parts[0] + parts[1]])
    for n in parts[2:]:
        if n < 0x80:
            out.append(n)
            continue
        stack = []
        while n:
            stack.append(n & 0x7F)
            n >>= 7
        stack.reverse()
        for j in range(len(stack) - 1):
            stack[j] |= 0x80
        out.extend(stack)
    return bytes(out)


# --------------------------------------------------------------------------- #
# Certificado TLS
#
# Sem validar a cadeia (aparelhos usam cert self-signed), extraímos o que
# identifica o aparelho e denuncia problema: CN do dono, CN/organização do
# emissor, nomes alternativos (SAN — hostname interno vaza aqui), validade e se
# é auto-assinado. Tudo parseado do DER na mão, para não puxar dependência.
# --------------------------------------------------------------------------- #
_OID_CN = "2.5.4.3"           # commonName
_OID_ORG = "2.5.4.10"         # organizationName
_OID_SAN = "2.5.29.17"        # subjectAltName


def _name_fields(der_name: bytes) -> dict[str, str]:
    """Extrai {oid: valor} de um Name X.509 (SEQUENCE OF RDN)."""
    fields: dict[str, str] = {}
    i = 0
    while i < len(der_name):
        _, rdn, i = _tlv(der_name, i)  # SET
        j = 0
        while j < len(rdn):
            _, atv, j = _tlv(rdn, j)  # SEQUENCE {oid, value}
            _, oid_val, k = _tlv(atv, 0)
            _, val, _ = _tlv(atv, k)
            oid = _oid_to_str(oid_val)
            fields.setdefault(oid, val.decode("utf-8", "replace").strip())
    return fields


def _san_dns(ext_value: bytes) -> list[str]:
    """Nomes dNSName ([2] IA5String) de um subjectAltName."""
    names: list[str] = []
    _, seq, _ = _tlv(ext_value, 0)  # GeneralNames SEQUENCE
    i = 0
    while i < len(seq):
        tag, val, i = _tlv(seq, i)
        if tag == 0x82:  # [2] dNSName
            names.append(val.decode("utf-8", "replace").strip())
    return names


def _asn1_time(raw: bytes) -> Optional[float]:
    """Converte UTCTime (YYMMDDHHMMSSZ) ou GeneralizedTime (YYYYMMDD...) em epoch."""
    import calendar

    s = raw.decode("ascii", "ignore").strip().rstrip("Z")
    # descarta fração de segundo/offset, se houver; fica só o dígito de data-hora
    s = re.split(r"[.+\-]", s)[0]
    fmt = "%y%m%d%H%M%S" if len(s) <= 12 else "%Y%m%d%H%M%S"
    try:
        return calendar.timegm(time.strptime(s[:14], fmt))
    except ValueError:
        return None


def parse_cert_der(der: bytes) -> dict:
    """Extrai os campos de interesse de um certificado X.509 em DER."""
    info: dict = {}
    try:
        _, cert, _ = _tlv(der, 0)             # Certificate SEQUENCE
        _, tbs, _ = _tlv(cert, 0)             # tbsCertificate SEQUENCE
        i = 0
        tag, _, i = _tlv(tbs, i)
        if tag == 0xA0:                       # [0] version, opcional
            tag, _, i = _tlv(tbs, i)
        # aqui já consumimos serialNumber; seguem signature, issuer, validity, subject
        _, _, i = _tlv(tbs, i)                # signature AlgorithmIdentifier
        _, issuer, i = _tlv(tbs, i)           # issuer Name
        _, validity, i = _tlv(tbs, i)         # validity SEQUENCE
        _, subject, i = _tlv(tbs, i)          # subject Name
    except (IndexError, ValueError):
        return info

    subj = _name_fields(subject)
    iss = _name_fields(issuer)
    info["subject_cn"] = subj.get(_OID_CN) or subj.get(_OID_ORG)
    info["issuer"] = iss.get(_OID_CN) or iss.get(_OID_ORG)
    info["self_signed"] = bool(subject == issuer)

    try:
        vi = 0
        _, _not_before, vi = _tlv(validity, vi)
        _, not_after, _ = _tlv(validity, vi)
        info["not_after"] = _asn1_time(not_after)
    except (IndexError, ValueError):
        info["not_after"] = None

    # Extensões [3] -> procurar subjectAltName. ``i`` já aponta para logo após o
    # subject dentro de ``tbs``; seguem SPKI e, opcional, as extensões.
    try:
        san: list[str] = []
        j = i
        while j < len(tbs):
            tag, val, j = _tlv(tbs, j)
            if tag != 0xA3:  # [3] extensions
                continue
            _, extseq, _ = _tlv(val, 0)
            p = 0
            while p < len(extseq):
                _, ext, p = _tlv(extseq, p)  # Extension SEQUENCE
                _, oid, q = _tlv(ext, 0)
                if _oid_to_str(oid) != _OID_SAN:
                    continue
                # pode haver o BOOLEAN critical antes do OCTET STRING extnValue
                _, octets, q = _tlv(ext, q)
                if q < len(ext):
                    _, octets, _ = _tlv(ext, q)
                san = _san_dns(octets)
            break
        if san:
            info["san"] = san[:8]
    except (IndexError, ValueError):
        pass

    return {key: v for key, v in info.items() if v not in (None, "", [])}


# --------------------------------------------------------------------------- #
# SNMP (161/UDP) — community "public"
#
# O default de fábrica de quase toda impressora, switch e access point. Só
# leitura: um GetRequest de sysDescr e sysName devolve modelo, firmware e o nome
# configurado do aparelho — e um host que responde a "public" é, por si só, um
# achado. Não há brute force de community: só o default universalmente conhecido.
# --------------------------------------------------------------------------- #
SNMP_COMMUNITY = "public"
_OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
_OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"


def _ber(tag: int, value: bytes) -> bytes:
    """Empacota um TLV BER com tamanho em forma curta ou longa."""
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    length = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + value


def _ber_int(n: int) -> bytes:
    length = max(1, (n.bit_length() + 8) // 8)
    return _ber(0x02, n.to_bytes(length, "big"))


def build_snmp_get(oids: list[str], request_id: int, community: str) -> bytes:
    """Monta um GetRequest SNMPv1 para os OIDs dados."""
    varbinds = b"".join(
        _ber(0x30, _ber(0x06, _encode_oid(o)) + _ber(0x05, b""))  # OID + NULL
        for o in oids
    )
    pdu = _ber(
        0xA0,  # GetRequest-PDU
        _ber_int(request_id) + _ber_int(0) + _ber_int(0) + _ber(0x30, varbinds),
    )
    return _ber(
        0x30,
        _ber_int(0)  # version 1 == 0
        + _ber(0x04, community.encode("ascii"))
        + pdu,
    )


def parse_snmp_response(data: bytes) -> dict[str, str]:
    """Extrai {oid: valor de texto} de um GetResponse SNMP."""
    out: dict[str, str] = {}
    try:
        _, msg, _ = _tlv(data, 0)             # SEQUENCE
        i = 0
        _, _ver, i = _tlv(msg, i)
        _, _community, i = _tlv(msg, i)
        _, pdu, _ = _tlv(msg, i)              # GetResponse-PDU (0xA2)
        j = 0
        _, _rid, j = _tlv(pdu, j)
        _, err, j = _tlv(pdu, j)
        if err and err[0] != 0:               # error-status != noError
            return out
        _, _eidx, j = _tlv(pdu, j)
        _, vblist, _ = _tlv(pdu, j)           # SEQUENCE OF VarBind
        p = 0
        while p < len(vblist):
            _, vb, p = _tlv(vblist, p)
            q = 0
            _, oid, q = _tlv(vb, q)
            vtag, vval, _ = _tlv(vb, q)
            if vtag == 0x04:                  # OCTET STRING
                text = vval.decode("utf-8", "replace")
                text = _CLEAN_RE.sub(" ", text).strip()
                if text:
                    out[_oid_to_str(oid)] = re.sub(r"\s+", " ", text)
    except (IndexError, ValueError):
        return out
    return out


def _snmp_one(ip: str, community: str, timeout: float) -> Optional[dict]:
    import os

    req_id = int.from_bytes(os.urandom(2), "big") or 1
    packet = build_snmp_get([_OID_SYS_DESCR, _OID_SYS_NAME], req_id, community)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(packet, (ip, 161))
            data, _ = s.recvfrom(4096)
    except OSError:
        return None
    fields = parse_snmp_response(data)
    if not fields:
        return None
    out: dict = {"community": community}
    descr = fields.get(_OID_SYS_DESCR)
    name = fields.get(_OID_SYS_NAME)
    if descr:
        out["descr"] = descr[:120]
    if name:
        out["name"] = name[:60]
    return out


def query_snmp(
    ips: list[str],
    community: str = SNMP_COMMUNITY,
    timeout: float = 1.0,
    workers: int = 64,
) -> dict[str, dict]:
    """Consulta sysDescr/sysName via SNMP em cada host. Retorna {ip: {...}}."""
    if not ips:
        return {}
    result: dict[str, dict] = {}
    lock = threading.Lock()

    def work(ip: str) -> None:
        info = _snmp_one(ip, community, timeout)
        if info:
            with lock:
                result[ip] = info

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ips)))) as pool:
        list(pool.map(work, ips))
    return result


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
    """Valor de um header HTTP/RTSP. None se ausente ou vazio.

    O espaço aqui é só horizontal: com ``\\s*``, um header vazio ("Server:")
    fazia o casamento atravessar a quebra de linha e devolver o valor do
    header seguinte — o roteador aparecia na tabela como "Accept-Ranges: bytes".
    """
    m = re.search(
        rf"^{re.escape(name)}[^\S\r\n]*:[^\S\r\n]*(.*)$",
        text, re.IGNORECASE | re.MULTILINE,
    )
    if not m:
        return None
    return m.group(1).strip() or None


# --------------------------------------------------------------------------- #
# URLs anunciadas por aparelhos — entrada não confiável
#
# O LOCATION do SSDP é escolhido pelo aparelho, não por nós: qualquer coisa na
# LAN pode anunciar o que quiser. Sem validar, o urlopen aceitaria
# `file:///etc/passwd` (lê o arquivo e joga o conteúdo na tabela) ou apontaria
# para um host interno arbitrário, transformando o alive em proxy de varredura.
# Só seguimos http do próprio IP que respondeu, e sem redirecionamento — sair
# do aparelho anularia exatamente a checagem de origem.
# --------------------------------------------------------------------------- #
def safe_device_url(url: Optional[str], device_ip: str) -> Optional[str]:
    """Devolve a URL se ela for ``http://`` do próprio ``device_ip``; senão None."""
    if not url or not device_ip:
        return None
    try:
        parts = urlsplit(url.strip())
    except ValueError:
        return None
    if parts.scheme != "http" or (parts.hostname or "") != device_ip:
        return None
    return urlunsplit(parts)


_OPENER = None


def _no_redirect_opener():
    """Opener que recusa redirecionamento (construído uma vez, sob demanda)."""
    global _OPENER
    if _OPENER is None:
        from urllib.request import HTTPRedirectHandler, build_opener

        class _NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        _OPENER = build_opener(_NoRedirect)
    return _OPENER


def _fetch_device(url: str, timeout: float, limit: int) -> Optional[str]:
    """Baixa uma URL já validada por :func:`safe_device_url`. None em qualquer erro."""
    try:
        with _no_redirect_opener().open(url, timeout=timeout) as resp:
            return resp.read(limit).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - aparelho pode recusar, sumir ou redirecionar
        return None


def new_ssdp_entry() -> dict:
    """Registro vazio de um aparelho SSDP. Única fonte da verdade do formato."""
    return {
        "name": None,
        "server": None,
        "model": None,
        "manufacturer": None,
        "location": None,
        "types": set(),
    }


def record_ssdp(results: dict[str, dict], ip: str, text: str) -> Optional[str]:
    """Processa uma resposta SSDP e devolve a LOCATION anunciada, se houver."""
    entry = results.setdefault(ip, new_ssdp_entry())
    server = _header(text, "SERVER")
    if server and not entry.get("server"):
        entry["server"] = server
    st = _header(text, "ST") or _header(text, "NT")
    if st:
        entry.setdefault("types", set()).add(st)
    loc = _header(text, "LOCATION")
    if loc and not entry.get("location"):
        entry["location"] = loc
    return loc


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
            loc = record_ssdp(results, addr[0], data.decode("utf-8", "replace"))
            if loc:
                locations.setdefault(addr[0], loc)
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

    def fetch(item: tuple[str, str]) -> None:
        ip, url = item
        safe = safe_device_url(url, ip)
        if not safe:
            return
        xml = _fetch_device(safe, timeout=1.5, limit=65536)
        if not xml:
            return
        entry = results.setdefault(ip, new_ssdp_entry())
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


# --------------------------------------------------------------------------- #
# WAN do gateway via UPnP (SOAP)
#
# Quando o roteador expõe WANIPConnection, dá para perguntar o IP público, o
# uptime do link e — o mais importante — a lista de redirecionamentos de porta
# ativos, que é o que está aberto da LAN para a internet sem ninguém saber.
# --------------------------------------------------------------------------- #
_WAN_TYPES = ("WANIPConnection", "WANPPPConnection")


def _soap(url: str, service_type: str, action: str, body: str = "", timeout: float = 2.0):
    """Faz uma chamada SOAP UPnP e devolve o XML de resposta (ou None).

    ``url`` tem de vir de :func:`safe_device_url`.
    """
    from urllib.request import Request

    envelope = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
        f'<u:{action} xmlns:u="{service_type}">{body}</u:{action}>'
        "</s:Body></s:Envelope>"
    ).encode()
    req = Request(
        url,
        data=envelope,
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{service_type}#{action}"',
        },
    )
    try:
        with _no_redirect_opener().open(req, timeout=timeout) as resp:
            return resp.read(65536).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - roteador pode recusar ou não implementar
        return None


def _find_wan_service(xml: str, base: str, device_ip: str) -> Optional[tuple[str, str]]:
    """Acha (serviceType, controlURL absoluto) do serviço WAN na descrição UPnP.

    O controlURL vem do XML do aparelho e pode ser absoluto apontando para
    qualquer lugar — por isso passa pela mesma validação de origem.
    """
    for block in re.findall(r"<service>(.*?)</service>", xml, re.DOTALL | re.IGNORECASE):
        stype = _tag(block, "serviceType")
        ctrl = _tag(block, "controlURL")
        if stype and ctrl and any(t in stype for t in _WAN_TYPES):
            url = safe_device_url(urljoin(base, ctrl), device_ip)
            if url:
                return stype, url
    return None


def gateway_wan_info(location: str, max_mappings: int = 24) -> dict:
    """Interroga o gateway via UPnP. Retorna ip público, uptime e mapeamentos."""
    info: dict = {}
    device_ip = urlsplit(location).hostname or ""
    safe = safe_device_url(location, device_ip)
    if not safe:
        return info
    xml = _fetch_device(safe, timeout=2.0, limit=131072)
    if not xml:
        return info

    info["model"] = " ".join(
        filter(None, [_tag(xml, "manufacturer"), _tag(xml, "modelName")])
    ) or None
    found = _find_wan_service(xml, safe, device_ip)
    if not found:
        return info
    stype, ctrl = found

    ext = _soap(ctrl, stype, "GetExternalIPAddress")
    if ext:
        ip = _tag(ext, "NewExternalIPAddress")
        if ip and ip != "0.0.0.0":
            info["external_ip"] = ip

    status = _soap(ctrl, stype, "GetStatusInfo")
    if status:
        uptime = _tag(status, "NewUptime")
        if uptime and uptime.isdigit():
            info["uptime_s"] = int(uptime)
        conn = _tag(status, "NewConnectionStatus")
        if conn:
            info["connection"] = conn

    # Enumera os redirecionamentos até o roteador dizer que acabou.
    mappings = []
    for index in range(max_mappings):
        resp = _soap(
            ctrl, stype, "GetGenericPortMappingEntry",
            f"<NewPortMappingIndex>{index}</NewPortMappingIndex>",
        )
        if not resp or "NewInternalClient" not in resp:
            break
        mappings.append(
            {
                "external_port": _tag(resp, "NewExternalPort"),
                "internal_port": _tag(resp, "NewInternalPort"),
                "internal_client": _tag(resp, "NewInternalClient"),
                "protocol": _tag(resp, "NewProtocol"),
                "description": _clean(_tag(resp, "NewPortMappingDescription"), 30),
            }
        )
    if mappings:
        info["port_mappings"] = mappings
    return info


def find_gateway_location(ssdp: dict, gateway_ip: Optional[str]) -> Optional[str]:
    """URL de descrição UPnP do gateway, a partir do resultado do SSDP."""
    if not gateway_ip:
        return None
    entry = (ssdp or {}).get(gateway_ip) or {}
    return safe_device_url(entry.get("location"), gateway_ip)


# --------------------------------------------------------------------------- #
# ONVIF / WS-Discovery (3702/UDP)
#
# O padrão das câmeras IP de segurança. Um Probe multicast faz cada câmera se
# anunciar com nome, fabricante e modelo (nos Scopes) — inclusive câmeras que
# não falam SSDP nem mDNS. Só descoberta: lemos o anúncio, nunca o vídeo.
# --------------------------------------------------------------------------- #
_WS_DISCOVERY_ADDR = "239.255.255.250"
_WS_DISCOVERY_PORT = 3702


def _ws_probe(message_id: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        f"<e:Header><w:MessageID>uuid:{message_id}</w:MessageID>"
        "<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
        "<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
        "</e:Header><e:Body><d:Probe>"
        "<d:Types>dn:NetworkVideoTransmitter</d:Types>"
        "</d:Probe></e:Body></e:Envelope>"
    ).encode("utf-8")


def _parse_onvif_scopes(xml: str) -> dict:
    """Extrai nome/fabricante/modelo dos Scopes ONVIF de um ProbeMatch."""
    info: dict = {}
    scopes = _tag(xml, "Scopes") or _tag(xml, "d:Scopes") or ""
    for token in scopes.split():
        # onvif://www.onvif.org/name/Camera%20Sala, /hardware/IPC-123, /location/...
        for chave, campo in (("/name/", "name"), ("/hardware/", "model"),
                             ("/location/", "location")):
            idx = token.lower().find(chave)
            if idx >= 0 and campo not in info:
                val = _clean(html.unescape(token[idx + len(chave):].replace("%20", " ")), 40)
                if val:
                    info[campo] = val
    return info


def discover_onvif(duration: float = 2.5) -> dict[str, dict]:
    """Escuta respostas ONVIF WS-Discovery. Retorna {ip: {onvif, name, model}}."""
    import os

    results: dict[str, dict] = {}
    probe = _ws_probe(os.urandom(8).hex())
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.5)
        for _ in range(2):  # UDP: duas tentativas cobrem perda de pacote
            try:
                sock.sendto(probe, (_WS_DISCOVERY_ADDR, _WS_DISCOVERY_PORT))
            except OSError:
                break
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            xml = data.decode("utf-8", "replace")
            if "ProbeMatch" not in xml:
                continue
            entry = results.setdefault(addr[0], {"onvif": True})
            for k, v in _parse_onvif_scopes(xml).items():
                entry.setdefault(k, v)
            xaddr = (_tag(xml, "XAddrs") or "").split()
            if xaddr and "xaddr" not in entry:
                entry["xaddr"] = xaddr[0]
    except OSError:
        return results
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    _fill_onvif_info(results)
    return results


# GetDeviceInformation SEM credencial. Se a câmera responde, ela expõe
# fabricante/modelo/firmware/serial a qualquer um na LAN — uma exposição real,
# no mesmo espírito do "SNMP public". Não é login: só verificamos se ela EXIGE
# um. 401/403 = protegida (o certo); 200 = anônima (o achado).
_ONVIF_GETINFO = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
    "</s:Body></s:Envelope>"
).encode("utf-8")


def onvif_device_info(xaddr: str, device_ip: str, timeout: float = 2.0) -> Optional[dict]:
    """GetDeviceInformation anônimo. Retorna {model, firmware, serial, anon} ou None."""
    from urllib.request import Request

    safe = safe_device_url(xaddr, device_ip)
    if not safe:
        return None
    req = Request(
        safe, data=_ONVIF_GETINFO,
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
    )
    try:
        with _no_redirect_opener().open(req, timeout=timeout) as resp:
            xml = resp.read(16384).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001 - 401/timeout/recusa: câmera protegida ou muda
        return None
    manufacturer = _tag(xml, "Manufacturer") or _tag(xml, "tds:Manufacturer")
    model = _tag(xml, "Model") or _tag(xml, "tds:Model")
    firmware = _tag(xml, "FirmwareVersion") or _tag(xml, "tds:FirmwareVersion")
    if not (manufacturer or model):
        return None
    return {
        "anon": True,
        "model": " ".join(filter(None, [manufacturer, model])) or None,
        "firmware": firmware,
        "serial": _tag(xml, "SerialNumber") or _tag(xml, "tds:SerialNumber"),
    }


def _fill_onvif_info(results: dict[str, dict]) -> None:
    """Para cada câmera com XAddrs, tenta o GetDeviceInformation anônimo."""
    def fetch(item: tuple[str, dict]) -> None:
        ip, entry = item
        xaddr = entry.get("xaddr")
        if not xaddr:
            return
        info = onvif_device_info(xaddr, ip)
        if info:
            entry["anon"] = True
            for k in ("model", "firmware", "serial"):
                if info.get(k) and not entry.get(k):
                    entry[k] = info[k]

    itens = [(ip, e) for ip, e in results.items() if e.get("xaddr")]
    if not itens:
        return
    with ThreadPoolExecutor(max_workers=max(1, min(8, len(itens)))) as pool:
        list(pool.map(fetch, itens))


def _tag(xml: str, tag: str) -> Optional[str]:
    m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    val = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()
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


# --------------------------------------------------------------------------- #
# DHCP rogue (67/68 UDP)
#
# Um servidor DHCP não autorizado é o vetor de MITM mais silencioso de uma rede
# interna: ele entrega a si mesmo como gateway/DNS e passa a ver todo o tráfego.
# Mandamos um DISCOVER em broadcast e coletamos as OFFERs — se responder mais de
# um servidor, ou um que ofereça um gateway diferente do atual, é rogue.
#
# Só um DISCOVER: nunca mandamos REQUEST, então nenhum lease é fechado e nada na
# rede é perturbado. Requer a porta 68 (privilegiada) — roda sob sudo/root.
# --------------------------------------------------------------------------- #
_DHCP_MAGIC = b"\x63\x82\x53\x63"


def _mac_to_bytes(mac: Optional[str]) -> bytes:
    """'aa:bb:cc:dd:ee:ff' -> 6 bytes. Zeros se ausente/inválido."""
    if not mac:
        return b"\x00" * 6
    try:
        return bytes(int(x, 16) for x in mac.split(":"))[:6].ljust(6, b"\x00")
    except ValueError:
        return b"\x00" * 6


def build_dhcp_discover(mac: Optional[str], xid: int) -> bytes:
    """Monta um pacote BOOTP/DHCP DISCOVER com flag de broadcast."""
    chaddr = _mac_to_bytes(mac).ljust(16, b"\x00")
    packet = struct.pack(
        ">BBBBIHHIIII16s64s128s",
        1, 1, 6, 0,        # op=BOOTREQUEST, htype=ethernet, hlen=6, hops=0
        xid,               # transaction id
        0, 0x8000,         # secs, flags=broadcast
        0, 0, 0, 0,        # ciaddr, yiaddr, siaddr, giaddr
        chaddr, b"", b"",  # chaddr (16), sname (64), file (128)
    )
    options = (
        _DHCP_MAGIC
        + bytes([53, 1, 1])                    # DHCP message type = DISCOVER
        + bytes([55, 5, 1, 3, 6, 15, 54])      # param request: subnet,router,dns,domain,serverid
        + bytes([255])                          # end
    )
    return packet + options


def _dhcp_options(data: bytes) -> dict[int, bytes]:
    """Decodifica as opções DHCP (TLV simples) após o magic cookie."""
    idx = data.find(_DHCP_MAGIC)
    if idx < 0:
        return {}
    i = idx + 4
    opts: dict[int, bytes] = {}
    while i < len(data):
        code = data[i]
        if code == 255:  # end
            break
        if code == 0:    # pad
            i += 1
            continue
        if i + 1 >= len(data):
            break
        length = data[i + 1]
        opts[code] = data[i + 2 : i + 2 + length]
        i += 2 + length
    return opts


def _ips_from(raw: bytes) -> list[str]:
    return [socket.inet_ntoa(raw[j : j + 4]) for j in range(0, len(raw) - 3, 4)]


def parse_dhcp_offer(data: bytes) -> Optional[dict]:
    """Extrai o servidor, o gateway e o DNS oferecidos de uma OFFER DHCP."""
    if len(data) < 240 or data[0] != 2:  # op=BOOTREPLY
        return None
    opts = _dhcp_options(data)
    if opts.get(53) not in (b"\x02", b"\x05"):  # OFFER ou ACK
        return None
    server = opts.get(54)
    info: dict = {
        "server": socket.inet_ntoa(server) if server and len(server) == 4 else None,
        "offered_ip": socket.inet_ntoa(data[16:20]) if data[16:20] != b"\x00" * 4 else None,
        "routers": _ips_from(opts.get(3, b"")),
        "dns": _ips_from(opts.get(6, b"")),
    }
    return info


def discover_dhcp(mac: Optional[str], duration: float = 3.0) -> Optional[list[dict]]:
    """Manda um DISCOVER e coleta as OFFERs. Retorna a lista de servidores.

    ``None`` quando não dá para escutar a porta 68 (sem privilégio): a sonda
    fica indisponível, não é o mesmo que "nenhum servidor rogue".
    """
    import os

    xid = int.from_bytes(os.urandom(4), "big")
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("", 68))
        except OSError:
            return None  # porta 68 exige privilégio (ou já está em uso)
        sock.settimeout(0.5)
        sock.sendto(build_dhcp_discover(mac, xid), ("255.255.255.255", 67))

        servers: dict[str, dict] = {}
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) >= 4 and struct.unpack(">I", data[4:8])[0] != xid:
                continue  # resposta a outro cliente
            offer = parse_dhcp_offer(data)
            if not offer:
                continue
            key = offer.get("server") or addr[0]
            offer.setdefault("source", addr[0])
            servers.setdefault(key, offer)
    except OSError:
        return None
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return list(servers.values())
