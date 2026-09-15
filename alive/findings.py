"""Achados: o que a varredura encontrou que merece atenção.

A diferença entre inventário e diagnóstico. Todas as regras aqui derivam de
dados que as sondas já coletaram — nada de teste extra, nada de credencial,
nada de exploração. Só a leitura honesta do que está exposto na sua LAN.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from .scanner import is_random_mac

# Serviços em texto puro ou de controle remoto que não deveriam estar abertos
# numa rede doméstica. {serviço: (severidade, o que é, o que fazer)}
#
# O "o que fazer" existe porque apontar o problema sem dizer a saída deixa o
# trabalho pela metade: quem roda isso em casa não sabe onde fica a opção.
_RISKY_SERVICES: dict[str, tuple[str, str, str]] = {
    "telnet": (
        "alto", "telnet (23) aberto — login e dados trafegam em texto puro",
        "desative o telnet no painel do aparelho (http://{ip}); prefira SSH",
    ),
    "ftp": (
        "medio", "FTP (21) aberto — credenciais em texto puro",
        "desative o FTP ou troque por SFTP/FTPS",
    ),
    "adb": (
        "alto", "ADB (5555) exposto — qualquer um na rede instala apps neste aparelho",
        "desligue a depuração por rede em Opções do desenvolvedor",
    ),
    "rtsp": (
        "alto", "RTSP (554) aberto — o vídeo pode ser acessado por quem está na rede",
        "exija senha no RTSP e confirme que a porta não está redirecionada",
    ),
    "vnc": (
        "alto", "VNC (5900) aberto — controle total da tela se a senha for fraca",
        "use senha forte e acesse por SSH/VPN em vez de expor a porta",
    ),
    "rdp": (
        "medio", "RDP (3389) aberto — alvo comum de força bruta",
        "restrinja o RDP à VPN e mantenha o NLA ligado",
    ),
    "mqtt": (
        "baixo", "MQTT (1883) sem TLS — comandos de automação em texto puro",
        "ative TLS (8883) e autenticação no broker",
    ),
    "dvr": (
        "medio", "porta de DVR (37777) aberta — interface proprietária exposta",
        "troque a senha padrão e mantenha a porta restrita à LAN",
    ),
}

SEVERITY_ORDER = {"alto": 0, "medio": 1, "baixo": 2}
SEVERITY_COLOR = {"alto": "bright_red", "medio": "yellow", "baixo": "bright_black"}


@dataclass
class Finding:
    """Um achado, sempre ancorado num host (ou no gateway)."""

    severity: str  # alto | medio | baixo
    ip: Optional[str]
    message: str
    fix: Optional[str] = None  # o que fazer a respeito, quando há uma ação clara

    @property
    def color(self) -> str:
        return SEVERITY_COLOR.get(self.severity, "yellow")


def _ip_list(hosts: list[dict], limit: int = 5) -> str:
    """IPs separados por vírgula, truncados — cabe numa linha de achado."""
    ips = ", ".join(h["ip"] for h in hosts[:limit])
    return f"{ips} ..." if len(hosts) > limit else ips


def _label(host: dict) -> str:
    name = host.get("name")
    return f"{host['ip']} ({name})" if name else host["ip"]


def collect(
    hosts: list[dict],
    wan: Optional[dict] = None,
    *,
    passive: bool = False,
    gateway: Optional[str] = None,
    gateway_mac_prev: Optional[str] = None,
) -> list[Finding]:
    """Aplica todas as regras e devolve os achados ordenados por severidade.

    Com ``passive``, o achado de "só respondeu a ARP" é omitido: em modo
    passivo ninguém foi pingado, então todo host vem do ARP por construção —
    reportar isso como descoberta seria mentir sobre o que foi verificado.

    ``gateway`` é o IP do roteador e ``gateway_mac_prev`` o MAC que ele tinha no
    scan anterior (do histórico). Juntos alimentam a detecção de MITM: o MAC do
    gateway mudar, ou o IP do gateway responder com um MAC forjado, é a
    assinatura de ARP spoofing / evil twin numa rede interna.
    """
    out: list[Finding] = []

    gw_mac = next(
        (h.get("mac") for h in hosts if gateway and h.get("ip") == gateway), None
    )

    for h in hosts:
        services = h.get("services") or set()
        for svc, (severity, text, fix) in _RISKY_SERVICES.items():
            if svc in services:
                # Uma câmera com RTSP é o funcionamento normal dela; o problema é
                # o serviço estar acessível, então o texto já diz isso.
                out.append(
                    Finding(severity, h["ip"], f"{_label(h)}: {text}",
                            fix.format(ip=h["ip"]))
                )

    # --- MITM: o gateway é o alvo nº 1 de ARP spoofing numa rede interna. ---

    # O MAC do gateway mudou entre scans. Ou você trocou de roteador, ou alguém
    # passou a responder pelo IP do gateway com o próprio MAC (poisoning/evil
    # twin). Roteador não troca de MAC ao reiniciar, então isso é raro e caro.
    if gateway and gw_mac and gateway_mac_prev and gw_mac != gateway_mac_prev:
        out.append(
            Finding(
                "alto", gateway,
                f"MAC do gateway {gateway} mudou de {gateway_mac_prev} para "
                f"{gw_mac} desde o último scan — troca de roteador, ou ARP "
                "spoofing / evil twin em andamento",
                "se você não trocou de roteador, alguém pode estar interceptando "
                "a rede; confira o MAC na etiqueta do aparelho e a tabela ARP",
            )
        )

    # O IP do gateway responde com um MAC localmente administrado. Placa de
    # roteador de verdade tem MAC de fábrica (OUI registrado); um MAC forjado
    # aqui sugere que um aparelho está se passando pelo gateway. Roteador
    # virtualizado (pfSense/OPNsense em VM) é o falso-positivo honesto, por isso
    # médio e em forma de pergunta.
    if gateway and gw_mac and is_random_mac(gw_mac):
        out.append(
            Finding(
                "medio", gateway,
                f"MAC do gateway {gateway} ({gw_mac}) é localmente administrado — "
                "roteador virtualizado, ou um aparelho forjando o gateway",
                "confirme que esse MAC bate com a etiqueta do seu roteador",
            )
        )

    # MAC repetido em IPs diferentes: bridge, NAT interno, VM — ou spoof.
    by_mac: dict[str, list[dict]] = {}
    for h in hosts:
        mac = h.get("mac")
        if mac and not h.get("random_mac"):
            by_mac.setdefault(mac, []).append(h)
    for mac, group in by_mac.items():
        if len(group) <= 1:
            continue
        ips = ", ".join(x["ip"] for x in group)
        # Se o MAC duplicado é o do gateway, isso é ARP spoofing clássico: um
        # aparelho responde ARP com o MAC do roteador para se meter no caminho.
        if gw_mac and mac == gw_mac:
            others = ", ".join(x["ip"] for x in group if x["ip"] != gateway)
            out.append(
                Finding(
                    "alto", gateway,
                    f"o MAC do gateway ({mac}) responde também em {others} — "
                    "ARP spoofing clássico: um aparelho se passa pelo roteador",
                    "isole o aparelho intruso; ele pode estar interceptando o "
                    "tráfego de quem está na rede",
                )
            )
        else:
            out.append(
                Finding(
                    "medio", group[0]["ip"],
                    f"MAC {mac} responde em {len(group)} IPs ({ips}) — "
                    "bridge, VM ou endereço forjado",
                    "se você não tem bridge nem VM aqui, investigue o aparelho",
                )
            )

    # Hosts que só apareceram na tabela ARP. O estado do vizinho separa dois
    # casos bem diferentes: confirmado é um aparelho presente que ignora ping;
    # obsoleto é cache que o kernel não revalidou — pode já ter saído da rede.
    silent = [] if passive else [h for h in hosts if h.get("via") == "arp"]
    confirmed = [h for h in silent if h.get("arp_state") != "stale"]
    stale = [h for h in silent if h.get("arp_state") == "stale"]
    if confirmed:
        out.append(
            Finding(
                "baixo", None,
                f"{len(confirmed)} host(s) responderam só a ARP, não a ping "
                f"({_ip_list(confirmed)}) — firewall ativo ou aparelho furtivo",
            )
        )
    if stale:
        out.append(
            Finding(
                "baixo", None,
                f"{len(stale)} host(s) vêm só de cache ARP obsoleto "
                f"({_ip_list(stale)}) — podem já ter saído da rede",
            )
        )

    # Redirecionamentos de porta ativos no roteador: exposição para a internet.
    for m in (wan or {}).get("port_mappings") or []:
        desc = f" [{m['description']}]" if m.get("description") else ""
        out.append(
            Finding(
                "alto", m.get("internal_client"),
                f"roteador redireciona {m.get('protocol')}/{m.get('external_port')} "
                f"da internet para {m.get('internal_client')}:{m.get('internal_port')}"
                f"{desc}",
                "remova o redirecionamento no painel do roteador se não for proposital",
            )
        )

    # SNMP com community "public" respondendo: o default de fábrica, leitura
    # aberta da configuração do aparelho para qualquer um na LAN.
    for h in hosts:
        snmp = h.get("snmp") or {}
        if snmp.get("community") == "public":
            out.append(
                Finding(
                    "medio", h["ip"],
                    f"{_label(h)}: SNMP responde à community padrão 'public' — "
                    "qualquer um na rede lê a configuração do aparelho",
                    "troque a community padrão ou desligue o SNMP se não usa",
                )
            )

    # Certificado TLS vencido: hosts com HTTPS cuja validade já passou.
    for h in hosts:
        tls = h.get("tls") or {}
        not_after = tls.get("not_after")
        if not_after and not_after < time.time():
            out.append(
                Finding(
                    "baixo", h["ip"],
                    f"{_label(h)}: certificado TLS vencido "
                    f"({tls.get('subject_cn') or 'sem CN'})",
                    "renove o certificado do aparelho",
                )
            )

    out.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.ip or ""))
    return out


def short_notes(host: dict) -> list[str]:
    """Marcações curtas do host para a coluna DETALHE (ex.: 'adb aberto!')."""
    services = host.get("services") or set()
    notes = []
    for svc in ("telnet", "adb", "vnc", "ftp"):
        if svc in services:
            notes.append(f"{svc} aberto!")
    if (host.get("snmp") or {}).get("community") == "public":
        notes.append("snmp público!")
    tls = host.get("tls") or {}
    if tls.get("not_after") and tls["not_after"] < time.time():
        notes.append("cert vencido!")
    return notes
