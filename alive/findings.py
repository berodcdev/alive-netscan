"""Achados: o que a varredura encontrou que merece atenção.

A diferença entre inventário e diagnóstico. Todas as regras aqui derivam de
dados que as sondas já coletaram — nada de teste extra, nada de credencial,
nada de exploração. Só a leitura honesta do que está exposto na sua LAN.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# Serviços em texto puro ou de controle remoto que não deveriam estar abertos
# numa rede doméstica. {serviço: (severidade, explicação)}
_RISKY_SERVICES: dict[str, tuple[str, str]] = {
    "telnet": ("alto", "telnet (23) aberto — login e dados trafegam em texto puro"),
    "ftp": ("medio", "FTP (21) aberto — credenciais em texto puro"),
    "adb": ("alto", "ADB (5555) exposto — qualquer um na rede instala apps neste aparelho"),
    "rtsp": ("alto", "RTSP (554) aberto — o vídeo pode ser acessado por quem está na rede"),
    "vnc": ("alto", "VNC (5900) aberto — controle total da tela se a senha for fraca"),
    "rdp": ("medio", "RDP (3389) aberto — alvo comum de força bruta"),
    "mqtt": ("baixo", "MQTT (1883) sem TLS — comandos de automação em texto puro"),
    "dvr": ("medio", "porta de DVR (37777) aberta — interface proprietária exposta"),
}

SEVERITY_ORDER = {"alto": 0, "medio": 1, "baixo": 2}
SEVERITY_COLOR = {"alto": "bright_red", "medio": "yellow", "baixo": "bright_black"}


@dataclass
class Finding:
    """Um achado, sempre ancorado num host (ou no gateway)."""

    severity: str  # alto | medio | baixo
    ip: Optional[str]
    message: str

    @property
    def color(self) -> str:
        return SEVERITY_COLOR.get(self.severity, "yellow")


def _label(host: dict) -> str:
    name = host.get("name")
    return f"{host['ip']} ({name})" if name else host["ip"]


def collect(hosts: list[dict], wan: Optional[dict] = None) -> list[Finding]:
    """Aplica todas as regras e devolve os achados ordenados por severidade."""
    out: list[Finding] = []

    for h in hosts:
        services = h.get("services") or set()
        for svc, (severity, text) in _RISKY_SERVICES.items():
            if svc in services:
                # Uma câmera com RTSP é o funcionamento normal dela; o problema é
                # o serviço estar acessível, então o texto já diz isso.
                out.append(Finding(severity, h["ip"], f"{_label(h)}: {text}"))

    # MAC repetido em IPs diferentes: bridge, NAT interno, VM — ou spoof.
    by_mac: dict[str, list[dict]] = {}
    for h in hosts:
        mac = h.get("mac")
        if mac and not h.get("random_mac"):
            by_mac.setdefault(mac, []).append(h)
    for mac, group in by_mac.items():
        if len(group) > 1:
            ips = ", ".join(x["ip"] for x in group)
            out.append(
                Finding(
                    "medio", group[0]["ip"],
                    f"MAC {mac} responde em {len(group)} IPs ({ips}) — "
                    "bridge, VM ou endereço forjado",
                )
            )

    # Hosts que só apareceram na tabela ARP: ignoram ping de propósito.
    silent = [h for h in hosts if h.get("via") == "arp"]
    if silent:
        ips = ", ".join(h["ip"] for h in silent[:5])
        extra = " ..." if len(silent) > 5 else ""
        out.append(
            Finding(
                "baixo", None,
                f"{len(silent)} host(s) responderam só a ARP, não a ping "
                f"({ips}{extra}) — firewall ativo ou aparelho furtivo",
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
    return notes
