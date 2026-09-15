"""Apresentação: banner, tabela colorida (rich) e saída JSON."""

from __future__ import annotations

import json
import re
from typing import Optional

from rich.box import SQUARE
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from . import __version__
from .history import seen_label
from .net import NetInfo, channel_from_freq

# highlight=False: sem auto-coloração de números/strings — controlamos as cores no tema.
console = Console(highlight=False)

BANNER = r"""
[bold green]▄▀█ █░░ █ █░█ █▀▀
█▀█ █▄▄ █ ▀▄▀ ██▄[/bold green]
[dim green]  host discovery · network recon  [/dim green][dim]v{ver}[/dim]"""


def print_banner() -> None:
    """Imprime a arte ASCII (uma vez, no topo)."""
    console.print(BANNER.format(ver=__version__))


def _kv(prefix: str, prefix_style: str, label: str, value: str) -> None:
    """Linha estilo recon: '[*] label ........ value'."""
    dots = "." * max(2, 13 - len(label))
    console.print(
        f"[{prefix_style}]{prefix}[/{prefix_style}] "
        f"[bold white]{label}[/bold white] [dim]{dots}[/dim] {value}"
    )


def print_summary(
    net: NetInfo,
    hosts: list[dict],
    method: str,
    diff: Optional[object] = None,
    findings: Optional[list] = None,
) -> None:
    """Imprime o resumo da rede em formato de saída de ferramenta de recon."""
    console.print()
    _kv("[*]", "green", "alvo", f"[bold green]{net.cidr or '?'}[/bold green]")
    iface = escape(net.interface) if net.interface else "[dim]?[/dim]"
    _kv("[*]", "green", "interface", iface)

    # Link: SSID + canal + sinal + taxa, o que estiver disponível.
    link = getattr(net, "link", None) or {}
    link_bits = []
    channel = link.get("channel") or channel_from_freq(link.get("freq"))
    if channel:
        band = "5GHz" if 30 <= channel <= 180 else ("6GHz" if channel > 180 else "2.4GHz")
        link_bits.append(f"canal {channel} [dim]({band})[/dim]")
    if link.get("signal") is not None:
        sig = link["signal"]
        color = "bright_green" if sig > -60 else ("yellow" if sig > -72 else "red")
        link_bits.append(f"[{color}]{sig} dBm[/{color}]")
    if link.get("bitrate"):
        link_bits.append(f"{link['bitrate']:.0f} Mb/s")
    ssid = escape(net.ssid) if net.ssid else "[dim]desconhecida[/dim]"
    _kv("[*]", "green", "ssid", " [dim]·[/dim] ".join([ssid, *link_bits]))

    # Gateway com modelo, quando o UPnP contou.
    wan = getattr(net, "wan", None) or {}
    gw = net.gateway or "[dim]?[/dim]"
    if wan.get("model"):
        gw = f"{gw} [dim]· {escape(str(wan['model']))}[/dim]"
    _kv("[*]", "green", "gateway", gw)

    dns = getattr(net, "dns", None) or []
    if dns:
        _kv("[*]", "green", "dns", "[dim]" + ", ".join(dns) + "[/dim]")

    if wan.get("external_ip"):
        pub = f"[bold white]{wan['external_ip']}[/bold white]"
        if wan.get("uptime_s"):
            hrs = wan["uptime_s"] // 3600
            up = f"{hrs // 24}d {hrs % 24}h" if hrs >= 24 else f"{hrs}h"
            pub += f" [dim]· uplink {up}[/dim]"
        _kv("[*]", "green", "publico", pub)

    _kv("[*]", "green", "metodo", f"[dim]{method}[/dim]")
    silent = sum(1 for h in hosts if h.get("via") == "arp")
    counted = f"[bold bright_green]{len(hosts)}[/bold bright_green]"
    if silent:
        counted += f" [dim]({silent} só via ARP — ignoram ping)[/dim]"
    _kv("[+]", "bright_green", "hosts vivos", counted)

    # Contagem por tipo: dá a leitura da rede em uma linha.
    counts: dict[tuple[str, str], int] = {}
    for h in hosts:
        dev = h["device"]
        counts[(dev.label, dev.color)] = counts.get((dev.label, dev.color), 0) + 1
    if counts:
        # Só os tipos mais frequentes cabem numa linha; o resto vira "+N outros".
        ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0][0]))
        shown, rest = ordered[:6], ordered[6:]
        parts = [f"[{color}]{n} {label}[/{color}]" for (label, color), n in shown]
        if rest:
            parts.append(f"[dim]+{sum(n for _, n in rest)} outros[/dim]")
        _kv("[+]", "bright_green", "tipos", "[dim] · [/dim]".join(parts))

    new_count = sum(1 for h in hosts if h.get("is_new"))
    gone = list(getattr(diff, "gone", []) or [])
    ago = getattr(diff, "ago", None)
    if new_count:
        since = f" [dim](desde o scan de {ago} atrás)[/dim]" if ago else ""
        contagem = f"[bold bright_green]{new_count}[/bold bright_green]"
        _kv("[+]", "bright_green", "novos", f"{contagem}{since}")
    if gone:
        # Nome vindo da rede (mDNS/NetBIOS/UPnP): sem escape, um aparelho
        # chamado "[/bold]" derruba o render inteiro com MarkupError — e leva
        # junto a saída de toda a varredura.
        names = ", ".join(
            escape(str(g.get("name") or g.get("ip") or "?")) for g in gone[:4]
        ) + (" ..." if len(gone) > 4 else "")
        _kv("[-]", "yellow", "sairam", f"[yellow]{len(gone)}[/yellow] [dim]{names}[/dim]")

    if findings:
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        colors = {"alto": "bright_red", "medio": "yellow", "baixo": "bright_black"}
        parts = [
            f"[{colors[sev]}]{by_sev[sev]} {sev}[/{colors[sev]}]"
            for sev in ("alto", "medio", "baixo")
            if by_sev.get(sev)
        ]
        _kv("[!]", "yellow", "achados", "[dim] · [/dim]".join(parts))


_VENDOR_DROP = {
    "inc", "incorporated", "ltd", "co", "corp", "corporation", "technologies",
    "technology", "systems", "system", "electronics", "electronic", "gmbh",
    "llc", "company", "international", "communications", "communication",
    "networks", "network", "sa", "ag", "limited", "foundation", "interactive",
    "labs", "solutions", "group", "holdings", "devices", "entertainment",
}


def clean_vendor(vendor: Optional[str]) -> Optional[str]:
    """Encurta nomes de fabricante para exibição (ex.: 'Apple, Inc.' -> 'Apple')."""
    if not vendor:
        return None
    s = vendor.split(",")[0].strip()
    words = s.split()
    while words and words[-1].lower().strip(".,") in _VENDOR_DROP:
        words.pop()
    return " ".join(words) or s


_NAME_SUFFIXES = (".local", ".lan", ".home", ".localdomain", ".home.arpa")

_IP_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def clean_hostname(name: Optional[str]) -> Optional[str]:
    """Normaliza nomes vindos de rDNS/mDNS/NetBIOS para exibição.

    Roteadores costumam devolver FQDN redundante no DNS reverso, tipo
    ``GPT-2741GNAC-N1.GPT-2741GNAC-N1`` — colapsamos a repetição e cortamos
    sufixos de domínio local que não informam nada.
    """
    if not name:
        return None
    s = name.strip().rstrip(".")
    # PTR que devolve o próprio IP (ver enrich._reverse_dns): repetir o IP na
    # coluna HOST não informa nada e come a coluna mais larga da tabela.
    if _IP_LIKE.match(s):
        return None
    low = s.lower()
    for suf in _NAME_SUFFIXES:
        if low.endswith(suf):
            s = s[: -len(suf)]
            break
    parts = [p for p in s.split(".") if p]
    if not parts:
        return None
    # "X.X" ou "X.X.X" -> "X" (mesmo rótulo repetido no domínio)
    if len({p.lower() for p in parts}) == 1:
        return parts[0]
    return ".".join(parts)


def detail_text(host: dict) -> str:
    """Coluna DETALHE: o dado mais específico que conseguimos sobre o aparelho.

    Ordem de preferência: modelo anunciado pelo próprio aparelho (mDNS/UPnP) >
    banner de servidor > família de SO pelo TTL. Alertas curtos vão no fim.
    """
    banners = host.get("banners") or {}
    bits: list[str] = []

    # Tudo aqui veio da rede (nome, banner, modelo): escapar antes de virar
    # markup, senão um aparelho com "[" no nome quebra ou injeta estilo.
    model = host.get("model")
    if model:
        bits.append(f"[white]{escape(model)}[/white]")

    if not model:
        for key in ("http_title", "http_server", "rtsp_server", "ssh"):
            if banners.get(key):
                bits.append(f"[white]{escape(str(banners[key]))}[/white]")
                break
    elif banners.get("ssh"):
        bits.append(escape(str(banners["ssh"])))

    # "Linux/Apple" é o TTL da maioria dos aparelhos — dizer isso não informa
    # nada. Só vale mostrar a família de SO quando ela destoa.
    if not bits and host.get("os_family") in ("Windows", "rede/embarcado"):
        bits.append(f"[dim]{host['os_family']}[/dim]")
    if host.get("via") == "arp":
        # "stale" = o kernel tem o MAC mas não confirmou o vizinho nesta
        # varredura: pode ser um aparelho que já saiu e ainda não expirou.
        if host.get("arp_state") == "stale":
            bits.append("[yellow]ARP obsoleto[/yellow]")
        else:
            bits.append("[dim]só ARP[/dim]")
    for note in host.get("notes") or []:
        bits.append(f"[bright_red]{note}[/bright_red]")

    return " [dim]·[/dim] ".join(bits) if bits else "[dim]—[/dim]"


def print_findings(items: list, limit: int = 8) -> None:
    """Bloco '[!] achados' — o que a varredura viu e merece atenção."""
    if not items:
        return
    console.print("[bold yellow][!] achados[/bold yellow]")
    for f in items[:limit]:
        console.print(f"  [{f.color}][!][/{f.color}] {escape(f.message)}")
    if len(items) > limit:
        console.print(f"  [dim]... e mais {len(items) - limit}[/dim]")
    console.print()


def render_table(hosts: list[dict], net: NetInfo) -> None:
    """Renderiza a tabela de dispositivos, adaptando as colunas à largura."""
    if not hosts:
        console.print(
            "\n[yellow][!][/yellow] nenhum host vivo encontrado. "
            "[dim]tente com sudo/nmap ou verifique a conexão.[/dim]\n"
        )
        return

    # Colunas secundárias somem em terminais estreitos, na ordem inversa da
    # importância: primeiro os serviços brutos, por último o essencial.
    width = console.size.width
    show_rtt = width >= 92
    show_visto = width >= 104
    show_mac = width >= 124
    show_services = width >= 152

    table = Table(
        box=SQUARE,
        border_style="green",
        header_style="bold green",
        expand=False,
        pad_edge=False,
    )
    table.add_column("#", justify="right", style="dim green")
    table.add_column("TIPO", no_wrap=True)
    table.add_column("HOST", style="bold", overflow="fold")
    table.add_column("IP", no_wrap=True, style="bright_green")
    if show_mac:
        table.add_column("MAC", no_wrap=True, style="dim")
    table.add_column("FABRICANTE", overflow="fold")
    table.add_column("DETALHE", overflow="fold")
    if show_rtt:
        table.add_column("RTT", justify="right", no_wrap=True, style="dim")
    if show_visto:
        table.add_column("VISTO", no_wrap=True, style="dim")
    if show_services:
        table.add_column("SERVIÇOS", style="dim")

    any_inferred = False
    any_random = False

    for i, h in enumerate(hosts, 1):
        dev = h["device"]
        is_self = net.ip and h["ip"] == net.ip
        is_gw = net.gateway and h["ip"] == net.gateway

        clean = clean_hostname(h.get("name"))
        name = escape(clean) if clean else "[dim]—[/dim]"
        tag = ""
        if is_self:
            tag = " [dim green]« você[/dim green]"
        elif is_gw:
            tag = " [dim red]« gateway[/dim red]"
        if h.get("is_new"):
            tag += " [bold bright_green]« NOVO[/bold bright_green]"

        # "?" = tipo inferido (palpite), não falha de leitura.
        mark = ""
        if h.get("inferred"):
            mark = " [dim]?[/dim]"
            any_inferred = True
        type_cell = Text.from_markup(f"[{dev.color}]▪ {dev.label}[/{dev.color}]{mark}")

        vendor = clean_vendor(h.get("vendor"))
        if vendor:
            vendor = escape(vendor)
        elif h.get("random_mac"):
            vendor = "[dim italic]aleatório[/dim italic]"
            any_random = True
        else:
            vendor = "[dim]?[/dim]"

        row = [
            str(i),
            type_cell,
            Text.from_markup(f"{name}{tag}"),
            h["ip"],
        ]
        if show_mac:
            row.append(h.get("mac") or "[dim]—[/dim]")
        row.append(Text.from_markup(vendor))
        row.append(Text.from_markup(detail_text(h)))
        if show_rtt:
            rtt = h.get("rtt")
            if rtt is None:
                row.append("[dim]—[/dim]")
            else:
                row.append(f"{rtt:.1f}ms" if rtt < 10 else f"{rtt:.0f}ms")
        if show_visto:
            row.append(seen_label(h, first_run=bool(h.get("history_off"))))
        if show_services:
            services = escape(", ".join(sorted(h.get("services") or []))) or "[dim]—[/dim]"
            row.append(services)
        table.add_row(*row)

    console.print()
    console.print(table)

    legend = []
    if any_inferred:
        legend.append("[bold]?[/bold] = tipo inferido")
    if any_random:
        legend.append("[bold]aleatório[/bold] = MAC privado (iOS/Android)")
    if legend:
        console.print(f"[dim]› {' · '.join(legend)}[/dim]")
    console.print(
        "[dim]› [bold]--json[/bold] para saída estruturada · "
        "[bold]-h[/bold] para todas as opções[/dim]\n"
    )


def to_json(hosts: list[dict], net: NetInfo, findings: Optional[list] = None) -> str:
    """Serializa o resultado em JSON."""
    payload = {
        "network": {
            "ssid": net.ssid,
            "interface": net.interface,
            "local_ip": net.ip,
            "gateway": net.gateway,
            "cidr": net.cidr,
            "link": getattr(net, "link", {}) or {},
            "dns": getattr(net, "dns", []) or [],
            "wan": getattr(net, "wan", {}) or {},
        },
        "hosts": [
            {
                "ip": h["ip"],
                "mac": h.get("mac"),
                "random_mac": bool(h.get("random_mac")),
                "name": clean_hostname(h.get("name")),
                "vendor": h.get("vendor"),
                "model": h.get("model"),
                "type": h["device"].label,
                "type_inferred": bool(h.get("inferred")),
                "os_family": h.get("os_family"),
                "banners": h.get("banners") or {},
                "services": sorted(h.get("services") or []),
                "rtt_ms": h.get("rtt"),
                "ttl": h.get("ttl"),
                "discovered_via": h.get("via"),
                "arp_state": h.get("arp_state"),
                "is_new": bool(h.get("is_new")),
                "first_seen": h.get("first_seen"),
                "seen_count": h.get("seen_count"),
                "presence": h.get("presence"),
                "is_gateway": bool(net.gateway and h["ip"] == net.gateway),
                "is_self": bool(net.ip and h["ip"] == net.ip),
            }
            for h in hosts
        ],
        "findings": [
            {"severity": f.severity, "ip": f.ip, "message": f.message}
            for f in (findings or [])
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def print_events(hosts: list[dict], diff: Optional[object]) -> None:
    """Linhas de entrada/saída de dispositivos (usado pelo --watch)."""
    for h in hosts:
        if h.get("is_new"):
            name = escape(clean_hostname(h.get("name")) or h["ip"])
            console.print(
                f"[bold bright_green][+][/bold bright_green] entrou: "
                f"[bold]{name}[/bold] [dim]{h['ip']} · {h['device'].label}[/dim]"
            )
    for g in getattr(diff, "gone", []) or []:
        name = escape(str(g.get("name") or g.get("ip")))
        console.print(
            f"[yellow][-][/yellow] saiu: [bold]{name}[/bold] [dim]{g.get('ip')}[/dim]"
        )


def error(msg: str) -> None:
    console.print(f"[bold red][!][/bold red] {msg}")


def warn(msg: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def info(msg: str) -> None:
    console.print(f"[green][*][/green] {msg}")
