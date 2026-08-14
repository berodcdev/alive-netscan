"""Apresentação: banner, tabela colorida (rich) e saída JSON."""

from __future__ import annotations

import json
from typing import Optional

from rich.box import SQUARE
from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __author_email__, __version__
from .net import NetInfo

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
) -> None:
    """Imprime o resumo da rede em formato de saída de ferramenta de recon."""
    console.print()
    _kv("[*]", "green", "alvo", f"[bold green]{net.cidr or '?'}[/bold green]")
    _kv("[*]", "green", "interface", net.interface or "[dim]?[/dim]")
    _kv("[*]", "green", "ssid", net.ssid or "[dim]desconhecida[/dim]")
    _kv("[*]", "green", "gateway", net.gateway or "[dim]?[/dim]")
    _kv("[*]", "green", "metodo", f"[dim]{method}[/dim]")
    _kv(
        "[+]", "bright_green", "hosts vivos",
        f"[bold bright_green]{len(hosts)}[/bold bright_green]",
    )

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
        _kv("[+]", "bright_green", "novos", f"[bold bright_green]{new_count}[/bold bright_green]{since}")
    if gone:
        names = ", ".join(
            f"{g.get('name') or g.get('ip')}" for g in gone[:4]
        ) + (" ..." if len(gone) > 4 else "")
        _kv("[-]", "yellow", "sairam", f"[yellow]{len(gone)}[/yellow] [dim]{names}[/dim]")


_VENDOR_DROP = {
    "inc", "incorporated", "ltd", "co", "corp", "corporation", "technologies",
    "technology", "systems", "system", "electronics", "electronic", "gmbh",
    "llc", "company", "international", "communications", "communication",
    "networks", "network", "sa", "ag", "limited", "foundation", "interactive",
    "labs", "solutions", "group", "holdings", "devices",
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


def clean_hostname(name: Optional[str]) -> Optional[str]:
    """Normaliza nomes vindos de rDNS/mDNS/NetBIOS para exibição.

    Roteadores costumam devolver FQDN redundante no DNS reverso, tipo
    ``GPT-2741GNAC-N1.GPT-2741GNAC-N1`` — colapsamos a repetição e cortamos
    sufixos de domínio local que não informam nada.
    """
    if not name:
        return None
    s = name.strip().rstrip(".")
    low = s.lower()
    for suf in _NAME_SUFFIXES:
        if low.endswith(suf):
            s = s[: -len(suf)]
            break
    parts = [p for p in s.split(".") if p]
    if not parts:
        return None
    # "X.X" ou "X.X.X" -> "X" (mesmo rótulo repetido no domínio)
    if len(set(p.lower() for p in parts)) == 1:
        return parts[0]
    return ".".join(parts)


def render_table(hosts: list[dict], net: NetInfo) -> None:
    """Renderiza a tabela de dispositivos, adaptando as colunas à largura."""
    if not hosts:
        console.print(
            "\n[yellow][!][/yellow] nenhum host vivo encontrado. "
            "[dim]tente com sudo/nmap ou verifique a conexão.[/dim]\n"
        )
        return

    # Colunas secundárias somem em terminais estreitos para manter a leitura fácil.
    width = console.size.width
    show_mac = width >= 82
    show_services = width >= 104

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
    if show_services:
        table.add_column("SERVIÇOS", style="dim")

    any_inferred = False
    any_random = False

    for i, h in enumerate(hosts, 1):
        dev = h["device"]
        is_self = net.ip and h["ip"] == net.ip
        is_gw = net.gateway and h["ip"] == net.gateway

        name = clean_hostname(h.get("name")) or "[dim]—[/dim]"
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
        if not vendor:
            if h.get("random_mac"):
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
        if show_services:
            services = ", ".join(sorted(h.get("services") or [])) or "[dim]—[/dim]"
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
        f"[dim]› [bold]--json[/bold] para saída estruturada · "
        f"[bold]-h[/bold] para todas as opções[/dim]\n"
    )


def to_json(hosts: list[dict], net: NetInfo) -> str:
    """Serializa o resultado em JSON."""
    payload = {
        "network": {
            "ssid": net.ssid,
            "interface": net.interface,
            "local_ip": net.ip,
            "gateway": net.gateway,
            "cidr": net.cidr,
        },
        "hosts": [
            {
                "ip": h["ip"],
                "mac": h.get("mac"),
                "random_mac": bool(h.get("random_mac")),
                "name": clean_hostname(h.get("name")),
                "vendor": h.get("vendor"),
                "type": h["device"].label,
                "type_inferred": bool(h.get("inferred")),
                "services": sorted(h.get("services") or []),
                "is_new": bool(h.get("is_new")),
                "is_gateway": bool(net.gateway and h["ip"] == net.gateway),
                "is_self": bool(net.ip and h["ip"] == net.ip),
            }
            for h in hosts
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def print_events(hosts: list[dict], diff: Optional[object]) -> None:
    """Linhas de entrada/saída de dispositivos (usado pelo --watch)."""
    for h in hosts:
        if h.get("is_new"):
            name = clean_hostname(h.get("name")) or h["ip"]
            console.print(
                f"[bold bright_green][+][/bold bright_green] entrou: "
                f"[bold]{name}[/bold] [dim]{h['ip']} · {h['device'].label}[/dim]"
            )
    for g in getattr(diff, "gone", []) or []:
        name = g.get("name") or g.get("ip")
        console.print(
            f"[yellow][-][/yellow] saiu: [bold]{name}[/bold] [dim]{g.get('ip')}[/dim]"
        )


def error(msg: str) -> None:
    console.print(f"[bold red][!][/bold red] {msg}")


def warn(msg: str) -> None:
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def info(msg: str) -> None:
    console.print(f"[green][*][/green] {msg}")
