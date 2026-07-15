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


def print_summary(net: NetInfo, host_count: int, method: str) -> None:
    """Imprime o resumo da rede em formato de saída de ferramenta de recon."""
    console.print()
    _kv("[*]", "green", "alvo", f"[bold green]{net.cidr or '?'}[/bold green]")
    _kv("[*]", "green", "interface", net.interface or "[dim]?[/dim]")
    _kv("[*]", "green", "ssid", net.ssid or "[dim]desconhecida[/dim]")
    _kv("[*]", "green", "gateway", net.gateway or "[dim]?[/dim]")
    _kv("[*]", "green", "metodo", f"[dim]{method}[/dim]")
    _kv(
        "[+]", "bright_green", "hosts vivos",
        f"[bold bright_green]{host_count}[/bold bright_green]",
    )


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

    for i, h in enumerate(hosts, 1):
        dev = h["device"]
        is_self = net.ip and h["ip"] == net.ip
        is_gw = net.gateway and h["ip"] == net.gateway

        name = h.get("name") or "[dim]—[/dim]"
        tag = ""
        if is_self:
            tag = " [dim green]« você[/dim green]"
        elif is_gw:
            tag = " [dim red]« gateway[/dim red]"

        type_cell = Text.from_markup(f"[{dev.color}]▪ {dev.label}[/{dev.color}]")
        vendor = clean_vendor(h.get("vendor")) or "[dim]?[/dim]"

        row = [
            str(i),
            type_cell,
            Text.from_markup(f"{name}{tag}"),
            h["ip"],
        ]
        if show_mac:
            row.append(h.get("mac") or "[dim]—[/dim]")
        row.append(vendor)
        if show_services:
            services = ", ".join(sorted(h.get("services") or [])) or "[dim]—[/dim]"
            row.append(services)
        table.add_row(*row)

    console.print()
    console.print(table)
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
                "name": h.get("name"),
                "vendor": h.get("vendor"),
                "type": h["device"].label,
                "services": sorted(h.get("services") or []),
                "is_gateway": bool(net.gateway and h["ip"] == net.gateway),
                "is_self": bool(net.ip and h["ip"] == net.ip),
            }
            for h in hosts
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def error(msg: str) -> None:
    console.print(f"[bold red][!][/bold red] {msg}")


def info(msg: str) -> None:
    console.print(f"[green][*][/green] {msg}")
