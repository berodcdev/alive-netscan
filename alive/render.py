"""Apresentação: banner, tabela colorida (rich) e saída JSON."""

from __future__ import annotations

import csv
import io
import json
import re
import time
from typing import Optional

from rich.box import SQUARE
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from . import __version__
from .findings import SEVERITY_COLOR, SEVERITY_ORDER
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


def _print_hanging(head: Text, value: Text) -> None:
    """Imprime ``head`` + ``value``, com as linhas seguintes alinhadas sob o valor.

    Feito à mão porque ``Table.grid`` resolveria o alinhamento mas preenche
    cada célula até a borda — o que enche a saída de espaços no fim da linha,
    visível assim que alguém redireciona para um arquivo.
    """
    recuo = head.cell_len
    linhas = value.wrap(console, max(20, console.size.width - recuo))
    if not linhas:
        console.print(head)
        return
    # Text.rstrip() do rich altera em lugar e devolve None.
    for linha in linhas:
        linha.rstrip()
    console.print(head + linhas[0])
    espacos = Text(" " * recuo)
    for extra in linhas[1:]:
        console.print(espacos + extra)


def _kv(prefix: str, prefix_style: str, label: str, value: str) -> None:
    """Linha estilo recon: '[*] label ........ value'.

    Um valor comprido quebra alinhado sob si mesmo; como texto solto ele
    voltava para a coluna zero e partia no meio de um item.
    """
    dots = "." * max(2, 13 - len(label))
    head = Text.from_markup(
        f"[{prefix_style}]{prefix}[/{prefix_style}] "
        f"[bold white]{label}[/bold white] [dim]{dots}[/dim] "
    )
    _print_hanging(head, Text.from_markup(value))


def print_summary(
    net: NetInfo,
    hosts: list[dict],
    method: str,
    diff: Optional[object] = None,
    findings: Optional[list] = None,
    passive: bool = False,
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
    silent = 0 if passive else sum(1 for h in hosts if h.get("via") == "arp")
    counted = f"[bold bright_green]{len(hosts)}[/bold bright_green]"
    if silent:
        counted += f" [dim]({silent} só via ARP — ignoram ping)[/dim]"
    elif passive:
        # Em modo passivo ninguém foi pingado: dizer "ignoram ping" seria falso.
        counted += " [dim](do cache ARP — só quem já conversou com esta máquina)[/dim]"
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


# A base OUI mistura caixas: vem "zte" ao lado de "Samsung" e "TP-LINK". Siglas
# têm grafia própria; o resto cai num Title Case simples.
_VENDOR_CASE = {
    "zte": "ZTE", "hp": "HP", "lg": "LG", "tcl": "TCL", "asus": "ASUS",
    "asustek": "ASUSTek", "msi": "MSI", "amd": "AMD", "ibm": "IBM",
    "tp-link": "TP-Link", "d-link": "D-Link", "htc": "HTC", "lge": "LGE",
    "arris": "ARRIS", "adtran": "ADTRAN", "avm": "AVM", "nec": "NEC",
    "sagemcom": "Sagemcom", "askey": "Askey", "cig": "CIG", "fiberhome": "FiberHome",
}


def _fix_case(word: str) -> str:
    conhecido = _VENDOR_CASE.get(word.lower())
    if conhecido:
        return conhecido
    # Só mexe em quem veio todo minúsculo ou todo maiúsculo; nomes que já têm
    # caixa mista ("iRobot", "NetGear") foram escritos assim de propósito.
    if word.islower() or word.isupper():
        return word.capitalize()
    return word


def clean_vendor(vendor: Optional[str]) -> Optional[str]:
    """Encurta e normaliza o fabricante (ex.: 'Apple, Inc.' -> 'Apple')."""
    if not vendor:
        return None
    s = vendor.split(",")[0].strip()
    words = s.split()
    while words and words[-1].lower().strip(".,") in _VENDOR_DROP:
        words.pop()
    words = words or s.split()
    return " ".join(_fix_case(w) for w in words)


_NAME_SUFFIXES = (".local", ".lan", ".home", ".localdomain", ".home.arpa")

_IP_LIKE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Célula sem informação. Uma constante porque a tabela precisa reconhecê-la
# para não empilhar dois placeholders na mesma coluna.
VAZIO = "[dim]—[/dim]"


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
    snmp = host.get("snmp") or {}
    tls = host.get("tls") or {}
    bits: list[str] = []

    # Tudo aqui veio da rede (nome, banner, modelo): escapar antes de virar
    # markup, senão um aparelho com "[" no nome quebra ou injeta estilo.
    model = host.get("model")
    if model:
        bits.append(f"[white]{escape(model)}[/white]")

    if not model:
        # sysDescr do SNMP é frequentemente o dado mais rico ("Linux nas 5.10").
        if snmp.get("descr"):
            bits.append(f"[white]{escape(str(snmp['descr']))}[/white]")
        else:
            for key in ("http_title", "http_server", "rtsp_server", "ssh"):
                if banners.get(key):
                    bits.append(f"[white]{escape(str(banners[key]))}[/white]")
                    break
            else:
                if tls.get("subject_cn"):
                    bits.append(f"[white]{escape(str(tls['subject_cn']))}[/white]")
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

    return " [dim]·[/dim] ".join(bits) if bits else VAZIO


# Marcador e rótulo por severidade. O resumo prometia "3 alto · 2 baixo" e
# depois imprimia todo achado com o mesmo "[!]" — sem dizer qual era qual.
_SEV_MARK = {"alto": ("[!]", "ALTO"), "medio": ("[!]", "MÉDIO"), "baixo": ("[·]", "BAIXO")}
# Marca de uma letra na coluna "!" da tabela, ligando host e achado.
_SEV_TABLE_MARK = {"alto": "!", "medio": "!", "baixo": "·"}


def print_findings(items: list, limit: int = 8) -> None:
    """Bloco '[!] achados' — o que a varredura viu e merece atenção."""
    if not items:
        return
    console.print("[bold yellow][!] achados[/bold yellow]")
    for f in items[:limit]:
        mark, rotulo = _SEV_MARK.get(f.severity, ("[!]", f.severity.upper()))
        _print_hanging(
            Text.from_markup(f"  [{f.color}]{mark} {rotulo:<5}[/{f.color}] "),
            Text.from_markup(escape(f.message)),
        )
        if getattr(f, "fix", None):
            # A seta entra no cabeçalho para que a continuação alinhe sob o
            # texto da ação, e não sob a seta.
            _print_hanging(
                Text(" " * 12 + "→ ", style="dim"),
                Text.from_markup(f"[dim]{escape(f.fix)}[/dim]"),
            )
    if len(items) > limit:
        console.print(f"  [dim]... e mais {len(items) - limit}[/dim]")
    console.print()


def _worst_by_ip(items: Optional[list]) -> dict[str, str]:
    """Pior severidade por host, para marcar a linha na tabela."""
    pior: dict[str, str] = {}
    for f in items or []:
        if not f.ip:
            continue
        atual = pior.get(f.ip)
        if atual is None or SEVERITY_ORDER.get(f.severity, 9) < SEVERITY_ORDER.get(atual, 9):
            pior[f.ip] = f.severity
    return pior


def print_footer(elapsed_s: float, scanned: int, hosts: list[dict]) -> None:
    """Rodapé: o que a varredura custou."""
    console.print(
        f"[dim]› {len(hosts)} vivos de {scanned} endereços "
        f"em {elapsed_s:.1f}s[/dim]"
    )


def render_table(
    hosts: list[dict], net: NetInfo, findings: Optional[list] = None
) -> None:
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
    alertas = _worst_by_ip(findings)
    show_alert = bool(alertas)
    # Abaixo de ~92 col o fabricante vira prefixo do DETALHE: são os dois dados
    # que competem pelo espaço e, separados, nenhum dos dois cabe inteiro.
    compact = width < 92
    # O "#" não é referenciável por nenhum comando — é o primeiro a sair.
    show_num = width >= 100
    show_rtt = width >= 92
    show_visto = width >= 104
    show_mac = width >= 124
    show_services = width >= 152

    table = Table(
        box=SQUARE,
        border_style="green",
        header_style="bold green",
        expand=False,
    )
    if show_num:
        table.add_column("#", justify="right", style="dim green")
    if show_alert:
        table.add_column("!", no_wrap=True, justify="center")
    table.add_column("TIPO", no_wrap=True)
    # ellipsis, não fold: quebrar no meio da palavra ("meu-noteboo/k") custa
    # duas linhas e não deixa o nome mais legível do que "meu-notebook…".
    table.add_column("HOST", style="bold", no_wrap=True, overflow="ellipsis",
                     min_width=6)
    table.add_column("IP", no_wrap=True, style="bright_green")
    if show_mac:
        table.add_column("MAC", no_wrap=True, style="dim")
    if not compact:
        table.add_column("FABRICANTE", overflow="ellipsis")
    table.add_column("DETALHE", overflow="ellipsis", min_width=8)
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

        limpo = clean_vendor(h.get("vendor"))
        vendor_conhecido = True
        if limpo:
            vendor = escape(limpo)
        elif h.get("random_mac"):
            vendor = "[dim italic]aleatório[/dim italic]"
            any_random = True
        else:
            vendor = "[dim]?[/dim]"
            vendor_conhecido = False

        row: list = []
        if show_num:
            row.append(str(i))
        if show_alert:
            sev = alertas.get(h["ip"])
            row.append(
                Text.from_markup(
                    f"[{SEVERITY_COLOR[sev]}]{_SEV_TABLE_MARK[sev]}[/]" if sev else ""
                )
            )
        row.append(type_cell)
        row.append(Text.from_markup(f"{name}{tag}"))
        row.append(h["ip"])
        if show_mac:
            row.append(h.get("mac") or "[dim]—[/dim]")
        detalhe = detail_text(h)
        if compact:
            # Sem coluna própria, o fabricante abre o DETALHE — mas juntar dois
            # placeholders ("? · —") é pior do que mostrar um só.
            tem_detalhe = detalhe != VAZIO
            if vendor_conhecido and tem_detalhe:
                celula = f"{vendor} [dim]·[/dim] {detalhe}"
            elif vendor_conhecido:
                celula = vendor
            else:
                celula = detalhe
            row.append(Text.from_markup(celula))
        else:
            row.append(Text.from_markup(vendor))
            row.append(Text.from_markup(detalhe))
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
    if show_alert:
        legend.append("[bold]![/bold] = tem achado abaixo")
    if any_inferred:
        legend.append("[bold]?[/bold] = tipo inferido")
    if any_random:
        legend.append("[bold]aleatório[/bold] = MAC privado (iOS/Android)")
    seta = Text("› ", style="dim")
    if legend:
        _print_hanging(seta, Text.from_markup(f"[dim]{' · '.join(legend)}[/dim]"))
    _print_hanging(
        seta,
        Text.from_markup(
            "[dim][bold]--json[/bold] para saída estruturada · "
            "[bold]-h[/bold] para todas as opções[/dim]"
        ),
    )
    console.print()


def to_json(
    hosts: list[dict],
    net: NetInfo,
    findings: Optional[list] = None,
    *,
    indent: Optional[int] = 2,
    extra: Optional[dict] = None,
) -> str:
    """Serializa o resultado em JSON. ``indent=None`` produz uma linha só."""
    payload: dict = {}
    if extra:
        payload.update(extra)
    payload.update({
        "network": {
            "ssid": net.ssid,
            "interface": net.interface,
            "local_ip": net.ip,
            "gateway": net.gateway,
            "cidr": net.cidr,
            "link": getattr(net, "link", {}) or {},
            "dns": getattr(net, "dns", []) or [],
            "wan": getattr(net, "wan", {}) or {},
            "dhcp_servers": getattr(net, "dhcp", None) or [],
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
                "snmp": h.get("snmp") or {},
                "tls": h.get("tls") or {},
                "services": sorted(h.get("services") or []),
                "mdns_services": h.get("mdns_services") or [],
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
            {"severity": f.severity, "ip": f.ip, "message": f.message,
             "fix": getattr(f, "fix", None)}
            for f in (findings or [])
        ],
    })
    return json.dumps(payload, ensure_ascii=False, indent=indent)


def to_targets(hosts: list[dict]) -> str:
    """Só os IPs, um por linha — para alimentar nmap, masscan, um for no shell."""
    return "\n".join(h["ip"] for h in hosts)


_CSV_COLUNAS = (
    "ip", "mac", "name", "vendor", "type", "os_family",
    "services", "rtt_ms", "discovered_via",
)


def to_csv(hosts: list[dict]) -> str:
    """Uma linha por host, colunas estáveis — para planilha ou pipeline."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(_CSV_COLUNAS)
    for h in hosts:
        writer.writerow([
            h["ip"],
            h.get("mac") or "",
            clean_hostname(h.get("name")) or "",
            h.get("vendor") or "",
            h["device"].label if h.get("device") else "",
            h.get("os_family") or "",
            " ".join(sorted(h.get("services") or [])),
            h.get("rtt") if h.get("rtt") is not None else "",
            h.get("via") or "",
        ])
    return buf.getvalue().rstrip("\n")


def watch_line(
    cycle: int, hosts: list[dict], net: NetInfo, findings: Optional[list], diff: object
) -> str:
    """Uma linha NDJSON por ciclo do --watch: o estado e o que mudou nele.

    ``--watch --json`` antes não emitia nada: o laço de monitoramento nunca
    serializava, o que deixava o modo inútil para automação.
    """
    eventos: list[dict] = [
        {
            "event": "entrou",
            "ip": h["ip"],
            "name": clean_hostname(h.get("name")),
            "type": h["device"].label,
        }
        for h in hosts
        if h.get("is_new")
    ]
    eventos += [
        {
            "event": "saiu",
            "ip": g.get("ip"),
            "name": clean_hostname(g.get("name")),
            "type": g.get("type"),
        }
        for g in (getattr(diff, "gone", None) or [])
    ]
    return to_json(
        hosts, net, findings, indent=None,
        extra={"cycle": cycle, "time": time.time(), "events": eventos},
    )


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
