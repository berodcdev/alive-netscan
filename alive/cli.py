"""Interface de linha de comando do `alive`."""

from __future__ import annotations

import argparse
import ipaddress
import sys
from typing import Optional

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import __author_email__, __version__, classify, enrich, net, render, scanner

DESCRIPTION = """\
[bold green]alive[/bold green] — reconhecimento de hosts na rede local [dim](WiFi/LAN · macOS + Linux)[/dim]

Varre a subrede, enumera cada host vivo e faz fingerprint de IP, MAC, fabricante
e tipo de dispositivo (roteador, computador, celular, TV, assistente, IoT...).\
"""

EPILOG = """\
[bold green]exemplos[/bold green]
  [green]alive[/green]                          [dim]# varre a rede WiFi atual[/dim]
  [green]alive --fast[/green]                   [dim]# rápido: só ping sweep + ARP[/dim]
  [green]alive -n 192.168.0.0/24[/green]        [dim]# varre uma subrede específica[/dim]
  [green]alive --sort type[/green]              [dim]# agrupa por tipo de dispositivo[/dim]
  [green]alive --json > recon.json[/green]      [dim]# exporta o resultado em JSON[/dim]

[bold green]nota[/bold green]
  Instale o [bold]nmap[/bold] e/ou rode com [bold]sudo[/bold] para uma varredura mais completa.

[bold yellow][!] uso autorizado[/bold yellow]
  Use o alive [bold]somente[/bold] em redes que você administra ou tem [bold]autorização
  explícita[/bold] para auditar. Escanear redes de terceiros pode ser ilegal.

[dim]{email}[/dim]\
""".format(email=__author_email__)


def build_parser() -> argparse.ArgumentParser:
    """Monta o parser com help colorido (rich-argparse quando disponível)."""
    formatter = argparse.RawDescriptionHelpFormatter
    try:
        # RawDescription* preserva as quebras de linha do texto (descrição/exemplos)
        # e ainda colore os argumentos.
        from rich_argparse import RawDescriptionRichHelpFormatter as _RF

        _RF.styles["argparse.prog"] = "bold green"
        _RF.styles["argparse.groups"] = "bold green"
        _RF.styles["argparse.args"] = "bold green"
        _RF.styles["argparse.metavar"] = "dim green"
        _RF.styles["argparse.help"] = "default"
        _RF.styles["argparse.text"] = "default"
        _RF.usage_markup = True
        # Manter a capitalização exata dos títulos de grupo (sem Title Case).
        _RF.group_name_formatter = str
        formatter = _RF  # type: ignore[assignment]
    except ImportError:
        pass

    parser = argparse.ArgumentParser(
        prog="alive",
        description=DESCRIPTION,
        epilog=EPILOG,
        formatter_class=formatter,
        add_help=False,  # recriamos o -h com texto em português
    )

    geral = parser.add_argument_group("geral")
    geral.add_argument(
        "-h", "--help", action="help",
        help="mostra esta ajuda e sai.",
    )
    geral.add_argument(
        "--version", action="version",
        version=f"[bold green]alive[/bold green] {__version__} · {__author_email__}",
        help="mostra a versão e sai.",
    )
    geral.add_argument(
        "--demo", action="store_true",
        help="mostra uma demonstração com dados fictícios (não escaneia nada).",
    )

    alvo = parser.add_argument_group("alvo")
    alvo.add_argument(
        "-n", "--network", metavar="CIDR",
        help="subrede a escanear, ex.: 192.168.0.0/24 [dim](padrão: detecta sozinho)[/dim].",
    )
    alvo.add_argument(
        "-i", "--interface", metavar="IF",
        help="interface de rede, ex.: en0, wlan0 [dim](padrão: a da rota padrão)[/dim].",
    )

    veloc = parser.add_argument_group("varredura")
    veloc.add_argument(
        "--fast", action="store_true",
        help="modo rápido: pula mDNS e fabricante (equivale a --no-mdns --no-vendor).",
    )
    veloc.add_argument(
        "--no-nmap", action="store_true",
        help="não usar o nmap, mesmo instalado (força o ping sweep).",
    )
    veloc.add_argument(
        "--no-mdns", action="store_true",
        help="pular a descoberta de nomes via mDNS/Bonjour.",
    )
    veloc.add_argument(
        "--no-vendor", action="store_true",
        help="pular a identificação do fabricante pelo MAC.",
    )
    veloc.add_argument(
        "-t", "--timeout", type=float, default=1.0, metavar="SEG",
        help="tempo de espera do ping por host [dim](padrão: 1.0s)[/dim].",
    )
    veloc.add_argument(
        "-w", "--workers", type=int, default=64, metavar="N",
        help="quantos pings em paralelo [dim](padrão: 64)[/dim].",
    )
    veloc.add_argument(
        "--mdns-time", type=float, default=3.0, metavar="SEG",
        help="tempo ouvindo anúncios mDNS/Bonjour [dim](padrão: 3.0s)[/dim].",
    )

    saida = parser.add_argument_group("saída")
    saida.add_argument(
        "--sort", choices=("ip", "name", "type"), default="ip",
        help="como ordenar a tabela: ip, name ou type [dim](padrão: ip)[/dim].",
    )
    saida.add_argument(
        "-j", "--json", action="store_true",
        help="imprimir em JSON em vez da tabela colorida.",
    )
    saida.add_argument(
        "-v", "--verbose", action="store_true",
        help="mostrar detalhes de diagnóstico (e o traceback em erros).",
    )
    return parser


def _resolve_network(
    args: argparse.Namespace, netinfo: net.NetInfo
) -> Optional[ipaddress.IPv4Network]:
    if args.network:
        try:
            return ipaddress.ip_network(args.network, strict=False)  # type: ignore[return-value]
        except ValueError:
            render.error(f"CIDR inválido: {args.network}")
            return None
    return netinfo.network


def _sort_hosts(hosts: list[dict], key: str) -> list[dict]:
    if key == "name":
        return sorted(hosts, key=lambda h: (h.get("name") or "~").lower())
    if key == "type":
        return sorted(hosts, key=lambda h: h["device"].label)
    return sorted(hosts, key=lambda h: ipaddress.ip_address(h["ip"]))


def run(args: argparse.Namespace) -> int:
    if getattr(args, "demo", False):
        return _run_demo(args)

    # --fast é um atalho para --no-mdns --no-vendor.
    if getattr(args, "fast", False):
        args.no_mdns = True
        args.no_vendor = True

    # 1) Descobrir a rede local.
    netinfo = net.discover()
    if args.interface:
        netinfo.interface = args.interface
        netinfo.network = net.get_network_for_interface(args.interface, netinfo.ip)
        netinfo.ssid = net.get_ssid(args.interface)

    network = _resolve_network(args, netinfo)
    if network is None:
        render.error(
            "não foi possível determinar a subrede. "
            "Use -n para especificar (ex.: -n 192.168.0.0/24)."
        )
        return 2
    netinfo.network = network

    use_nmap = (not args.no_nmap) and scanner.has_nmap()
    method = "nmap + ping sweep + ARP" if use_nmap else "ping sweep + ARP"

    if not args.json:
        render.print_banner()
        render.info(
            f"varrendo [bold green]{netinfo.cidr}[/bold green] "
            f"[dim]({method})[/dim]"
        )

    # 2) Scan (com barra de progresso, exceto em modo JSON).
    total = max(1, network.num_addresses - 2)
    if args.json:
        hosts_raw = scanner.scan(
            network, use_nmap=use_nmap, timeout=args.timeout,
            workers=args.workers, local_ip=netinfo.ip, gateway=netinfo.gateway,
        )
    else:
        with Progress(
            SpinnerColumn(style="green"),
            TextColumn("[green]ping sweep[/green]"),
            BarColumn(bar_width=30, complete_style="green", finished_style="bright_green"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=render.console,
            transient=True,
        ) as progress:
            task = progress.add_task("scan", total=total)
            hosts_raw = scanner.scan(
                network, use_nmap=use_nmap, timeout=args.timeout,
                workers=args.workers, local_ip=netinfo.ip, gateway=netinfo.gateway,
                progress=lambda: progress.advance(task),
            )
            progress.update(task, completed=total)

    ips = [h["ip"] for h in hosts_raw]
    macs = [h["mac"] for h in hosts_raw if h["mac"]]

    # 3) Enriquecimento.
    hostnames = enrich.resolve_hostnames(ips)
    vendors = {} if args.no_vendor else enrich.lookup_vendors(macs)
    mdns = {} if args.no_mdns else _run_mdns(args, netinfo, has_json=args.json)

    # Nome do próprio host: sabemos com certeza (é a máquina que roda o alive).
    local_name = _local_hostname()

    # 4) Classificação + montagem final.
    hosts: list[dict] = []
    for h in hosts_raw:
        ip = h["ip"]
        mac = h["mac"]
        is_self = bool(netinfo.ip and ip == netinfo.ip)
        m = mdns.get(ip, {})
        services = set(m.get("services") or [])
        hostname = hostnames.get(ip)
        mdns_name = m.get("name")
        vendor = vendors.get(mac) if mac else None
        dev = classify.classify(
            ip=ip, mac=mac, vendor=vendor, hostname=hostname,
            mdns_name=mdns_name, services=services, gateway=netinfo.gateway,
        )
        name = mdns_name or hostname
        # O host local é sempre um computador; usamos seu hostname se nada melhor.
        if is_self:
            if dev is classify.UNKNOWN:
                dev = classify.COMPUTER
            name = name or local_name
        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "name": name,
                "vendor": vendor,
                "services": services,
                "device": dev,
            }
        )

    hosts = _sort_hosts(hosts, args.sort)

    # 5) Saída.
    if args.json:
        print(render.to_json(hosts, netinfo))
    else:
        render.print_summary(netinfo, host_count=len(hosts), method=method)
        render.render_table(hosts, netinfo)
    return 0


def _run_demo(args: argparse.Namespace) -> int:
    """Renderiza uma saída de exemplo com dados fictícios (docs/testes/GIF)."""
    demo_net = net.NetInfo(
        interface="en0",
        ip="192.168.0.42",
        network=ipaddress.ip_network("192.168.0.0/24"),
        gateway="192.168.0.1",
        ssid="CASA-2.4G",
    )

    def host(ip, mac, name, vendor, dev, services=()):
        return {
            "ip": ip, "mac": mac, "name": name, "vendor": vendor,
            "services": set(services), "device": dev,
        }

    C = classify
    hosts = [
        host("192.168.0.1", "a4:2b:8c:1f:07:e3", None, "TP-Link Systems Inc.", C.ROUTER),
        host("192.168.0.42", "f0:18:98:2a:1b:cd", "meu-notebook", "Apple, Inc.", C.COMPUTER, ("ssh", "workstation")),
        host("192.168.0.51", "3c:5a:b4:77:21:9f", "Galaxy-S23", "Samsung Electronics Co.,Ltd", C.PHONE),
        host("192.168.0.60", "54:60:09:aa:bb:12", "Sala (Chromecast)", "Google LLC", C.TV, ("googlecast",)),
        host("192.168.0.71", "68:37:e9:3d:4c:8a", "Echo-Cozinha", "Amazon Technologies", C.SPEAKER, ("amzn-alexa",)),
        host("192.168.0.80", "9c:93:4e:55:70:2b", "HP-LaserJet", "HP Inc.", C.PRINTER, ("ipp", "pdl-datastream")),
        host("192.168.0.90", "d8:f1:5b:23:9e:44", "lampada-quarto", "Espressif Inc.", C.IOT),
        host("192.168.0.101", "dc:a6:32:11:88:f0", "raspberrypi", "Raspberry Pi Foundation", C.SBC, ("ssh",)),
        host("192.168.0.110", "78:c8:81:6e:aa:01", "PlayStation-5", "Sony Interactive", C.GAME),
    ]

    if args.json:
        print(render.to_json(hosts, demo_net))
        return 0
    render.print_banner()
    render.info("[yellow]modo demonstração[/yellow] [dim](dados fictícios)[/dim]")
    render.print_summary(demo_net, host_count=len(hosts), method="nmap + ping sweep + ARP")
    render.render_table(hosts, demo_net)
    return 0


def _local_hostname() -> Optional[str]:
    """Nome amigável da máquina local (sem sufixo .local)."""
    import socket

    try:
        name = socket.gethostname()
    except OSError:
        return None
    if not name:
        return None
    return name.split(".")[0]


def _run_mdns(args, netinfo, has_json: bool) -> dict:
    if has_json:
        return enrich.discover_mdns(duration=args.mdns_time)
    with render.console.status(
        "[green]sniffing mDNS/Bonjour...[/green]",
        spinner="dots",
        spinner_style="green",
    ):
        return enrich.discover_mdns(duration=args.mdns_time)


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        render.console.print("\n[yellow]interrompido pelo usuário.[/yellow]")
        return 130
    except Exception as exc:  # noqa: BLE001 - UX: nunca vaza stack trace cru
        if getattr(args, "verbose", False):
            raise
        render.error(str(exc) or exc.__class__.__name__)
        render.console.print("[dim]rode com -v para o traceback completo.[/dim]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
