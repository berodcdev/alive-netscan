"""Interface de linha de comando do `alive`."""

from __future__ import annotations

import argparse
import ipaddress
import sys
import time
from typing import Optional

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import (
    __author_email__,
    __version__,
    classify,
    enrich,
    findings,
    history,
    net,
    probe,
    render,
    scanner,
)

DESCRIPTION = """\
[bold green]alive[/bold green] — recon de hosts na rede local [dim](macOS + Linux)[/dim]

Varre a subrede, enumera cada host vivo e faz fingerprint de IP, MAC, fabricante
e tipo de dispositivo (roteador, computador, celular, TV, assistente, IoT...).\
"""

EPILOG = """\
[bold green]exemplos[/bold green]
  [green]alive[/green]                          [dim]# varre a rede WiFi atual[/dim]
  [green]alive --fast[/green]                   [dim]# rápido: sem mDNS, fabricante nem sondas[/dim]
  [green]alive -n 192.168.0.0/24[/green]        [dim]# varre uma subrede específica[/dim]
  [green]alive --watch[/green]                  [dim]# monitora e avisa quem entra e sai[/dim]
  [green]alive --watch 60[/green]               [dim]# monitorando a cada 60 segundos[/dim]
  [green]alive --passive[/green]                [dim]# sem mandar pacote: só cache ARP + mDNS[/dim]
  [green]alive --stealth[/green]                [dim]# furtivo: ordem aleatória e jitter[/dim]
  [green]alive --sort type[/green]              [dim]# agrupa por tipo de dispositivo[/dim]
  [green]alive --sort risk[/green]              [dim]# host com achado mais grave primeiro[/dim]
  [green]alive -o targets | nmap -iL -[/green]  [dim]# só os IPs, p/ outra ferramenta[/dim]
  [green]alive -o csv > rede.csv[/green]        [dim]# planilha de todos os hosts[/dim]
  [green]alive --with-service smb[/green]       [dim]# só quem expõe SMB[/dim]
  [green]alive --json > recon.json[/green]      [dim]# exporta o resultado em JSON[/dim]
  [green]alive --watch --json[/green]           [dim]# NDJSON: uma linha por ciclo[/dim]
  [green]alive --fail-on alto[/green]           [dim]# código 3 se houver achado grave[/dim]

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
        from rich_argparse import RawDescriptionRichHelpFormatter as _Rich

        _Rich.styles["argparse.prog"] = "bold green"
        _Rich.styles["argparse.groups"] = "bold green"
        _Rich.styles["argparse.args"] = "bold green"
        _Rich.styles["argparse.metavar"] = "dim green"
        _Rich.styles["argparse.help"] = "default"
        _Rich.styles["argparse.text"] = "default"
        _Rich.usage_markup = True
        # Manter a capitalização exata dos títulos de grupo (sem Title Case).
        _Rich.group_name_formatter = str
        formatter = _Rich  # type: ignore[assignment]
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
    alvo.add_argument(
        "--force", action="store_true",
        help="varrer mesmo uma rede maior que /20 [dim](pode levar horas)[/dim].",
    )

    veloc = parser.add_argument_group("varredura")
    veloc.add_argument(
        "--fast", action="store_true",
        help="modo rápido: pula mDNS, fabricante e as sondas (portas/UPnP/NetBIOS).",
    )
    veloc.add_argument(
        "--passive", action="store_true",
        help="modo passivo: nenhum pacote para os hosts [dim](só tabela ARP + escuta mDNS)[/dim].",
    )
    veloc.add_argument(
        "--stealth", action="store_true",
        help="modo furtivo: ordem aleatória, atraso entre pacotes e poucos workers "
             "[dim](mais lento, evita assinatura de varredura)[/dim].",
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
        "--no-ports", action="store_true",
        help="pular o fingerprint por portas TCP [dim](identifica iPhone, câmera, NAS...)[/dim].",
    )
    veloc.add_argument(
        "--no-upnp", action="store_true",
        help="pular a descoberta SSDP/UPnP [dim](nome e modelo de TVs, IoT, roteadores)[/dim].",
    )
    veloc.add_argument(
        "--no-netbios", action="store_true",
        help="pular a consulta de nomes NetBIOS [dim](Windows, Samba, NAS)[/dim].",
    )
    veloc.add_argument(
        "--no-snmp", action="store_true",
        help="pular a consulta SNMP com community public [dim](impressora, switch, AP)[/dim].",
    )
    veloc.add_argument(
        "--no-dhcp", action="store_true",
        help="pular a detecção de servidor DHCP rogue [dim](requer sudo/root)[/dim].",
    )
    veloc.add_argument(
        "--upnp-time", type=float, default=2.5, metavar="SEG",
        help="tempo ouvindo respostas SSDP/UPnP [dim](padrão: 2.5s)[/dim].",
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

    monitor = parser.add_argument_group("monitoramento")
    monitor.add_argument(
        "--watch", nargs="?", type=float, const=30.0, default=None, metavar="SEG",
        help="fica varrendo e avisa quem entra e sai [dim](padrão: a cada 30s)[/dim].",
    )
    monitor.add_argument(
        "--no-history", action="store_true",
        help="não comparar com o scan anterior nem marcar dispositivos novos.",
    )

    saida = parser.add_argument_group("saída")
    saida.add_argument(
        "-o", "--output", choices=("table", "json", "targets", "csv"), default="table",
        help="formato de saída: table, json, targets (só IPs) ou csv [dim](padrão: table)[/dim].",
    )
    saida.add_argument(
        "--with-service", metavar="SVC",
        help="só hosts com estes serviços abertos, separados por vírgula "
             "[dim](ex.: smb,http,rtsp)[/dim].",
    )
    saida.add_argument(
        "--sort", choices=("ip", "name", "type", "risk"), default="ip",
        help="ordenar por: ip, name, type ou risk [dim](risk = achado mais grave "
             "primeiro; padrão: ip)[/dim].",
    )
    saida.add_argument(
        "--fail-on", choices=("alto", "medio", "baixo"), default=None, metavar="NÍVEL",
        help="sair com código 3 se houver achado deste nível ou pior [dim](cron/CI)[/dim].",
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


# Acima disso a varredura deixa de ser viável: cada IP é um ping (um processo)
# e depois 22 conexões TCP. Um /8 são 16 milhões de endereços — a lista de IPs
# sozinha estoura a memória antes do primeiro pacote sair.
MAX_ADDRESSES = 4096  # /20


def _br_num(n: int) -> str:
    """Número com separador de milhar em pt-BR (1234567 -> 1.234.567)."""
    return f"{n:,}".replace(",", ".")


def _check_size(network: ipaddress.IPv4Network, netinfo: net.NetInfo, force: bool) -> bool:
    """Recusa redes grandes demais para varrer, sugerindo a subrede local."""
    if force or network.num_addresses <= MAX_ADDRESSES:
        return True
    render.error(
        f"{network} tem {_br_num(network.num_addresses)} endereços — acima do "
        f"limite de {_br_num(MAX_ADDRESSES)} (/20). Varrer isso levaria horas."
    )
    if netinfo.ip:
        suggestion = ipaddress.ip_network(f"{netinfo.ip}/24", strict=False)
        render.console.print(
            f"[dim]› varra a sua subrede: [bold]-n {suggestion}[/bold][/dim]"
        )
    render.console.print(
        "[dim]› ou varra assim mesmo: [bold]--force[/bold][/dim]"
    )
    return False


def _sort_hosts(hosts: list[dict], key: str) -> list[dict]:
    if key == "name":
        return sorted(hosts, key=lambda h: (h.get("name") or "~").lower())
    if key == "type":
        return sorted(
            hosts,
            key=lambda h: (
                classify.TYPE_RANK.get(h["device"].label, 99),
                ipaddress.ip_address(h["ip"]),
            ),
        )
    return sorted(hosts, key=lambda h: ipaddress.ip_address(h["ip"]))


def _apply_passive(args: argparse.Namespace) -> None:
    """--passive: nenhum pacote unicast sai daqui para os hosts.

    Sobra a tabela ARP que o sistema já mantém e a escuta de mDNS — tráfego
    multicast que a rede já troca sozinha. Sem ping, nmap, porta, NetBIOS nem
    M-SEARCH. Cobre menos, mas não deixa rastro em IDS nem acorda aparelho.
    """
    if not getattr(args, "passive", False):
        return
    args.no_nmap = True
    args.no_ports = True
    args.no_netbios = True
    args.no_upnp = True
    args.no_snmp = True
    args.no_dhcp = True


def _exit_code(found: list, fail_on: Optional[str]) -> int:
    """3 quando existe achado no nível pedido ou pior — para cron e CI."""
    if not fail_on:
        return 0
    teto = findings.SEVERITY_ORDER[fail_on]
    pior = min(
        (findings.SEVERITY_ORDER.get(f.severity, 9) for f in found), default=9
    )
    return 3 if pior <= teto else 0


def _apply_fast(args: argparse.Namespace) -> None:
    """--fast é um atalho: só ping sweep + ARP, sem sonda de nome nem de tipo."""
    if not getattr(args, "fast", False):
        return
    args.no_mdns = True
    args.no_vendor = True
    args.no_ports = True
    args.no_upnp = True
    args.no_netbios = True
    args.no_snmp = True
    args.no_dhcp = True


# Parâmetros de furtividade que as sondas recebem. Ficam em ``args`` para o
# _collect repassar a scanner.scan e probe.probe_ports.
_STEALTH_JITTER = 0.3     # atraso máximo (s) sorteado antes de cada pacote
_STEALTH_WORKERS = 8      # poucos em paralelo: menos rajada simultânea


def _apply_stealth(args: argparse.Namespace) -> None:
    """--stealth: ordem aleatória, atraso entre pacotes e poucos workers.

    O objetivo é não deixar a assinatura óbvia de uma varredura — a rajada
    sequencial de pings e SYNs que um IDS reconhece na hora. Custa tempo.
    """
    args.jitter = 0.0
    args.shuffle = False
    if not getattr(args, "stealth", False):
        return
    args.jitter = _STEALTH_JITTER
    args.shuffle = True
    # Respeita um valor menor que o usuário tenha pedido; limita um alto.
    args.workers = min(args.workers, _STEALTH_WORKERS)


def _output_format(args: argparse.Namespace) -> str:
    """--json é atalho para -o json; senão vale o que veio em --output."""
    if getattr(args, "json", False):
        return "json"
    return getattr(args, "output", "table")


def _wanted_services(spec: Optional[str]) -> set[str]:
    return {s.strip().lower() for s in (spec or "").split(",") if s.strip()}


def _filter_by_service(hosts: list[dict], wanted: set[str]) -> list[dict]:
    """Mantém só hosts que expõem pelo menos um dos serviços pedidos."""
    if not wanted:
        return hosts
    return [h for h in hosts if {s.lower() for s in (h.get("services") or set())} & wanted]


def _sort_by_risk(hosts: list[dict], found: list) -> list[dict]:
    """Ordena os hosts pelo achado mais grave de cada um (mais grave primeiro)."""
    worst: dict[str, int] = {}
    for f in found or []:
        if not f.ip:
            continue
        rank = findings.SEVERITY_ORDER.get(f.severity, 9)
        if f.ip not in worst or rank < worst[f.ip]:
            worst[f.ip] = rank
    return sorted(
        hosts,
        key=lambda h: (worst.get(h["ip"], 9), ipaddress.ip_address(h["ip"])),
    )


def run(args: argparse.Namespace) -> int:
    if getattr(args, "demo", False):
        return _run_demo(args)

    _apply_fast(args)
    _apply_passive(args)
    _apply_stealth(args)

    # 1) Descobrir a rede local.
    netinfo = net.discover()
    vpn_note: Optional[str] = None
    if args.interface:
        # Com -i, tudo passa a vir da interface escolhida: o IP da rota padrão
        # pode ser de outra rede (VPN), o que derivaria a subrede errada.
        netinfo.interface = args.interface
        netinfo.ip = net.get_interface_ip(args.interface) or netinfo.ip
        netinfo.gateway = net.get_gateway_for_interface(args.interface) or netinfo.gateway
        netinfo.network = net.get_network_for_interface(args.interface, netinfo.ip)
        netinfo.ssid = net.get_ssid(args.interface)
    elif net.is_virtual_interface(netinfo.interface) and not args.network:
        # Rota padrão via VPN/túnel: a rede detectada não é a WiFi local.
        vpn_note = (
            f"a rota padrão sai por [bold]{netinfo.interface}[/bold] (VPN/túnel). "
            "Para varrer a WiFi, use [bold]-i en0[/bold] "
            "(Linux: [bold]-i wlan0[/bold]) ou [bold]-n CIDR[/bold]."
        )

    network = _resolve_network(args, netinfo)
    if network is None:
        render.error(
            "não foi possível determinar a subrede. "
            "Use -n para especificar (ex.: -n 192.168.0.0/24)."
        )
        return 2
    if not _check_size(network, netinfo, args.force):
        return 2
    netinfo.network = network

    use_nmap = (not args.no_nmap) and scanner.has_nmap()
    method = _method_label(args, use_nmap)
    out_fmt = _output_format(args)
    is_table = out_fmt == "table"

    if args.watch is not None:
        return _run_watch(args, netinfo, use_nmap=use_nmap, method=method, note=vpn_note)

    if is_table:
        render.print_banner()
        if vpn_note:
            render.warn(vpn_note)
        render.info(
            f"varrendo [bold green]{netinfo.cidr}[/bold green] "
            f"[dim]({method})[/dim]"
        )

    inicio = time.monotonic()
    # Formatos de máquina (json/targets/csv) não podem ter spinner nem barra
    # sujando o stdout — coletam em modo silencioso.
    hosts, diff, found = _collect(args, netinfo, use_nmap=use_nmap, quiet=not is_table)
    duracao = time.monotonic() - inicio

    wanted = _wanted_services(getattr(args, "with_service", None))
    hosts = _filter_by_service(hosts, wanted)
    if wanted:
        ips = {h["ip"] for h in hosts}
        found = [f for f in found if f.ip is None or f.ip in ips]

    if out_fmt == "json":
        print(render.to_json(hosts, netinfo, found))
    elif out_fmt == "targets":
        print(render.to_targets(hosts))
    elif out_fmt == "csv":
        print(render.to_csv(hosts))
    else:
        render.print_summary(netinfo, hosts, method=method, diff=diff,
                             findings=found, passive=args.passive)
        render.render_table(hosts, netinfo, found)
        render.print_findings(found)
        render.print_footer(duracao, max(1, network.num_addresses - 2), hosts)
    return _exit_code(found, args.fail_on)


def _method_label(args: argparse.Namespace, use_nmap: bool) -> str:
    """Descreve as técnicas realmente usadas nesta execução."""
    if getattr(args, "passive", False):
        parts = ["ARP"]
        if not args.no_mdns:
            parts.append("mDNS")
        return " + ".join(parts) + " (passivo)"
    parts = ["nmap"] if use_nmap else []
    parts += ["ping sweep", "ARP"]
    if not args.no_mdns:
        parts.append("mDNS")
    if not args.no_ports:
        parts.append("portas")
    if not args.no_upnp:
        parts.append("UPnP")
    if not args.no_netbios:
        parts.append("NetBIOS")
    return " + ".join(parts)


def _collect(
    args: argparse.Namespace,
    netinfo: net.NetInfo,
    *,
    use_nmap: bool,
    quiet: bool,
) -> tuple[list[dict], history.Diff, list[findings.Finding]]:
    """Executa scan + enriquecimento + sondas e devolve (hosts, diff, achados)."""
    network = netinfo.network
    assert network is not None  # garantido por _resolve_network

    # 1) Hosts vivos (barra de progresso, exceto em JSON/watch silencioso).
    total = max(1, network.num_addresses - 2)
    scan_kwargs = {
        "use_nmap": use_nmap, "use_ping": not getattr(args, "passive", False),
        "timeout": args.timeout, "workers": args.workers,
        "local_ip": netinfo.ip, "gateway": netinfo.gateway,
        "jitter": getattr(args, "jitter", 0.0),
        "shuffle": getattr(args, "shuffle", False),
    }
    if quiet:
        hosts_raw = scanner.scan(network, **scan_kwargs)
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
                network, progress=lambda: progress.advance(task), **scan_kwargs
            )
            progress.update(task, completed=total)

    ips = [h["ip"] for h in hosts_raw]
    macs = [h["mac"] for h in hosts_raw if h["mac"]]

    # 2) Enriquecimento passivo.
    hostnames = enrich.resolve_hostnames(ips)
    vendors = {} if args.no_vendor else enrich.lookup_vendors(macs)
    mdns = {} if args.no_mdns else _staged(
        args, quiet, "sniffing mDNS/Bonjour", lambda: enrich.discover_mdns(args.mdns_time)
    )

    # 3) Sondas ativas — é o que resolve os hosts sem nome nem OUI.
    port_workers = _STEALTH_WORKERS if getattr(args, "stealth", False) else 192
    ports = {} if args.no_ports else _staged(
        args, quiet, "fingerprint de portas",
        lambda: probe.probe_ports(
            ips, workers=port_workers,
            jitter=getattr(args, "jitter", 0.0),
            shuffle=getattr(args, "shuffle", False),
        ),
    )
    upnp = {} if args.no_upnp else _staged(
        args, quiet, "sondando SSDP/UPnP", lambda: probe.discover_ssdp(args.upnp_time)
    )
    netbios = {} if args.no_netbios else _staged(
        args, quiet, "consultando NetBIOS", lambda: probe.query_netbios(ips)
    )
    snmp = {} if getattr(args, "no_snmp", False) else _staged(
        args, quiet, "consultando SNMP (public)", lambda: probe.query_snmp(ips)
    )
    # DHCP rogue: precisa da porta 68 (privilegiada). Só tentamos sob root, senão
    # a sonda mostraria um spinner só para falhar ao fazer bind.
    dhcp: Optional[list[dict]] = None
    _is_root = hasattr(__import__("os"), "geteuid") and __import__("os").geteuid() == 0
    if not getattr(args, "no_dhcp", False) and _is_root:
        local_mac_for_dhcp = scanner.normalize_mac(
            net.get_interface_mac(netinfo.interface)
        )
        dhcp = _staged(
            args, quiet, "procurando DHCP rogue",
            lambda: probe.discover_dhcp(local_mac_for_dhcp),
        )
        # _staged devolve {} se a sonda lançar: normaliza para None (não rodou).
        if not isinstance(dhcp, list):
            dhcp = None
    # Banners só fazem sentido depois de saber quais portas estão abertas. O
    # certificado TLS vem junto, do mesmo handshake dos hosts com HTTPS.
    banners = {} if args.no_ports else _staged(
        args, quiet, "lendo banners e certificados", lambda: probe.grab_banners(ports)
    )

    # O gateway conta, via UPnP, o IP público, o uptime do link e — o que mais
    # importa — os redirecionamentos de porta ativos para a internet.
    netinfo.link = net.get_link_info(netinfo.interface)
    netinfo.dns = net.get_dns_servers()
    if not args.no_upnp:
        location = probe.find_gateway_location(upnp, netinfo.gateway)
        if location:
            netinfo.wan = _staged(
                args, quiet, "interrogando o gateway (UPnP)",
                lambda: probe.gateway_wan_info(location),
            )

    local_name = _local_hostname()
    local_mac = scanner.normalize_mac(net.get_interface_mac(netinfo.interface))

    # 4) Fusão dos sinais + classificação.
    hosts: list[dict] = []
    for h in hosts_raw:
        ip = h["ip"]
        is_self = bool(netinfo.ip and ip == netinfo.ip)
        # A tabela ARP nunca lista a própria máquina: usamos o MAC da interface.
        mac = h["mac"] or (local_mac if is_self else None)

        m = mdns.get(ip, {})
        u = upnp.get(ip, {})
        # O certificado TLS vem dentro dos banners; separamos para não poluir o
        # texto de classificação nem a coluna de banner com o dict do cert.
        b = dict(banners.get(ip, {}))
        tls = b.pop("tls", None)
        s = snmp.get(ip, {})
        services = set(m.get("services") or []) | set(ports.get(ip) or [])
        hostname = hostnames.get(ip)
        # Ordem de nome: mDNS (mais amigável) > UPnP > SNMP sysName > NetBIOS > rDNS.
        name = (
            m.get("name") or u.get("name") or s.get("name")
            or netbios.get(ip) or hostname
        )
        vendor = (vendors.get(mac) if mac else None) or u.get("manufacturer")
        # Modelo: o aparelho dizendo o que é (TXT do mDNS) vale mais que o UPnP.
        model = m.get("model") or u.get("model")
        os_family = scanner.os_family_from_ttl(h.get("ttl"))

        dev, inferred = classify.classify(
            ip=ip, mac=mac, vendor=vendor, hostname=hostname,
            mdns_name=m.get("name"), services=services,
            gateway=netinfo.gateway, upnp=u,
            model=model, banners=b, os_family=os_family,
            snmp=s, tls=tls,
        )
        # O host local é a máquina que roda o alive: é computador, sem palpite.
        # (Macs e notebooks Linux também usam MAC aleatório na WiFi, o que sem
        # isso os classificaria como "CELULAR ?".)
        if is_self:
            if dev is classify.UNKNOWN or inferred:
                dev, inferred = classify.COMPUTER, False
            name = name or local_name
        hosts.append(
            {
                "ip": ip,
                "mac": mac,
                "name": name,
                "vendor": vendor,
                "model": model,
                "services": services,
                "mdns_services": sorted(m.get("services") or []),
                "banners": b,
                "snmp": s,
                "tls": tls,
                "device": dev,
                "inferred": inferred,
                "random_mac": scanner.is_random_mac(mac),
                "rtt": h.get("rtt"),
                "ttl": h.get("ttl"),
                "os_family": os_family,
                "via": h.get("via"),
                "arp_state": h.get("arp_state"),
                "history_off": bool(args.no_history),
            }
        )

    hosts = _sort_hosts(hosts, args.sort)

    # 5) Histórico: quem é novo, quem saiu e desde quando cada um é conhecido.
    diff = history.Diff()
    if not args.no_history:
        diff = history.compare(hosts, netinfo.cidr)
        for h in hosts:
            h["is_new"] = history.host_key(h) in diff.new_keys
        history.save(hosts, netinfo.cidr, gateway=netinfo.gateway)

    # 6) Achados: o que merece atenção no que foi encontrado. O MAC do gateway
    # do scan anterior (diff) alimenta a detecção de MITM. Só vale se o IP do
    # gateway não mudou desde então.
    gw_mac_prev = (
        diff.gateway_mac_before
        if diff.gateway_ip_before == netinfo.gateway
        else None
    )
    netinfo.dhcp = dhcp
    found = findings.collect(
        hosts,
        netinfo.wan,
        passive=bool(getattr(args, "passive", False)),
        gateway=netinfo.gateway,
        gateway_mac_prev=gw_mac_prev,
        dhcp=dhcp,
    )
    for h in hosts:
        h["notes"] = findings.short_notes(h)
    # A ordenação por risco só é possível aqui: precisa dos achados prontos.
    if args.sort == "risk":
        hosts = _sort_by_risk(hosts, found)
    return hosts, diff, found


def _staged(args, quiet: bool, label: str, fn):
    """Roda uma etapa de enriquecimento com spinner e à prova de falha.

    Nenhuma sonda é essencial: se uma quebrar (roteador exótico, rede estranha,
    resposta malformada), o scan segue sem ela em vez de morrer. Com -v a
    exceção sobe, para poder depurar.
    """
    error: Optional[Exception] = None

    def guarded():
        nonlocal error
        try:
            return fn()
        except Exception as exc:
            if getattr(args, "verbose", False):
                raise
            error = exc
            return {}

    if quiet:
        return guarded()
    with render.console.status(
        f"[green]{label}...[/green]", spinner="dots", spinner_style="green"
    ):
        result = guarded()
    if error is not None:
        render.warn(
            f"etapa '{label}' falhou ({error.__class__.__name__}) — seguindo sem ela. "
            "[dim]rode com -v para o traceback.[/dim]"
        )
    return result


def _run_watch(
    args: argparse.Namespace,
    netinfo: net.NetInfo,
    *,
    use_nmap: bool,
    method: str,
    note: Optional[str] = None,
) -> int:
    """Monitora a rede em ciclos, reportando entradas e saídas."""
    interval = max(5.0, float(args.watch))
    # Com --json o monitoramento vira NDJSON: uma linha por ciclo, com o estado
    # e os eventos daquele ciclo. Nada de banner nem spinner poluindo a saída.
    if not args.json:
        render.print_banner()
        if note:
            render.warn(note)
        render.info(
            f"monitorando [bold green]{netinfo.cidr}[/bold green] "
            f"[dim](ciclo de {interval:.0f}s · {method} · ctrl-c para sair)[/dim]"
        )
    cycle = 0
    while True:
        cycle += 1
        hosts, diff, found = _collect(
            args, netinfo, use_nmap=use_nmap, quiet=args.json
        )
        if args.json:
            print(render.watch_line(cycle, hosts, netinfo, found, diff), flush=True)
            time.sleep(interval)
            continue
        stamp = time.strftime("%H:%M:%S")
        changed = any(h.get("is_new") for h in hosts) or bool(diff.gone)
        if cycle == 1:
            render.print_summary(netinfo, hosts, method=method, diff=diff,
                                 findings=found, passive=args.passive)
            render.render_table(hosts, netinfo, found)
            render.print_findings(found)
        elif changed:
            render.console.print(
                f"\n[dim]── ciclo {cycle} · {stamp} ──[/dim]"
            )
            render.print_events(hosts, diff)
            render.render_table(hosts, netinfo, found)
        else:
            render.console.print(
                f"[dim][*] ciclo {cycle} · {stamp} · sem mudanças "
                f"({len(hosts)} hosts)[/dim]"
            )
        time.sleep(interval)


def _run_demo(args: argparse.Namespace) -> int:
    """Renderiza uma saída de exemplo com dados fictícios (docs/testes/GIF)."""
    demo_net = net.NetInfo(
        interface="en0",
        ip="192.168.0.42",
        network=ipaddress.ip_network("192.168.0.0/24"),
        gateway="192.168.0.1",
        ssid="CASA-5G",
        link={"channel": 36, "signal": -47, "bitrate": 866.0},
        dns=["192.168.0.1", "1.1.1.1"],
        wan={
            "model": "TP-Link Archer C6",
            "external_ip": "189.45.10.77",
            "uptime_s": 1054800,
            "port_mappings": [
                {
                    "external_port": "32400", "internal_port": "32400",
                    "internal_client": "192.168.0.101", "protocol": "TCP",
                    "description": "plex",
                }
            ],
        },
    )

    def host(ip, mac, name, vendor, dev, services=(), **extra):
        h = {
            "ip": ip, "mac": mac, "name": name, "vendor": vendor,
            "services": set(services), "device": dev,
            "inferred": False, "is_new": False,
            "random_mac": scanner.is_random_mac(mac),
            "model": None, "banners": {}, "os_family": None,
            "rtt": None, "ttl": None, "via": "ping", "notes": [],
            "first_seen": time.time() - 86400 * 9, "seen_count": 40, "presence": 1.0,
        }
        h.update(extra)
        h["notes"] = findings.short_notes(h)
        return h

    tipos = classify
    hosts = [
        host("192.168.0.1", "a4:2b:8c:1f:07:e3", "roteador", "TP-Link", tipos.ROUTER,
             ("dns", "http"), model="Archer C6", rtt=2.1),
        host("192.168.0.42", "f0:18:98:2a:1b:cd", "meu-notebook", "Apple, Inc.", tipos.COMPUTER,
             ("ssh", "workstation"), model="MacBook Air", rtt=7.4),
        host("192.168.0.51", "3c:5a:b4:77:21:9f", "Galaxy-S23", "Samsung Electronics Co.,Ltd",
             tipos.PHONE, (), rtt=31.0),
        host("192.168.0.55", "6e:1a:c4:90:2d:7b", None, None, tipos.PHONE, (),
             inferred=True, is_new=True, rtt=44.2, first_seen=None, seen_count=1, presence=0.02),
        host("192.168.0.60", "54:60:09:aa:bb:12", "Sala (Chromecast)", "Google LLC", tipos.TV,
             ("googlecast", "cast"), model="Chromecast Ultra", rtt=12.0),
        host("192.168.0.71", "68:37:e9:3d:4c:8a", "Echo-Cozinha", "Amazon", tipos.SPEAKER,
             ("amzn-alexa",), model="Echo Dot", rtt=18.3),
        host("192.168.0.80", "9c:93:4e:55:70:2b", "HP-LaserJet", "HP Inc.", tipos.PRINTER,
             ("ipp", "jetdirect"), model="HP LaserJet M28w", rtt=9.9),
        host("192.168.0.88", "3c:e1:a1:44:0b:19", "cam-garagem", "Intelbras", tipos.CAMERA,
             ("rtsp", "http", "telnet"), banners={"http_server": "GoAhead-Webs"}, rtt=3.2),
        host("192.168.0.90", "d8:f1:5b:23:9e:44", "lampada-quarto", "Espressif", tipos.IOT,
             ("mqtt",), rtt=25.7),
        host("192.168.0.101", "dc:a6:32:11:88:f0", "raspberrypi", "Raspberry Pi Foundation",
             tipos.SBC, ("ssh", "plex"), banners={"ssh": "OpenSSH_9.6p1 Debian"}, rtt=1.8),
        host("192.168.0.110", "78:c8:81:6e:aa:01", "PlayStation-5", "Sony Interactive", tipos.GAME,
             (), rtt=15.1),
        host("192.168.0.150", "00:1a:2b:3c:4d:5e", None, "Dell Inc.", tipos.COMPUTER, (),
             inferred=True, via="arp", ttl=128, os_family="Windows",
             first_seen=time.time() - 86400 * 2, seen_count=3, presence=0.3),
    ]
    demo_diff = history.Diff(
        new_keys={"ip:192.168.0.55"},
        gone=[{"ip": "192.168.0.120", "name": "iPad-Sala"}],
        previous_time=time.time() - 900,
        first_run=False,
    )

    hosts = _sort_hosts(hosts, args.sort)
    demo_findings = findings.collect(hosts, demo_net.wan)

    if args.json:
        print(render.to_json(hosts, demo_net, demo_findings))
        return _exit_code(demo_findings, args.fail_on)
    render.print_banner()
    render.info("[yellow]modo demonstração[/yellow] [dim](dados fictícios)[/dim]")
    render.print_summary(
        demo_net, hosts,
        method="nmap + ping + ARP + mDNS + portas + banners + UPnP + NetBIOS",
        diff=demo_diff,
        findings=demo_findings,
    )
    render.render_table(hosts, demo_net, demo_findings)
    render.print_findings(demo_findings)
    # Duração fictícia como o resto do demo, para a saída ficar igual à real.
    render.print_footer(8.4, 254, hosts)
    return _exit_code(demo_findings, args.fail_on)


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


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except KeyboardInterrupt:
        render.console.print("\n[yellow]interrompido pelo usuário.[/yellow]")
        return 130
    except Exception as exc:
        if getattr(args, "verbose", False):
            raise
        # Sem o nome da classe, um KeyError vira só "'location'" na tela.
        detail = str(exc)
        render.error(
            f"{exc.__class__.__name__}: {detail}" if detail else exc.__class__.__name__
        )
        render.console.print("[dim]rode com -v para o traceback completo.[/dim]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
