"""CLI: parser, ordenação, rótulo de método e guarda de tamanho de rede."""

from __future__ import annotations

import ipaddress

import pytest
from rich.console import Console

from alive import classify, cli, render
from alive.net import NetInfo


@pytest.fixture
def captura(monkeypatch):
    import io

    buf = io.StringIO()
    monkeypatch.setattr(render, "console",
                        Console(file=buf, width=100, no_color=True, highlight=False,
                                legacy_windows=False))
    return buf


def netinfo(ip="192.168.0.61"):
    return NetInfo(interface="wlan0", ip=ip, network=None, gateway="192.168.0.1",
                   ssid="CASA")


class TestCheckSize:
    @pytest.mark.parametrize("cidr", ["192.168.0.0/24", "192.168.0.0/20", "10.0.0.0/22"])
    def test_aceita_rede_domestica(self, cidr, captura):
        assert cli._check_size(ipaddress.ip_network(cidr), netinfo(), False) is True

    @pytest.mark.parametrize("cidr", ["10.0.0.0/8", "172.16.0.0/12", "10.0.0.0/19"])
    def test_recusa_rede_grande(self, cidr, captura):
        """16 milhões de IPs estouram a memória antes do primeiro pacote sair."""
        assert cli._check_size(ipaddress.ip_network(cidr), netinfo(), False) is False

    def test_force_libera(self, captura):
        rede = ipaddress.ip_network("10.0.0.0/8")
        assert cli._check_size(rede, netinfo(), True) is True

    def test_sugere_a_subrede_local(self, captura):
        cli._check_size(ipaddress.ip_network("10.0.0.0/8"), netinfo(), False)
        saida = captura.getvalue()
        assert "-n 192.168.0.0/24" in saida and "--force" in saida

    def test_sem_ip_local_nao_sugere(self, captura):
        cli._check_size(ipaddress.ip_network("10.0.0.0/8"), netinfo(ip=None), False)
        assert "-n " not in captura.getvalue()

    def test_numero_formatado_em_pt_br(self):
        assert cli._br_num(16777216) == "16.777.216"
        assert cli._br_num(4096) == "4.096"
        assert cli._br_num(254) == "254"


def host(ip, name=None, dev=classify.COMPUTER):
    return {"ip": ip, "name": name, "device": dev}


HOSTS = [
    host("192.168.0.100", "zebra", classify.TV),
    host("192.168.0.9", "alfa", classify.ROUTER),
    host("192.168.0.20", None, classify.PHONE),
]


class TestSortHosts:

    def test_por_ip_e_numerico(self):
        """Ordem de string colocaria .100 antes de .20."""
        ordenado = cli._sort_hosts(HOSTS, "ip")
        assert [h["ip"] for h in ordenado] == \
            ["192.168.0.9", "192.168.0.20", "192.168.0.100"]

    def test_por_nome_com_sem_nome_no_fim(self):
        ordenado = cli._sort_hosts(HOSTS, "name")
        assert [h["name"] for h in ordenado] == ["alfa", "zebra", None]

    def test_por_tipo(self):
        ordenado = cli._sort_hosts(HOSTS, "type")
        assert [h["device"].label for h in ordenado] == \
            ["CELULAR", "ROTEADOR", "TV/STREAM"]


class TestMethodLabel:
    def test_lista_as_tecnicas_usadas(self):
        args = cli.build_parser().parse_args([])
        rotulo = cli._method_label(args, use_nmap=True)
        for parte in ("nmap", "ping sweep", "ARP", "mDNS", "portas", "UPnP", "NetBIOS"):
            assert parte in rotulo

    def test_sem_nmap(self):
        args = cli.build_parser().parse_args([])
        assert "nmap" not in cli._method_label(args, use_nmap=False)

    def test_sondas_desligadas_somem(self):
        args = cli.build_parser().parse_args(["--no-mdns", "--no-upnp"])
        rotulo = cli._method_label(args, use_nmap=False)
        assert "mDNS" not in rotulo and "UPnP" not in rotulo


class TestParser:
    def test_padroes(self):
        args = cli.build_parser().parse_args([])
        assert args.sort == "ip" and args.timeout == 1.0 and args.workers == 64
        assert args.watch is None and args.force is False

    def test_watch_sem_valor_usa_30s(self):
        assert cli.build_parser().parse_args(["--watch"]).watch == 30.0

    def test_watch_com_valor(self):
        assert cli.build_parser().parse_args(["--watch", "60"]).watch == 60.0

    def test_sort_invalido_e_rejeitado(self):
        with pytest.raises(SystemExit):
            cli.build_parser().parse_args(["--sort", "inexistente"])

    def test_flags_curtas(self):
        args = cli.build_parser().parse_args(["-n", "10.0.0.0/24", "-i", "eth0", "-j"])
        assert args.network == "10.0.0.0/24" and args.interface == "eth0" and args.json


class TestResolveNetwork:
    def test_cidr_explicito(self, captura):
        args = cli.build_parser().parse_args(["-n", "10.0.0.0/24"])
        assert str(cli._resolve_network(args, netinfo())) == "10.0.0.0/24"

    def test_cidr_nao_alinhado_e_normalizado(self, captura):
        args = cli.build_parser().parse_args(["-n", "192.168.0.61/24"])
        assert str(cli._resolve_network(args, netinfo())) == "192.168.0.0/24"

    def test_cidr_invalido(self, captura):
        args = cli.build_parser().parse_args(["-n", "isso-nao-e-uma-rede"])
        assert cli._resolve_network(args, netinfo()) is None
        assert "CIDR inválido" in captura.getvalue()


def test_fast_desliga_todas_as_sondas():
    args = cli.build_parser().parse_args(["--fast"])
    cli._apply_fast(args)
    assert args.no_mdns and args.no_vendor and args.no_ports
    assert args.no_upnp and args.no_netbios


def test_sem_fast_nao_mexe_nas_sondas():
    args = cli.build_parser().parse_args([])
    cli._apply_fast(args)
    assert not any([args.no_mdns, args.no_vendor, args.no_ports,
                    args.no_upnp, args.no_netbios])


def test_demo_em_json_e_valido(capsys):
    import json
    args = cli.build_parser().parse_args(["--demo", "--json"])
    assert cli.run(args) == 0
    dados = json.loads(capsys.readouterr().out)
    assert len(dados["hosts"]) == 12
    assert dados["network"]["ssid"] == "CASA-5G"
