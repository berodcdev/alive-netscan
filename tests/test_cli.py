"""CLI: parser, ordenação, rótulo de método e guarda de tamanho de rede."""

from __future__ import annotations

import ipaddress

import pytest

from alive import classify, cli
from alive.net import NetInfo


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

    def test_por_tipo_segue_prioridade_nao_alfabeto(self):
        """Infraestrutura primeiro; alfabética não diz nada sobre a rede."""
        ordenado = cli._sort_hosts(HOSTS, "type")
        assert [h["device"].label for h in ordenado] == \
            ["ROTEADOR", "CELULAR", "TV/STREAM"]


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


class TestPassive:
    def test_desliga_tudo_que_manda_pacote(self):
        args = cli.build_parser().parse_args(["--passive"])
        cli._apply_passive(args)
        assert args.no_nmap and args.no_ports and args.no_netbios and args.no_upnp

    def test_mantem_o_mdns(self):
        """mDNS é multicast: o mesmo tráfego que a rede já troca sozinha."""
        args = cli.build_parser().parse_args(["--passive"])
        cli._apply_passive(args)
        assert not args.no_mdns

    def test_metodo_diz_que_foi_passivo(self):
        args = cli.build_parser().parse_args(["--passive"])
        cli._apply_passive(args)
        rotulo = cli._method_label(args, use_nmap=False)
        assert "passivo" in rotulo and "ping" not in rotulo

    def test_sem_passive_nao_mexe(self):
        args = cli.build_parser().parse_args([])
        cli._apply_passive(args)
        assert not args.no_nmap


class TestExitCode:
    def _achados(self, *severidades):
        from alive.findings import Finding
        return [Finding(s, "1.2.3.4", "x") for s in severidades]

    def test_sem_fail_on_sempre_zero(self):
        assert cli._exit_code(self._achados("alto"), None) == 0

    def test_achado_no_nivel_pedido(self):
        assert cli._exit_code(self._achados("alto"), "alto") == 3

    def test_achado_pior_que_o_pedido(self):
        assert cli._exit_code(self._achados("alto"), "medio") == 3

    def test_achado_mais_brando_que_o_pedido(self):
        assert cli._exit_code(self._achados("baixo"), "alto") == 0

    def test_sem_achado_nenhum(self):
        assert cli._exit_code([], "baixo") == 0

    def test_fail_on_baixo_pega_qualquer_coisa(self):
        assert cli._exit_code(self._achados("baixo"), "baixo") == 3


class TestFlagsSnmp:
    def test_flag_no_snmp_existe(self):
        from alive import cli
        args = cli.build_parser().parse_args(["--no-snmp"])
        assert args.no_snmp is True

    def test_passivo_desliga_snmp(self):
        from alive import cli
        args = cli.build_parser().parse_args(["--passive"])
        cli._apply_passive(args)
        assert args.no_snmp is True

    def test_fast_desliga_snmp(self):
        from alive import cli
        args = cli.build_parser().parse_args(["--fast"])
        cli._apply_fast(args)
        assert args.no_snmp is True


class TestFlagsDhcp:
    def test_flag_no_dhcp_existe(self):
        from alive import cli
        assert cli.build_parser().parse_args(["--no-dhcp"]).no_dhcp is True

    def test_passivo_desliga_dhcp(self):
        from alive import cli
        args = cli.build_parser().parse_args(["--passive"])
        cli._apply_passive(args)
        assert args.no_dhcp is True

    def test_fast_desliga_dhcp(self):
        from alive import cli
        args = cli.build_parser().parse_args(["--fast"])
        cli._apply_fast(args)
        assert args.no_dhcp is True


class TestStealth:
    def test_flag_stealth_liga_jitter_shuffle_e_limita_workers(self):
        from alive import cli
        args = cli.build_parser().parse_args(["--stealth"])
        cli._apply_stealth(args)
        assert args.jitter > 0 and args.shuffle is True
        assert args.workers <= cli._STEALTH_WORKERS

    def test_sem_stealth_sem_jitter(self):
        from alive import cli
        args = cli.build_parser().parse_args([])
        cli._apply_stealth(args)
        assert args.jitter == 0.0 and args.shuffle is False

    def test_stealth_respeita_workers_menor(self):
        from alive import cli
        args = cli.build_parser().parse_args(["--stealth", "-w", "2"])
        cli._apply_stealth(args)
        assert args.workers == 2


class TestSaidaFormato:
    def test_output_padrao_table(self):
        from alive import cli
        assert cli._output_format(cli.build_parser().parse_args([])) == "table"

    def test_json_e_atalho_para_output_json(self):
        from alive import cli
        assert cli._output_format(cli.build_parser().parse_args(["--json"])) == "json"

    def test_output_targets(self):
        from alive import cli
        assert cli._output_format(cli.build_parser().parse_args(["-o", "targets"])) == "targets"

    def test_json_vence_output(self):
        from alive import cli
        args = cli.build_parser().parse_args(["--json", "-o", "csv"])
        assert cli._output_format(args) == "json"


class TestFiltroServico:
    def _h(self, ip, *svcs):
        return {"ip": ip, "services": set(svcs)}

    def test_filtra_por_servico(self):
        from alive import cli
        hosts = [self._h("192.168.0.1", "http"), self._h("192.168.0.2", "smb"),
                 self._h("192.168.0.3", "http", "https")]
        wanted = cli._wanted_services("http")
        out = cli._filter_by_service(hosts, wanted)
        assert [h["ip"] for h in out] == ["192.168.0.1", "192.168.0.3"]

    def test_varios_servicos_separados_por_virgula(self):
        from alive import cli
        assert cli._wanted_services("smb, HTTP ,rtsp") == {"smb", "http", "rtsp"}

    def test_sem_filtro_retorna_tudo(self):
        from alive import cli
        hosts = [self._h("192.168.0.1", "http")]
        assert cli._filter_by_service(hosts, set()) == hosts


class TestOrdenacaoPorRisco:
    def test_host_com_achado_mais_grave_vem_primeiro(self):
        from alive import cli, findings
        hosts = [{"ip": "192.168.0.9"}, {"ip": "192.168.0.1"}, {"ip": "192.168.0.5"}]
        found = [
            findings.Finding("baixo", "192.168.0.9", "x"),
            findings.Finding("alto", "192.168.0.5", "y"),
        ]
        ordem = [h["ip"] for h in cli._sort_by_risk(hosts, found)]
        assert ordem == ["192.168.0.5", "192.168.0.9", "192.168.0.1"]

    def test_sem_achados_cai_para_ordem_de_ip(self):
        from alive import cli
        hosts = [{"ip": "192.168.0.9"}, {"ip": "192.168.0.1"}]
        assert [h["ip"] for h in cli._sort_by_risk(hosts, [])] == \
            ["192.168.0.1", "192.168.0.9"]


class TestFlagOnvif:
    def test_flag_no_onvif_existe(self):
        from alive import cli
        assert cli.build_parser().parse_args(["--no-onvif"]).no_onvif is True

    def test_passivo_e_fast_desligam_onvif(self):
        from alive import cli
        a = cli.build_parser().parse_args(["--passive"])
        cli._apply_passive(a)
        b = cli.build_parser().parse_args(["--fast"])
        cli._apply_fast(b)
        assert a.no_onvif is True and b.no_onvif is True
