"""Apresentação: limpeza de nome/fabricante, coluna DETALHE, JSON e escaping."""

from __future__ import annotations

import ipaddress
import json

import pytest

from alive import classify, history, render
from alive.net import NetInfo
from tests.conftest import Captura


def host(ip="192.168.0.9", **extra):
    h = {
        "ip": ip, "mac": "f0:18:98:2a:1b:cd", "name": None, "vendor": None,
        "model": None, "services": set(), "banners": {}, "device": classify.COMPUTER,
        "inferred": False, "random_mac": False, "rtt": None, "ttl": None,
        "os_family": None, "via": "ping", "notes": [], "arp_state": None,
    }
    h.update(extra)
    return h


class TestCleanHostname:
    @pytest.mark.parametrize(
        "raw,esperado",
        [
            ("raspberrypi.local", "raspberrypi"),
            ("pc-sala.lan", "pc-sala"),
            ("nas.home.arpa", "nas"),
            ("GPT-2741GNAC-N1.GPT-2741GNAC-N1", "GPT-2741GNAC-N1"),
            ("host.dominio.com", "host.dominio.com"),
            ("  nome.  ", "nome"),
        ],
    )
    def test_normaliza(self, raw, esperado):
        assert render.clean_hostname(raw) == esperado

    @pytest.mark.parametrize("raw", ["192.168.0.61", "10.0.0.1", "8.8.8.8"])
    def test_ip_nao_e_nome(self, raw):
        """PTR que devolve o próprio IP só repetiria a coluna ao lado."""
        assert render.clean_hostname(raw) is None

    @pytest.mark.parametrize("raw", [None, "", "   ", "..."])
    def test_vazio(self, raw):
        assert render.clean_hostname(raw) is None


class TestCleanVendor:
    @pytest.mark.parametrize(
        "raw,esperado",
        [
            ("Apple, Inc.", "Apple"),
            ("Samsung Electronics Co.,Ltd", "Samsung"),
            ("Raspberry Pi Foundation", "Raspberry Pi"),
            ("Google LLC", "Google"),
            ("TP-Link Technologies Co.", "TP-Link"),
            ("Sony Interactive Entertainment", "Sony"),
        ],
    )
    def test_encurta(self, raw, esperado):
        assert render.clean_vendor(raw) == esperado

    def test_nome_de_uma_palavra_sobrevive(self):
        assert render.clean_vendor("Espressif") == "Espressif"

    def test_vazio(self):
        assert render.clean_vendor(None) is None


class TestDetailText:
    def test_prefere_o_modelo(self):
        texto = render.detail_text(host(model="MacBook Air",
                                        banners={"http_server": "nginx"}))
        assert "MacBook Air" in texto and "nginx" not in texto

    def test_cai_para_o_banner(self):
        assert "GoAhead-Webs" in render.detail_text(
            host(banners={"http_server": "GoAhead-Webs"}))

    def test_arp_confirmado(self):
        assert "só ARP" in render.detail_text(host(via="arp", arp_state="confirmado"))

    def test_arp_obsoleto(self):
        assert "ARP obsoleto" in render.detail_text(host(via="arp", arp_state="stale"))

    def test_sem_nada(self):
        assert "—" in render.detail_text(host())

    def test_escapa_markup_do_aparelho(self):
        """Modelo vindo da rede não pode virar estilo nem quebrar o render."""
        texto = render.detail_text(host(model="[bold]INJETADO[/bold]"))
        assert "\\[bold]" in texto


class TestToJson:
    def test_estrutura(self):
        net = NetInfo(interface="wlan0", ip="192.168.0.61",
                      network=ipaddress.ip_network("192.168.0.0/24"),
                      gateway="192.168.0.1", ssid="CASA")
        dados = json.loads(render.to_json([host(name="pc.local")], net))
        assert dados["network"]["cidr"] == "192.168.0.0/24"
        (h,) = dados["hosts"]
        assert h["name"] == "pc" and h["type"] == "COMPUTADOR"

    def test_expoe_o_estado_arp(self):
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        dados = json.loads(render.to_json([host(via="arp", arp_state="stale")], net))
        assert dados["hosts"][0]["arp_state"] == "stale"

    def test_ip_como_nome_nao_vaza_para_o_json(self):
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        dados = json.loads(render.to_json([host(name="192.168.0.9")], net))
        assert dados["hosts"][0]["name"] is None

    def test_findings_serializam(self):
        from alive.findings import Finding
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        dados = json.loads(render.to_json([], net, [Finding("alto", "1.2.3.4", "x")]))
        assert dados["findings"] == [
            {"severity": "alto", "ip": "1.2.3.4", "message": "x", "fix": None}
        ]


NOMES_HOSTIS = ["[/bold]", "[blink]x[/]", "[red on white]", "[[", "]]"]


class TestEscapingHostil:
    """Regressão: nome vindo da rede derrubava o render com MarkupError."""

    @pytest.mark.parametrize("nome", NOMES_HOSTIS)
    def test_host_que_saiu(self, nome, captura):
        net = NetInfo(interface="wlan0", ip=None,
                      network=ipaddress.ip_network("192.168.0.0/24"),
                      gateway=None, ssid=None)
        diff = history.Diff(gone=[{"ip": "192.168.0.9", "name": nome}],
                            previous_time=None, first_run=False)
        render.print_summary(net, [], method="teste", diff=diff)
        assert nome in captura.getvalue()

    @pytest.mark.parametrize("nome", NOMES_HOSTIS)
    def test_host_na_tabela(self, nome, captura):
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        render.render_table([host(name=nome, vendor=nome)], net)
        assert "MarkupError" not in captura.getvalue()

    def test_ssid_e_interface_hostis(self, captura):
        net = NetInfo(interface="[/dim]", ip=None, network=None, gateway=None,
                      ssid="[red]REDE")
        render.print_summary(net, [], method="teste")
        assert "[red]REDE" in captura.getvalue()

    def test_evento_de_entrada_e_saida(self, captura):
        diff = history.Diff(gone=[{"ip": "192.168.0.8", "name": "[/bold]"}])
        render.print_events([host(name="[/i]", is_new=True)], diff)
        assert "[/bold]" in captura.getvalue()


class TestRenderTable:
    @pytest.mark.parametrize("largura", [60, 80, 100, 120, 160, 200])
    def test_nunca_estoura_a_largura(self, largura, monkeypatch):
        cap = Captura(largura)
        monkeypatch.setattr(render, "console", cap.console)
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        render.render_table(
            [host(name="um-nome-bem-comprido-de-aparelho", vendor="Raspberry Pi",
                  model="Servidor doméstico com nome longo")],
            net,
        )
        for linha in cap.linhas():
            assert len(linha) <= largura, f"linha de {len(linha)} col em {largura}"

    def test_sem_hosts(self, captura):
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        render.render_table([], net)
        assert "nenhum host vivo" in captura.getvalue()


class TestPrintFindings:
    """A severidade tem de aparecer: o resumo promete '3 alto · 2 baixo'."""

    def _achados(self):
        from alive.findings import Finding
        return [Finding("alto", "192.168.0.88", "telnet aberto"),
                Finding("medio", "192.168.0.9", "FTP aberto"),
                Finding("baixo", None, "cache ARP obsoleto")]

    def test_mostra_o_rotulo_de_severidade(self, captura):
        render.print_findings(self._achados())
        saida = captura.getvalue()
        assert "ALTO" in saida and "MÉDIO" in saida and "BAIXO" in saida

    def test_mensagem_longa_quebra_alinhada(self, captura):
        from alive.findings import Finding
        longa = "palavra " * 40
        render.print_findings([Finding("alto", "1.2.3.4", longa.strip())])
        linhas = [ln for ln in captura.getvalue().splitlines() if ln.strip()]
        # A continuação fica recuada sob a mensagem, não na coluna zero.
        assert all(ln.startswith(" ") for ln in linhas[1:])

    def test_sem_achados_nao_imprime_nada(self, captura):
        render.print_findings([])
        assert captura.getvalue() == ""

    def test_trunca_e_avisa(self, captura):
        from alive.findings import Finding
        render.print_findings([Finding("baixo", None, f"achado {i}") for i in range(12)],
                              limit=3)
        assert "e mais 9" in captura.getvalue()


class TestColunaDeAlerta:
    def test_marca_o_host_com_achado(self, captura):
        from alive.findings import Finding
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        render.render_table([host("192.168.0.88"), host("192.168.0.9")], net,
                            [Finding("alto", "192.168.0.88", "telnet aberto")])
        saida = captura.getvalue()
        assert "!" in saida and "tem achado abaixo" in saida

    def test_sem_achados_a_coluna_nem_aparece(self, captura):
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        render.render_table([host("192.168.0.9")], net, [])
        assert "tem achado abaixo" not in captura.getvalue()


class TestSemEspacoNoFimDaLinha:
    """Espaço no fim da linha aparece assim que alguém redireciona para arquivo."""

    def test_kv_longo(self, captura):
        net = NetInfo(interface="wlan0", ip=None, network=None, gateway=None,
                      ssid="rede " * 30)
        render.print_summary(net, [], method="m " * 40)
        assert not any(ln.endswith(" ") for ln in captura.getvalue().splitlines())

    def test_achados_longos(self, captura):
        from alive.findings import Finding
        render.print_findings([Finding("alto", "1.2.3.4", "palavra " * 40)])
        assert not any(ln.endswith(" ") for ln in captura.getvalue().splitlines())


def test_print_footer(captura):
    render.print_footer(12.34, 254, [host("192.168.0.1"), host("192.168.0.2")])
    assert "2 vivos de 254 endereços em 12.3s" in captura.getvalue()


class TestCaixaDoFabricante:
    """A base OUI mistura caixas: vinha 'zte' ao lado de 'Samsung'."""

    @pytest.mark.parametrize(
        "raw,esperado",
        [
            ("zte", "ZTE"),
            ("ZTE Corporation", "ZTE"),
            ("TP-LINK TECHNOLOGIES CO.,LTD.", "TP-Link"),
            ("hewlett packard", "Hewlett Packard"),
            ("ASUSTek COMPUTER INC.", "ASUSTek Computer"),
        ],
    )
    def test_normaliza(self, raw, esperado):
        assert render.clean_vendor(raw) == esperado

    def test_caixa_mista_e_intencional(self):
        """'iRobot' e 'NetGear' foram escritos assim de propósito."""
        assert render.clean_vendor("iRobot") == "iRobot"

    def test_nome_todo_descartado_nao_vira_vazio(self):
        """'Technologies Inc' é só sufixo — melhor mostrar algo do que nada."""
        assert render.clean_vendor("Technologies Inc") == "Technologies Inc"


class TestColunaCompacta:
    """Abaixo de 92 col o fabricante entra no DETALHE — sem empilhar vazios."""

    def _linhas(self, h, monkeypatch, largura=80):
        cap = Captura(largura)
        monkeypatch.setattr(render, "console", cap.console)
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        render.render_table([h], net)
        return cap.getvalue()

    def test_fabricante_e_detalhe(self, monkeypatch):
        saida = self._linhas(host(vendor="Raspberry Pi Foundation",
                                  model="Servidor"), monkeypatch)
        assert "Raspberry Pi · Servidor" in saida

    def test_so_fabricante(self, monkeypatch):
        saida = self._linhas(host(vendor="Samsung Electronics"), monkeypatch)
        assert "Samsung" in saida and "· —" not in saida

    def test_nem_fabricante_nem_detalhe(self, monkeypatch):
        """Regressão: aparecia '? · —', dois placeholders na mesma célula."""
        assert "? · —" not in self._linhas(host(), monkeypatch)

    def test_coluna_fabricante_volta_em_terminal_largo(self, monkeypatch):
        saida = self._linhas(host(vendor="Samsung Electronics"), monkeypatch,
                             largura=170)
        assert "FABRICANTE" in saida and "SERVIÇOS" in saida


class TestWatchLine:
    """Regressão: --watch --json não emitia uma linha sequer."""

    def _net(self):
        return NetInfo(interface="wlan0", ip=None,
                       network=ipaddress.ip_network("192.168.0.0/24"),
                       gateway=None, ssid="CASA")

    def test_uma_linha_por_ciclo(self):
        linha = render.watch_line(3, [host()], self._net(), [], history.Diff())
        assert "\n" not in linha
        assert json.loads(linha)["cycle"] == 3

    def test_evento_de_entrada(self):
        h = host("192.168.0.55", name="novo.local", is_new=True)
        dados = json.loads(render.watch_line(1, [h], self._net(), [], history.Diff()))
        assert dados["events"] == [
            {"event": "entrou", "ip": "192.168.0.55", "name": "novo",
             "type": "COMPUTADOR"}
        ]

    def test_evento_de_saida(self):
        diff = history.Diff(gone=[{"ip": "192.168.0.9", "name": "pc.local",
                                   "type": "COMPUTADOR"}])
        dados = json.loads(render.watch_line(2, [], self._net(), [], diff))
        assert dados["events"][0]["event"] == "saiu"
        assert dados["events"][0]["name"] == "pc"

    def test_carrega_o_estado_completo(self):
        dados = json.loads(render.watch_line(1, [host()], self._net(), [], history.Diff()))
        assert dados["network"]["cidr"] == "192.168.0.0/24"
        assert len(dados["hosts"]) == 1
        assert isinstance(dados["time"], float)


class TestFindingFix:
    def test_acao_aparece_abaixo_da_mensagem(self, captura):
        from alive.findings import Finding
        render.print_findings([Finding("alto", "1.2.3.4", "telnet aberto",
                                       "desative o telnet")])
        assert "→ desative o telnet" in captura.getvalue()

    def test_achado_sem_acao_nao_imprime_seta(self, captura):
        from alive.findings import Finding
        render.print_findings([Finding("baixo", None, "só informativo")])
        assert "→" not in captura.getvalue()


class TestResumoPassivo:
    def _net(self):
        return NetInfo(interface="wlan0", ip=None,
                       network=ipaddress.ip_network("192.168.0.0/24"),
                       gateway=None, ssid="CASA")

    def test_nao_diz_que_ignoram_ping(self, captura):
        """Em modo passivo nada foi pingado — a frase seria falsa."""
        render.print_summary(self._net(), [host(via="arp")], method="ARP (passivo)",
                             passive=True)
        assert "ignoram ping" not in captura.getvalue()
        assert "cache ARP" in captura.getvalue()

    def test_modo_normal_mantem_a_frase(self, captura):
        render.print_summary(self._net(), [host(via="arp")], method="ping + ARP")
        assert "ignoram ping" in captura.getvalue()


class TestSaidaArmada:
    """Formatos de máquina: targets (só IPs) e csv."""

    def test_targets_um_ip_por_linha(self):
        hosts = [host("192.168.0.1"), host("192.168.0.9"), host("192.168.0.20")]
        assert render.to_targets(hosts) == "192.168.0.1\n192.168.0.9\n192.168.0.20"

    def test_targets_vazio(self):
        assert render.to_targets([]) == ""

    def test_csv_tem_cabecalho_e_linha(self):
        h = host("192.168.0.9", mac="aa:bb:cc:dd:ee:01", name="pc-sala.local",
                 vendor="Dell", os_family="Windows", services={"smb", "rdp"},
                 rtt=3.2, via="ping", device=classify.COMPUTER)
        linhas = render.to_csv([h]).splitlines()
        assert linhas[0] == "ip,mac,name,vendor,type,os_family,services,rtt_ms,discovered_via"
        assert linhas[1].startswith("192.168.0.9,aa:bb:cc:dd:ee:01,pc-sala,Dell,COMPUTADOR,Windows,")
        assert "rdp smb" in linhas[1]  # serviços ordenados

    def test_csv_escapa_virgula_do_fabricante(self):
        import csv as _csv
        import io
        h = host("192.168.0.9", vendor="Samsung Electronics Co.,Ltd")
        linhas = list(_csv.reader(io.StringIO(render.to_csv([h]))))
        assert linhas[1][3] == "Samsung Electronics Co.,Ltd"

    def test_csv_campos_ausentes_viram_vazio(self):
        h = host("192.168.0.9", mac=None, name=None, vendor=None, rtt=None)
        campos = render.to_csv([h]).splitlines()[1].split(",")
        assert campos[1] == "" and campos[7] == ""  # mac e rtt vazios
