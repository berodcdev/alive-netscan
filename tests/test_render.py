"""Apresentação: limpeza de nome/fabricante, coluna DETALHE, JSON e escaping."""

from __future__ import annotations

import ipaddress
import json

import pytest
from rich.console import Console

from alive import classify, history, render
from alive.net import NetInfo


@pytest.fixture
def captura(monkeypatch):
    """Console de largura fixa que escreve num buffer, para inspecionar a saída."""
    import io

    buf = io.StringIO()
    console = Console(file=buf, width=100, highlight=False, no_color=True,
                      legacy_windows=False)
    monkeypatch.setattr(render, "console", console)
    return buf


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
        assert dados["findings"] == [{"severity": "alto", "ip": "1.2.3.4", "message": "x"}]


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
        import io
        buf = io.StringIO()
        monkeypatch.setattr(render, "console",
                            Console(file=buf, width=largura, no_color=True,
                                    highlight=False, legacy_windows=False))
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        render.render_table(
            [host(name="um-nome-bem-comprido-de-aparelho", vendor="Raspberry Pi",
                  model="Servidor doméstico com nome longo")],
            net,
        )
        for linha in buf.getvalue().splitlines():
            assert len(linha) <= largura, f"linha de {len(linha)} col em {largura}"

    def test_sem_hosts(self, captura):
        net = NetInfo(interface=None, ip=None, network=None, gateway=None, ssid=None)
        render.render_table([], net)
        assert "nenhum host vivo" in captura.getvalue()
