"""Sondas: limpeza de banner, parsing de XML/NBSTAT e validação de URL."""

from __future__ import annotations

import pytest

from alive import probe


class TestClean:
    def test_decodifica_entidades_html(self):
        """A página do aparelho serve o <title> com entidades numéricas."""
        assert probe._clean("&#90;&#49;&#51;&#50;&#50;&#48;") == "Z13220"

    def test_entidades_nomeadas(self):
        assert probe._clean("Sala &amp; Cozinha") == "Sala & Cozinha"

    def test_remove_controle_e_colapsa_espaco(self):
        assert probe._clean("  HP\x00 Laser\r\n  Jet  ") == "HP Laser Jet"

    def test_trunca(self):
        assert probe._clean("x" * 80, limit=10) == "x" * 10

    @pytest.mark.parametrize("raw", [None, "", "   ", "\x00\x01"])
    def test_vazio_vira_none(self, raw):
        assert probe._clean(raw) is None


class TestTag:
    def test_extrai(self):
        assert probe._tag("<modelName>Archer C6</modelName>", "modelName") == "Archer C6"

    def test_decodifica_entidades(self):
        xml = "<friendlyName>Sala &amp; Cozinha</friendlyName>"
        assert probe._tag(xml, "friendlyName") == "Sala & Cozinha"

    def test_colapsa_quebras(self):
        assert probe._tag("<a>\n  dois\n  valores\n</a>", "a") == "dois valores"

    def test_ausente(self):
        assert probe._tag("<b>x</b>", "a") is None

    def test_vazio(self):
        assert probe._tag("<a>  </a>", "a") is None


class TestHeader:
    def test_extrai_case_insensitive(self):
        texto = "HTTP/1.1 200 OK\r\nserver: GoAhead-Webs\r\n\r\n"
        assert probe._header(texto, "Server") == "GoAhead-Webs"

    def test_ausente(self):
        assert probe._header("HTTP/1.1 200 OK\r\n\r\n", "Server") is None


class TestSafeDeviceUrl:
    """O LOCATION do SSDP é escolhido pelo aparelho — entrada não confiável."""

    def test_aceita_http_do_proprio_ip(self):
        url = "http://192.168.0.4:5000/desc.xml"
        assert probe.safe_device_url(url, "192.168.0.4") == url

    @pytest.mark.parametrize(
        "url,motivo",
        [
            ("file:///etc/passwd", "esquema file lê arquivo local"),
            ("ftp://192.168.0.4/x", "esquema não-http"),
            ("https://192.168.0.4/x", "só http é esperado na LAN"),
            ("http://10.0.0.9/x", "outro host da rede"),
            ("http://evil.example.com/x", "host externo"),
            ("http://192.168.0.44/x", "IP parecido, mas outro"),
            ("", "vazio"),
            (None, "ausente"),
        ],
    )
    def test_rejeita(self, url, motivo):
        assert probe.safe_device_url(url, "192.168.0.4") is None, motivo

    def test_sem_ip_de_referencia(self):
        assert probe.safe_device_url("http://192.168.0.4/x", "") is None


class TestFindWanService:
    BASE = "http://192.168.0.1:5000/desc.xml"

    def test_resolve_control_url_relativa(self):
        xml = (
            "<service><serviceType>urn:WANIPConnection:1</serviceType>"
            "<controlURL>/ctl/IPConn</controlURL></service>"
        )
        achado = probe._find_wan_service(xml, self.BASE, "192.168.0.1")
        assert achado == ("urn:WANIPConnection:1", "http://192.168.0.1:5000/ctl/IPConn")

    def test_recusa_control_url_para_fora(self):
        """controlURL vem do XML do aparelho e pode apontar para qualquer lugar."""
        xml = (
            "<service><serviceType>urn:WANIPConnection:1</serviceType>"
            "<controlURL>http://192.168.0.99/evil</controlURL></service>"
        )
        assert probe._find_wan_service(xml, self.BASE, "192.168.0.1") is None

    def test_ignora_servico_sem_wan(self):
        xml = (
            "<service><serviceType>urn:Layer3Forwarding:1</serviceType>"
            "<controlURL>/ctl/L3F</controlURL></service>"
        )
        assert probe._find_wan_service(xml, self.BASE, "192.168.0.1") is None


def _nbstat(nomes: list[tuple[str, int, int]]) -> bytes:
    """Monta uma resposta NBSTAT sintética. nomes = [(nome, sufixo, flags)]."""
    header = b"\x00" * 12
    nome_codificado = b"\x20" + b"A" * 32 + b"\x00"
    rr = b"\x00\x21" + b"\x00\x01" + b"\x00\x00\x00\x00" + b"\x00\x00"
    corpo = bytes([len(nomes)])
    for nome, sufixo, flags in nomes:
        corpo += nome.ljust(15).encode("ascii")[:15]
        corpo += bytes([sufixo])
        corpo += flags.to_bytes(2, "big")
    return header + nome_codificado + rr + corpo


class TestParseNbstat:
    def test_nome_de_workstation(self):
        data = _nbstat([("MINHAMAQUINA", 0x00, 0x0000)])
        assert probe._parse_nbstat(data) == "MINHAMAQUINA"

    def test_ignora_nome_de_grupo(self):
        """Flag 0x8000 = nome de grupo (workgroup), não da máquina."""
        data = _nbstat([("WORKGROUP", 0x00, 0x8000)])
        assert probe._parse_nbstat(data) is None

    def test_ignora_sufixo_de_servico(self):
        data = _nbstat([("MINHAMAQUINA", 0x20, 0x0000)])
        assert probe._parse_nbstat(data) is None

    def test_escolhe_o_nome_unico_entre_varios(self):
        data = _nbstat([
            ("WORKGROUP", 0x00, 0x8000),
            ("NAS-CASA", 0x00, 0x0000),
            ("NAS-CASA", 0x20, 0x0000),
        ])
        assert probe._parse_nbstat(data) == "NAS-CASA"

    @pytest.mark.parametrize("data", [b"", b"\x00" * 8, b"\xff" * 40])
    def test_resposta_truncada_ou_lixo(self, data):
        """Resposta malformada não pode derrubar a varredura."""
        assert probe._parse_nbstat(data) is None


def test_encode_netbios_name():
    """Codificação de 1º nível: cada byte vira dois chars 'A'+nibble."""
    assert probe._encode_netbios_name("*") == b"CK" + b"AA" * 15


def test_port_service_cobre_default_ports():
    assert set(probe.DEFAULT_PORTS) == set(probe.PORT_SERVICE)
    assert probe.PORT_SERVICE[23] == "telnet"
    assert probe.PORT_SERVICE[62078] == "ios"


def test_new_ssdp_entry_tem_formato_estavel():
    entry = probe.new_ssdp_entry()
    assert set(entry) == {"name", "server", "model", "manufacturer", "location", "types"}


class TestRecordSsdp:
    def test_registra_server_e_location(self):
        resultados: dict = {}
        texto = (
            "HTTP/1.1 200 OK\r\nSERVER: Linux/3.4 UPnP/1.0\r\n"
            "LOCATION: http://192.168.0.4:5000/desc.xml\r\nST: upnp:rootdevice\r\n\r\n"
        )
        loc = probe.record_ssdp(resultados, "192.168.0.4", texto)
        assert loc == "http://192.168.0.4:5000/desc.xml"
        assert resultados["192.168.0.4"]["server"] == "Linux/3.4 UPnP/1.0"
        assert "upnp:rootdevice" in resultados["192.168.0.4"]["types"]

    def test_resposta_sem_location(self):
        """Regressão: o roteador que responde sem LOCATION não pode virar KeyError."""
        resultados: dict = {}
        assert probe.record_ssdp(resultados, "192.168.0.1", "HTTP/1.1 200 OK\r\n\r\n") is None
