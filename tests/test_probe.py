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


class TestUsefulTitle:
    """O <title> só vira DETALHE se disser algo sobre o aparelho."""

    @pytest.mark.parametrize(
        "titulo",
        ["302 Found", "401 Unauthorized", "404 Not Found",   # linha de status
         "0,1,2", "1.2.3", "   ", "42",                      # só números
         "Document", "index of /", "Login", "Welcome",       # placeholder
         "ok", "x"],                                          # curto demais
    )
    def test_descarta_ruido(self, titulo):
        assert probe.useful_title(titulo) is None

    @pytest.mark.parametrize(
        "titulo",
        ["Archer C6", "Z13220", "HP LaserJet M28w", "RT-AC68U", "Câmera IP"],
    )
    def test_mantem_o_que_identifica(self, titulo):
        assert probe.useful_title(titulo) == titulo

    def test_none(self):
        assert probe.useful_title(None) is None


class TestHeaderVazio:
    """Regressão: header vazio engolia o valor do header seguinte."""

    RESP = ("HTTP/1.1 302 Found\r\nServer:\r\nAccept-Ranges: bytes\r\n"
            "Location: /start.html\r\n\r\n")

    def test_header_vazio_e_none(self):
        assert probe._header(self.RESP, "Server") is None

    def test_nao_invade_a_linha_seguinte(self):
        assert probe._header(self.RESP, "Server") != "Accept-Ranges: bytes"

    def test_header_seguinte_continua_legivel(self):
        assert probe._header(self.RESP, "Accept-Ranges") == "bytes"

    def test_valor_normal(self):
        resp = "HTTP/1.1 200 OK\r\nServer: GoAhead-Webs\r\n\r\n"
        assert probe._header(resp, "Server") == "GoAhead-Webs"

    def test_nome_com_hifen(self):
        resp = "RTSP/1.0 200 OK\r\nContent-Type: application/sdp\r\n\r\n"
        assert probe._header(resp, "Content-Type") == "application/sdp"


# Certificado X.509 auto-assinado real (openssl), CN=nas.local, O=Synology Inc.,
# SAN DNS nas.local + nas.example.com, válido até 2036. Fixture determinística.
_CERT_B64 = (
    "MIIDZzCCAk+gAwIBAgIUYfQL2pTfezEfgzjYL8L76tRCcpkwDQYJKoZIhvcNAQEL"
    "BQAwLDESMBAGA1UEAwwJbmFzLmxvY2FsMRYwFAYDVQQKDA1TeW5vbG9neSBJbmMu"
    "MB4XDTI2MDkxNTIxMDYzMVoXDTM2MDkxMjIxMDYzMVowLDESMBAGA1UEAwwJbmFz"
    "LmxvY2FsMRYwFAYDVQQKDA1TeW5vbG9neSBJbmMuMIIBIjANBgkqhkiG9w0BAQEF"
    "AAOCAQ8AMIIBCgKCAQEA9I1xuAWTiEwjXs/2Bi1S8fci22xxi60Q5P7qbZFe/gJ"
    "X1b3RR9hLltO1xf+4WtQ0fvBBMXNgeC19cqMlH7tx7YNgXtqR0xcHgEdaaXHSdzj"
    "jx1mP9ReMwXu8s8eR/ztffqLrI/GwDG5zRgPEgwGV2ZyROkGCm2EzPZXE1fURyg"
    "er9x1mRB36c666smW2qr1rXJRPwBLbQa9xbGew0452Be0x7+0Erg0toI3PZYJ0Z"
    "hcVCCMgFSskpg597OYsloOun8SeUfJ1F2tXPbJ3w0f0qt894e1kMF/EZu6HP6QO"
    "evSXmU5AX6SP0vYH+bomGz5Cg4RIjKcCNOIXH+3hSHFPjQIDAQABo4GAMH4wHQYD"
    "VR0OBBYEFBM+PvM4xetTdMrQBAFXOaTD/x9cMB8GA1UdIwQYMBaAFBM+PvM4xetT"
    "dMrQBAFXOaTD/x9cMA8GA1UdEwEB/wQFMAMBAf8wKwYDVR0RBCQwIoIJbmFzLmxv"
    "Y2Fsgg9uYXMuZXhhbXBsZS5jb22HBMCoADIwDQYJKoZIhvcNAQELBQADggEBABiy"
    "yis2FHdSdLLNR/xnBncWGND91nIiSfcOonJ7Sy245zOkDdkS1zJVlT6Na/wr9an"
    "kpcI+TsCLktQE2kvL6KEpmbUuuauTk2CQ59Mg+IEJw9hOo8oU19fr5Vf6mK9JgM"
    "rqs7NUnBrHyAv6UlSstVY3UbbogQO1znsXojgBT7ikyirP5eGihVILwVlA7uRM8"
    "esE2bo7sGclm8Pc3Ay632Iwgfar4JjfVjTfLjW/9YosGkxp7K+NImKMImU5oBmj"
    "ppTXW0JAaOciT0OJohmuAtimWTIc4H/bpdaRXKaQh3SnskUqs0CATqSFA2WkTt/"
    "OZTwEKtYe3UClopMFkjUJqlM="
)


class TestOid:
    @pytest.mark.parametrize(
        "dotted",
        ["1.3.6.1.2.1.1.1.0", "2.5.4.3", "2.5.29.17", "1.2.840.113549.1.1.11"],
    )
    def test_encode_decode_ida_e_volta(self, dotted):
        assert probe._oid_to_str(probe._encode_oid(dotted)) == dotted


class TestCertTLS:
    def _cert(self):
        import base64
        return probe.parse_cert_der(base64.b64decode(_CERT_B64))

    def test_extrai_cn_do_dono(self):
        assert self._cert()["subject_cn"] == "nas.local"

    def test_extrai_emissor(self):
        assert self._cert()["issuer"] == "nas.local"

    def test_detecta_auto_assinado(self):
        assert self._cert()["self_signed"] is True

    def test_extrai_san_dns(self):
        assert self._cert()["san"] == ["nas.local", "nas.example.com"]

    def test_san_ignora_entradas_que_nao_sao_dns(self):
        """O certificado tem um SAN de IP; só os nomes DNS entram."""
        assert all("." in n and not n[0].isdigit() for n in self._cert()["san"])

    def test_validade_no_futuro(self):
        import time
        assert self._cert()["not_after"] > time.time()

    def test_der_invalido_nao_quebra(self):
        assert probe.parse_cert_der(b"\x30\x03lixo") == {}

    def test_der_vazio(self):
        assert probe.parse_cert_der(b"") == {}


class TestSnmp:
    def _resposta(self, descr, name, err=0, request_id=0x1234):
        """Monta um GetResponse SNMP com os dois OIDs."""
        def octstr(s):
            return probe._ber(0x04, s.encode())

        def oid(o):
            return probe._ber(0x06, probe._encode_oid(o))

        vbs = b""
        if descr is not None:
            vbs += probe._ber(0x30, oid(probe._OID_SYS_DESCR) + octstr(descr))
        if name is not None:
            vbs += probe._ber(0x30, oid(probe._OID_SYS_NAME) + octstr(name))
        pdu = probe._ber(
            0xA2,
            probe._ber_int(request_id) + probe._ber_int(err) + probe._ber_int(0)
            + probe._ber(0x30, vbs),
        )
        return probe._ber(0x30, probe._ber_int(0) + octstr("public") + pdu)

    def test_request_bem_formado(self):
        pkt = probe.build_snmp_get(
            [probe._OID_SYS_DESCR, probe._OID_SYS_NAME], 0x1234, "public"
        )
        assert pkt[0] == 0x30 and b"public" in pkt

    def test_parse_extrai_descr_e_nome(self):
        resp = self._resposta("Linux nas 5.10 armv7l", "nas-sala")
        out = probe.parse_snmp_response(resp)
        assert out[probe._OID_SYS_DESCR] == "Linux nas 5.10 armv7l"
        assert out[probe._OID_SYS_NAME] == "nas-sala"

    def test_error_status_descarta_resposta(self):
        assert probe.parse_snmp_response(self._resposta("x", "y", err=2)) == {}

    def test_resposta_lixo_nao_quebra(self):
        assert probe.parse_snmp_response(b"\x30\x02\x00\x00") == {}

    def test_colapsa_espacos_e_controle(self):
        out = probe.parse_snmp_response(self._resposta("HP\x00\r\n  LaserJet", None))
        assert out[probe._OID_SYS_DESCR] == "HP LaserJet"
