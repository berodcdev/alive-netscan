"""Achados: regras, severidade e ordenação."""

from __future__ import annotations

import pytest

from alive import findings


def host(ip, **extra):
    h = {"ip": ip, "services": set(), "via": "ping", "mac": None, "random_mac": False}
    h.update(extra)
    return h


class TestServicosArriscados:
    @pytest.mark.parametrize(
        "servico,severidade",
        [("telnet", "alto"), ("adb", "alto"), ("rtsp", "alto"), ("vnc", "alto"),
         ("ftp", "medio"), ("rdp", "medio"), ("dvr", "medio"), ("mqtt", "baixo")],
    )
    def test_severidade(self, servico, severidade):
        achados = findings.collect([host("192.168.0.9", services={servico})])
        assert [f.severity for f in achados] == [severidade]

    def test_inclui_o_nome_quando_existe(self):
        h = host("192.168.0.88", services={"telnet"}, name="cam-garagem")
        assert "192.168.0.88 (cam-garagem)" in findings.collect([h])[0].message

    def test_sem_servico_nenhum(self):
        assert findings.collect([host("192.168.0.9")]) == []


class TestMacDuplicado:
    def test_mesmo_mac_em_dois_ips(self):
        hosts = [host("192.168.0.9", mac="aa:bb:cc:dd:ee:01"),
                 host("192.168.0.10", mac="aa:bb:cc:dd:ee:01")]
        achados = findings.collect(hosts)
        assert len(achados) == 1
        assert achados[0].severity == "medio"
        assert "2 IPs" in achados[0].message

    def test_mac_aleatorio_nao_conta(self):
        """MAC sorteado repetido é coincidência esperada, não spoof."""
        hosts = [host("192.168.0.9", mac="6e:bb:cc:dd:ee:01", random_mac=True),
                 host("192.168.0.10", mac="6e:bb:cc:dd:ee:01", random_mac=True)]
        assert findings.collect(hosts) == []


class TestHostsSoArp:
    def test_confirmado_e_aparelho_furtivo(self):
        h = host("192.168.0.10", via="arp", arp_state="confirmado")
        (achado,) = findings.collect([h])
        assert "firewall ativo ou aparelho furtivo" in achado.message

    def test_stale_e_cache_obsoleto(self):
        h = host("192.168.0.63", via="arp", arp_state="stale")
        (achado,) = findings.collect([h])
        assert "cache ARP obsoleto" in achado.message
        assert "podem já ter saído" in achado.message

    def test_os_dois_casos_viram_achados_separados(self):
        hosts = [host("192.168.0.10", via="arp", arp_state="confirmado"),
                 host("192.168.0.63", via="arp", arp_state="stale"),
                 host("192.168.0.65", via="arp", arp_state="stale")]
        mensagens = [f.message for f in findings.collect(hosts)]
        assert len(mensagens) == 2
        assert any("1 host(s) responderam só a ARP" in m for m in mensagens)
        assert any("2 host(s) vêm só de cache" in m for m in mensagens)

    def test_sem_estado_conta_como_confirmado(self):
        """Snapshot antigo ou macOS não tem estado: não inventamos 'obsoleto'."""
        (achado,) = findings.collect([host("192.168.0.10", via="arp")])
        assert "firewall ativo" in achado.message

    def test_trunca_a_lista_de_ips(self):
        hosts = [host(f"192.168.0.{i}", via="arp") for i in range(10, 20)]
        (achado,) = findings.collect(hosts)
        assert achado.message.count("192.168.0.") == 5
        assert "..." in achado.message


class TestRedirecionamentos:
    def test_port_mapping_e_severidade_alta(self):
        wan = {"port_mappings": [{
            "external_port": "32400", "internal_port": "32400",
            "internal_client": "192.168.0.101", "protocol": "TCP",
            "description": "plex",
        }]}
        (achado,) = findings.collect([], wan)
        assert achado.severity == "alto"
        assert "TCP/32400" in achado.message and "[plex]" in achado.message

    def test_sem_wan(self):
        assert findings.collect([], None) == []


def test_ordenacao_por_severidade():
    hosts = [host("192.168.0.9", services={"mqtt"}),      # baixo
             host("192.168.0.8", services={"telnet"}),    # alto
             host("192.168.0.7", services={"ftp"})]       # medio
    assert [f.severity for f in findings.collect(hosts)] == ["alto", "medio", "baixo"]


def test_toda_severidade_tem_cor():
    for sev in findings.SEVERITY_ORDER:
        assert findings.Finding(sev, None, "x").color


class TestShortNotes:
    def test_marca_servicos_graves(self):
        notas = findings.short_notes(host("192.168.0.9", services={"telnet", "adb"}))
        assert set(notas) == {"telnet aberto!", "adb aberto!"}

    def test_sem_nota(self):
        assert findings.short_notes(host("192.168.0.9", services={"http"})) == []


class TestAcaoRecomendada:
    def test_servico_arriscado_diz_o_que_fazer(self):
        h = host("192.168.0.88", services={"telnet"})
        (achado,) = findings.collect([h])
        assert achado.fix and "192.168.0.88" in achado.fix

    def test_redirecionamento_diz_o_que_fazer(self):
        wan = {"port_mappings": [{"external_port": "80", "internal_port": "80",
                                  "internal_client": "192.168.0.9", "protocol": "TCP"}]}
        (achado,) = findings.collect([], wan)
        assert "painel do roteador" in achado.fix

    def test_achado_informativo_nao_tem_acao(self):
        """Host só em ARP não tem ação óbvia — inventar uma seria ruído."""
        (achado,) = findings.collect([host("192.168.0.9", via="arp")])
        assert achado.fix is None

    def test_toda_acao_cabe_numa_linha(self):
        for _sev, _texto, fix in findings._RISKY_SERVICES.values():
            assert len(fix) <= 80, fix


class TestModoPassivo:
    def test_nao_reporta_descoberta_por_arp(self):
        """Em modo passivo todo host vem do ARP: reportar isso seria mentir."""
        hosts = [host("192.168.0.9", via="arp", arp_state="confirmado"),
                 host("192.168.0.10", via="arp", arp_state="stale")]
        assert findings.collect(hosts, passive=True) == []

    def test_servico_arriscado_continua_valendo(self):
        h = host("192.168.0.88", via="arp", services={"telnet"})
        achados = findings.collect([h], passive=True)
        assert len(achados) == 1 and achados[0].severity == "alto"

    def test_sem_passive_reporta_normalmente(self):
        hosts = [host("192.168.0.9", via="arp", arp_state="confirmado")]
        assert len(findings.collect(hosts)) == 1


class TestMitm:
    """Detecção de MITM ancorada no gateway: ARP spoofing / evil twin."""

    GW = "192.168.0.1"
    MAC_A = "a0:b1:c2:d3:e4:f5"  # MAC de fábrica (OUI registrado)
    MAC_B = "a0:b1:c2:00:00:99"  # outro MAC de fábrica

    def _mitm(self, achados):
        return [f for f in achados if f.ip == self.GW]

    def test_mac_do_gateway_mudou(self):
        hosts = [host(self.GW, mac=self.MAC_B)]
        achados = findings.collect(
            hosts, gateway=self.GW, gateway_mac_prev=self.MAC_A
        )
        (a,) = self._mitm(achados)
        assert a.severity == "alto"
        assert self.MAC_A in a.message and self.MAC_B in a.message
        assert a.fix

    def test_mac_igual_ao_anterior_nao_alarma(self):
        hosts = [host(self.GW, mac=self.MAC_A)]
        achados = findings.collect(
            hosts, gateway=self.GW, gateway_mac_prev=self.MAC_A
        )
        assert self._mitm(achados) == []

    def test_sem_historico_nao_alarma_por_mudanca(self):
        hosts = [host(self.GW, mac=self.MAC_A)]
        achados = findings.collect(hosts, gateway=self.GW, gateway_mac_prev=None)
        assert self._mitm(achados) == []

    def test_gateway_com_mac_localmente_administrado(self):
        hosts = [host(self.GW, mac="6e:00:11:22:33:44", random_mac=True)]
        achados = findings.collect(hosts, gateway=self.GW)
        (a,) = self._mitm(achados)
        assert a.severity == "medio"
        assert "localmente administrado" in a.message

    def test_gateway_com_mac_de_fabrica_nao_alarma(self):
        hosts = [host(self.GW, mac=self.MAC_A)]
        achados = findings.collect(hosts, gateway=self.GW)
        assert self._mitm(achados) == []

    def test_mac_do_gateway_duplicado_e_spoof_alto(self):
        """MAC do gateway respondendo em outro IP: ARP spoofing clássico."""
        hosts = [
            host(self.GW, mac=self.MAC_A),
            host("192.168.0.77", mac=self.MAC_A),
        ]
        achados = findings.collect(hosts, gateway=self.GW)
        alto = [f for f in achados if f.severity == "alto"]
        assert len(alto) == 1
        assert "192.168.0.77" in alto[0].message
        assert "ARP spoofing" in alto[0].message

    def test_mac_duplicado_sem_ser_gateway_continua_medio(self):
        hosts = [
            host("192.168.0.9", mac=self.MAC_A),
            host("192.168.0.10", mac=self.MAC_A),
        ]
        achados = findings.collect(hosts, gateway=self.GW)
        assert [f.severity for f in achados] == ["medio"]

    def test_sem_gateway_nenhuma_regra_mitm_dispara(self):
        hosts = [host(self.GW, mac="6e:00:11:22:33:44", random_mac=True)]
        assert findings.collect(hosts) == []
